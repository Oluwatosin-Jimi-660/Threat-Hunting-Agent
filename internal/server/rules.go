package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"threat-hunting-agent/internal/schema"
)

// HuntRule is a declarative detection rule loaded from JSON.
type HuntRule struct {
	RuleID         string            `json:"rule_id"`
	Description    string            `json:"description"`
	TargetEventIDs []int             `json:"target_event_ids"`
	Conditions     RuleCondition     `json:"conditions"`
	MITRETechnique *schema.ATTACKMap `json:"mitre_technique,omitempty"`
	RiskWeight     int               `json:"risk_weight"`
	Enabled        bool              `json:"enabled"`
	UpdatedAt      string            `json:"updated_at"`
}

type RuleCondition struct {
	Operator string           `json:"operator"`
	Checks   []FieldCondition `json:"checks,omitempty"`
	Any      []RuleCondition  `json:"any,omitempty"`
	All      []RuleCondition  `json:"all,omitempty"`
}

type FieldCondition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

type RuleSet struct {
	Version string     `json:"version"`
	Rules   []HuntRule `json:"rules"`
}

type SignedRulePackage struct {
	PackageVersion string  `json:"package_version"`
	SignedAt       string  `json:"signed_at"`
	Signer         string  `json:"signer"`
	Payload        RuleSet `json:"payload"`
	Signature      string  `json:"signature"`
}

type RuleManager struct {
	mu        sync.RWMutex
	rules     []HuntRule
	rulesByID map[string]HuntRule
	versions  []RuleSet
	ruleFile  string
	auditLog  string
}

func NewRuleManager(ruleFile string, auditLog string) (*RuleManager, error) {
	rm := &RuleManager{ruleFile: ruleFile, auditLog: auditLog, rulesByID: map[string]HuntRule{}}
	if err := rm.Load(); err != nil {
		return nil, err
	}
	return rm, nil
}

func (r *RuleManager) Load() error {
	b, err := os.ReadFile(r.ruleFile)
	if err != nil {
		return err
	}
	var rs RuleSet
	if err := json.Unmarshal(b, &rs); err != nil {
		return err
	}
	if err := validateRuleSet(rs); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.versions = append(r.versions, RuleSet{Version: rs.Version, Rules: append([]HuntRule{}, rs.Rules...)})
	r.rules = append([]HuntRule{}, rs.Rules...)
	r.rulesByID = map[string]HuntRule{}
	for _, rule := range rs.Rules {
		r.rulesByID[rule.RuleID] = rule
	}
	return nil
}

func (r *RuleManager) Rules() []HuntRule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]HuntRule{}, r.rules...)
}

func (r *RuleManager) Versions() []RuleSet {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]RuleSet, len(r.versions))
	copy(out, r.versions)
	return out
}

func (r *RuleManager) Rollback(version string, actor string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rs := range r.versions {
		if rs.Version != version {
			continue
		}
		r.rules = append([]HuntRule{}, rs.Rules...)
		r.rulesByID = map[string]HuntRule{}
		for _, rule := range rs.Rules {
			r.rulesByID[rule.RuleID] = rule
		}
		if err := r.persistLocked(); err != nil {
			return err
		}
		return r.appendAudit("rollback", actor, version)
	}
	return fmt.Errorf("unknown ruleset version %s", version)
}

func (r *RuleManager) SetEnabled(ruleID string, enabled bool, actor string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, rule := range r.rules {
		if rule.RuleID != ruleID {
			continue
		}
		rule.Enabled = enabled
		rule.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		r.rules[i] = rule
		r.rulesByID[ruleID] = rule
		if err := r.persistLocked(); err != nil {
			return err
		}
		return r.appendAudit("toggle_rule", actor, ruleID)
	}
	return fmt.Errorf("rule not found: %s", ruleID)
}

func (r *RuleManager) UpsertRule(rule HuntRule, actor string) error {
	if err := validateRule(rule); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rule.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	updated := false
	for i := range r.rules {
		if r.rules[i].RuleID == rule.RuleID {
			r.rules[i] = rule
			updated = true
			break
		}
	}
	if !updated {
		r.rules = append(r.rules, rule)
	}
	r.rulesByID[rule.RuleID] = rule
	if err := r.persistLocked(); err != nil {
		return err
	}
	return r.appendAudit("upsert_rule", actor, rule.RuleID)
}

func (r *RuleManager) persistLocked() error {
	payload := RuleSet{Version: "1.0", Rules: r.rules}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(r.ruleFile), 0o750); err != nil {
		return err
	}
	return os.WriteFile(r.ruleFile, b, 0o640)
}

func (r *RuleManager) appendAudit(action, actor, ruleID string) error {
	if err := os.MkdirAll(filepath.Dir(r.auditLog), 0o750); err != nil {
		return err
	}
	entry := map[string]string{
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"action":    action,
		"actor":     actor,
		"rule_id":   ruleID,
	}
	b, _ := json.Marshal(entry)
	f, err := os.OpenFile(r.auditLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

func validateRuleSet(rs RuleSet) error {
	if len(rs.Rules) == 0 {
		return errors.New("ruleset must contain at least one rule")
	}
	ids := map[string]struct{}{}
	for _, rule := range rs.Rules {
		if _, ok := ids[rule.RuleID]; ok {
			return fmt.Errorf("duplicate rule_id %s", rule.RuleID)
		}
		ids[rule.RuleID] = struct{}{}
		if err := validateRule(rule); err != nil {
			return fmt.Errorf("rule %s: %w", rule.RuleID, err)
		}
	}
	return nil
}

func validateRule(rule HuntRule) error {
	if strings.TrimSpace(rule.RuleID) == "" {
		return errors.New("rule_id required")
	}
	if strings.TrimSpace(rule.Description) == "" {
		return errors.New("description required")
	}
	if len(rule.TargetEventIDs) == 0 {
		return errors.New("target_event_ids required")
	}
	if rule.RiskWeight < 1 || rule.RiskWeight > 100 {
		return errors.New("risk_weight must be between 1 and 100")
	}
	if err := validateCondition(rule.Conditions); err != nil {
		return err
	}
	return nil
}

func validateCondition(c RuleCondition) error {
	op := strings.ToUpper(strings.TrimSpace(c.Operator))
	switch op {
	case "AND", "OR":
		if len(c.Checks) == 0 && len(c.Any) == 0 && len(c.All) == 0 {
			return errors.New("condition must contain checks, any, or all")
		}
		for _, check := range c.Checks {
			if strings.TrimSpace(check.Field) == "" {
				return errors.New("condition check field required")
			}
			switch strings.ToLower(check.Operator) {
			case "equals", "contains", "prefix", "suffix", "not_equals":
			default:
				return fmt.Errorf("unsupported operator %s", check.Operator)
			}
		}
		for _, sub := range c.Any {
			if err := validateCondition(sub); err != nil {
				return err
			}
		}
		for _, sub := range c.All {
			if err := validateCondition(sub); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported condition operator %s", c.Operator)
	}
	return nil
}

func EvaluateRules(event schema.Event, rules []HuntRule) []RuleMatch {
	matches := []RuleMatch{}
	for _, rule := range rules {
		if !rule.Enabled || !containsEventID(rule.TargetEventIDs, event.WindowsEventID) {
			continue
		}
		ok, reasons := evaluateCondition(rule.Conditions, event)
		if ok {
			matches = append(matches, RuleMatch{Rule: rule, Reasons: reasons})
		}
	}
	return matches
}

type RuleMatch struct {
	Rule    HuntRule
	Reasons []string
}

func evaluateCondition(c RuleCondition, event schema.Event) (bool, []string) {
	op := strings.ToUpper(c.Operator)
	results := make([]bool, 0, len(c.Checks)+len(c.Any)+len(c.All))
	reasons := []string{}
	for _, check := range c.Checks {
		matched, reason := evaluateCheck(check, event)
		results = append(results, matched)
		if matched {
			reasons = append(reasons, reason)
		}
	}
	for _, sub := range c.Any {
		matched, subReasons := evaluateCondition(sub, event)
		results = append(results, matched)
		if matched {
			reasons = append(reasons, subReasons...)
		}
	}
	for _, sub := range c.All {
		matched, subReasons := evaluateCondition(sub, event)
		results = append(results, matched)
		if matched {
			reasons = append(reasons, subReasons...)
		}
	}
	if len(results) == 0 {
		return false, nil
	}
	if op == "AND" {
		for _, r := range results {
			if !r {
				return false, nil
			}
		}
		return true, reasons
	}
	for _, r := range results {
		if r {
			return true, reasons
		}
	}
	return false, nil
}

func evaluateCheck(check FieldCondition, event schema.Event) (bool, string) {
	actual := strings.ToLower(event.Data[check.Field])
	expected := strings.ToLower(check.Value)
	switch strings.ToLower(check.Operator) {
	case "equals":
		if actual == expected {
			return true, fmt.Sprintf("%s equals %q", check.Field, check.Value)
		}
	case "not_equals":
		if actual != expected {
			return true, fmt.Sprintf("%s not_equals %q", check.Field, check.Value)
		}
	case "contains":
		if strings.Contains(actual, expected) {
			return true, fmt.Sprintf("%s contains %q", check.Field, check.Value)
		}
	case "prefix":
		if strings.HasPrefix(actual, expected) {
			return true, fmt.Sprintf("%s starts with %q", check.Field, check.Value)
		}
	case "suffix":
		if strings.HasSuffix(actual, expected) {
			return true, fmt.Sprintf("%s ends with %q", check.Field, check.Value)
		}
	}
	return false, ""
}

func containsEventID(ids []int, eventID int) bool {
	for _, id := range ids {
		if id == eventID {
			return true
		}
	}
	return false
}
