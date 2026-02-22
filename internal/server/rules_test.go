package server

import (
	"os"
	"path/filepath"
	"testing"

	"threat-hunting-agent/internal/schema"
)

func TestEvaluateRulesMatchesExpectedEvent(t *testing.T) {
	rules := []HuntRule{{
		RuleID:         "R1",
		Description:    "encoded powershell",
		TargetEventIDs: []int{4104},
		Conditions: RuleCondition{Operator: "AND", Checks: []FieldCondition{{
			Field: "command_line", Operator: "contains", Value: "-enc",
		}}},
		RiskWeight: 50,
		Enabled:    true,
	}}
	event := schema.Event{WindowsEventID: 4104, Data: map[string]string{"command_line": "powershell -enc AAA"}}
	matches := EvaluateRules(event, rules)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Rule.RuleID != "R1" {
		t.Fatalf("unexpected rule id %s", matches[0].Rule.RuleID)
	}
}

func TestRuleManagerUpsertPersistsAndAudits(t *testing.T) {
	tmp := t.TempDir()
	ruleFile := filepath.Join(tmp, "rules.json")
	auditFile := filepath.Join(tmp, "audit.log")
	if err := os.WriteFile(ruleFile, []byte(`{"version":"1.0","rules":[{"rule_id":"A","description":"d","target_event_ids":[1],"conditions":{"operator":"AND","checks":[{"field":"x","operator":"equals","value":"y"}]},"risk_weight":1,"enabled":true}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rm, err := NewRuleManager(ruleFile, auditFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := rm.UpsertRule(HuntRule{
		RuleID:         "B",
		Description:    "new",
		TargetEventIDs: []int{2},
		Conditions:     RuleCondition{Operator: "AND", Checks: []FieldCondition{{Field: "a", Operator: "contains", Value: "b"}}},
		RiskWeight:     10,
		Enabled:        true,
	}, "tester"); err != nil {
		t.Fatal(err)
	}
	if len(rm.Rules()) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rm.Rules()))
	}
	if b, err := os.ReadFile(auditFile); err != nil || len(b) == 0 {
		t.Fatalf("expected non-empty audit log")
	}
}
