package server

import (
	"sort"
	"sync"
	"time"

	"threat-hunting-agent/internal/schema"
)

type Finding struct {
	Timestamp    string            `json:"timestamp"`
	EndpointID   string            `json:"endpoint_id"`
	RuleID       string            `json:"rule_id"`
	MatchedEvent schema.Event      `json:"matched_event_data"`
	RiskScore    int               `json:"risk_score"`
	Explanation  string            `json:"explanation"`
	MITRE        *schema.ATTACKMap `json:"mitre_technique,omitempty"`
}

type FindingsStore struct {
	mu       sync.RWMutex
	findings []Finding
}

func NewFindingsStore() *FindingsStore { return &FindingsStore{findings: []Finding{}} }

func (f *FindingsStore) Add(newFindings ...Finding) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.findings = append(f.findings, newFindings...)
}

func (f *FindingsStore) Query(endpointID, ruleID string, start, end time.Time) []Finding {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := []Finding{}
	for _, finding := range f.findings {
		t, err := time.Parse(time.RFC3339Nano, finding.Timestamp)
		if err != nil {
			continue
		}
		if endpointID != "" && finding.EndpointID != endpointID {
			continue
		}
		if ruleID != "" && finding.RuleID != ruleID {
			continue
		}
		if !start.IsZero() && t.Before(start) {
			continue
		}
		if !end.IsZero() && t.After(end) {
			continue
		}
		out = append(out, finding)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp < out[j].Timestamp })
	return out
}

func (f *FindingsStore) RiskDistribution() map[string]int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	d := map[string]int{"low": 0, "medium": 0, "high": 0, "critical": 0}
	for _, finding := range f.findings {
		s := finding.RiskScore
		switch {
		case s >= 80:
			d["critical"]++
		case s >= 60:
			d["high"]++
		case s >= 30:
			d["medium"]++
		default:
			d["low"]++
		}
	}
	return d
}
