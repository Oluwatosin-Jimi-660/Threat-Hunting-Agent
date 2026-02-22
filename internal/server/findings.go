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
	mu             sync.RWMutex
	findings       []Finding
	byEndpoint     map[string][]int
	byRule         map[string][]int
	retention      time.Duration
	tamperFindings []Finding
}

func NewFindingsStore(retention time.Duration) *FindingsStore {
	return &FindingsStore{findings: []Finding{}, byEndpoint: map[string][]int{}, byRule: map[string][]int{}, retention: retention}
}

func (f *FindingsStore) Add(newFindings ...Finding) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pruneLocked(time.Now().UTC())
	for _, finding := range newFindings {
		if finding.RuleID == "tamper_event" {
			f.tamperFindings = append(f.tamperFindings, finding)
		}
		f.findings = append(f.findings, finding)
		idx := len(f.findings) - 1
		f.byEndpoint[finding.EndpointID] = append(f.byEndpoint[finding.EndpointID], idx)
		f.byRule[finding.RuleID] = append(f.byRule[finding.RuleID], idx)
	}
}

func (f *FindingsStore) Query(endpointID, ruleID string, start, end time.Time) []Finding {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := []Finding{}
	indexes := make([]int, 0)
	if endpointID != "" {
		indexes = append(indexes, f.byEndpoint[endpointID]...)
	} else if ruleID != "" {
		indexes = append(indexes, f.byRule[ruleID]...)
	} else {
		indexes = make([]int, len(f.findings))
		for i := range f.findings {
			indexes[i] = i
		}
	}
	for _, idx := range indexes {
		finding := f.findings[idx]
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

func (f *FindingsStore) TamperEvents(endpointID string) []Finding {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]Finding, 0, len(f.tamperFindings))
	for _, finding := range f.tamperFindings {
		if endpointID != "" && finding.EndpointID != endpointID {
			continue
		}
		out = append(out, finding)
	}
	return out
}

func (f *FindingsStore) pruneLocked(now time.Time) {
	if f.retention <= 0 || len(f.findings) == 0 {
		return
	}
	keep := make([]Finding, 0, len(f.findings))
	f.byEndpoint = map[string][]int{}
	f.byRule = map[string][]int{}
	for _, finding := range f.findings {
		ts, err := time.Parse(time.RFC3339Nano, finding.Timestamp)
		if err != nil || now.Sub(ts) > f.retention {
			continue
		}
		keep = append(keep, finding)
		idx := len(keep) - 1
		f.byEndpoint[finding.EndpointID] = append(f.byEndpoint[finding.EndpointID], idx)
		f.byRule[finding.RuleID] = append(f.byRule[finding.RuleID], idx)
	}
	f.findings = keep
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
