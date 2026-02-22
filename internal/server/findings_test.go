package server

import (
	"testing"
	"time"
)

func TestFindingsQueryAndRiskDistribution(t *testing.T) {
	store := NewFindingsStore()
	now := time.Now().UTC()
	store.Add(
		Finding{Timestamp: now.Add(-2 * time.Minute).Format(time.RFC3339Nano), EndpointID: "e1", RuleID: "r1", RiskScore: 20},
		Finding{Timestamp: now.Add(-1 * time.Minute).Format(time.RFC3339Nano), EndpointID: "e1", RuleID: "r2", RiskScore: 65},
		Finding{Timestamp: now.Format(time.RFC3339Nano), EndpointID: "e2", RuleID: "r1", RiskScore: 85},
	)
	results := store.Query("e1", "", now.Add(-3*time.Minute), now)
	if len(results) != 2 {
		t.Fatalf("expected 2 findings for endpoint e1, got %d", len(results))
	}
	d := store.RiskDistribution()
	if d["critical"] != 1 || d["high"] != 1 || d["low"] != 1 {
		t.Fatalf("unexpected distribution: %#v", d)
	}
}
