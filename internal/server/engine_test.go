package server

import (
	"testing"
	"time"

	"threat-hunting-agent/internal/schema"
)

func TestOverviewAggregatesRiskAndTechniqueCounts(t *testing.T) {
	eng := NewEngine()
	eng.Ingest(schema.TelemetryEnvelope{
		SchemaVersion: "1.0",
		Envelope:      schema.EnvelopeMeta{EndpointID: "endpoint-a", BatchID: "b1"},
		Events: []schema.Event{
			{
				EventID:        "e1",
				WindowsEventID: 4104,
				LogChannel:     "PowerShell",
				RecordedAt:     time.Now().Add(-5 * time.Minute).Format(time.RFC3339Nano),
				LocalScore:     65,
				Data:           map[string]string{"command_line": "powershell -enc aaa"},
			},
			{
				EventID:        "e2",
				WindowsEventID: 1102,
				LogChannel:     "Security",
				RecordedAt:     time.Now().Add(-4 * time.Minute).Format(time.RFC3339Nano),
				LocalScore:     30,
				Data:           map[string]string{},
			},
		},
	})

	overview := eng.Overview()
	if overview.TotalEndpoints != 1 {
		t.Fatalf("expected 1 endpoint, got %d", overview.TotalEndpoints)
	}
	if overview.TotalEvents != 2 {
		t.Fatalf("expected 2 events, got %d", overview.TotalEvents)
	}
	if overview.TotalChains == 0 {
		t.Fatalf("expected at least one chain")
	}
	if len(overview.AttackTechniqueMap) == 0 {
		t.Fatalf("expected attack technique counts")
	}
	if len(overview.EndpointScores) != 1 {
		t.Fatalf("expected endpoint score snapshot")
	}
	if overview.EndpointScores[0].EndpointID != "endpoint-a" {
		t.Fatalf("unexpected endpoint id: %s", overview.EndpointScores[0].EndpointID)
	}
}
