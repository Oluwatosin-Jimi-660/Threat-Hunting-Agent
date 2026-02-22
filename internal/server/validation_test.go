package server

import (
	"testing"
	"time"

	"threat-hunting-agent/internal/schema"
)

func validEnvelope() schema.TelemetryEnvelope {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return schema.TelemetryEnvelope{
		SchemaVersion: "1.0",
		Envelope: schema.EnvelopeMeta{
			AgentID:    "agent-1",
			EndpointID: "endpoint-1",
			BatchID:    "batch-1",
			SentAt:     now,
		},
		Events: []schema.Event{{
			EventID:        "evt-1",
			WindowsEventID: 4688,
			RecordedAt:     now,
			Data:           map[string]string{"process_name": "powershell.exe"},
		}},
	}
}

func TestValidateTelemetryEnvelope_Valid(t *testing.T) {
	env := validEnvelope()
	if err := ValidateTelemetryEnvelope(env); err != nil {
		t.Fatalf("expected valid envelope, got error: %v", err)
	}
}

func TestValidateTelemetryEnvelope_RejectsMissingBatchID(t *testing.T) {
	env := validEnvelope()
	env.Envelope.BatchID = ""
	if err := ValidateTelemetryEnvelope(env); err == nil {
		t.Fatal("expected error for missing batch_id")
	}
}

func TestValidateTelemetryEnvelope_RejectsBadRecordedAt(t *testing.T) {
	env := validEnvelope()
	env.Events[0].RecordedAt = "2026-01-02"
	if err := ValidateTelemetryEnvelope(env); err == nil {
		t.Fatal("expected error for bad recorded_at")
	}
}
