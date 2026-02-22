package server

import (
	"errors"
	"strings"
	"time"

	"threat-hunting-agent/internal/schema"
)

func ValidateTelemetryEnvelope(env schema.TelemetryEnvelope) error {
	if env.SchemaVersion != "1.0" {
		return errors.New("invalid schema_version")
	}
	if strings.TrimSpace(env.Envelope.EndpointID) == "" {
		return errors.New("envelope.endpoint_id required")
	}
	if strings.TrimSpace(env.Envelope.BatchID) == "" {
		return errors.New("envelope.batch_id required")
	}
	if strings.TrimSpace(env.Envelope.AgentID) == "" {
		return errors.New("envelope.agent_id required")
	}
	if len(env.Events) == 0 || len(env.Events) > 100 {
		return errors.New("events must contain 1-100 entries")
	}
	if sentAt := strings.TrimSpace(env.Envelope.SentAt); sentAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, sentAt); err != nil {
			return errors.New("envelope.sent_at must be RFC3339Nano")
		}
	}
	for _, evt := range env.Events {
		if strings.TrimSpace(evt.EventID) == "" {
			return errors.New("event.event_id required")
		}
		if strings.TrimSpace(evt.RecordedAt) == "" {
			return errors.New("event.recorded_at required")
		}
		if _, err := time.Parse(time.RFC3339Nano, evt.RecordedAt); err != nil {
			return errors.New("event.recorded_at must be RFC3339Nano")
		}
	}
	return nil
}
