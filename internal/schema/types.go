package schema

import "time"

type TelemetryEnvelope struct {
	SchemaVersion string       `json:"schema_version"`
	Envelope      EnvelopeMeta `json:"envelope"`
	Events        []Event      `json:"events"`
}

type EnvelopeMeta struct {
	AgentID      string `json:"agent_id"`
	EndpointID   string `json:"endpoint_id"`
	SentAt       string `json:"sent_at"`
	AgentVersion string `json:"agent_version"`
	BatchID      string `json:"batch_id"`
	SequenceNum  int64  `json:"sequence_num"`
}

type Event struct {
	EventID        string            `json:"event_id"`
	WindowsEventID int               `json:"windows_event_id"`
	LogChannel     string            `json:"log_channel"`
	RecordedAt     string            `json:"recorded_at"`
	LocalScore     int               `json:"local_score"`
	Data           map[string]string `json:"data"`
	Hashes         map[string]string `json:"hashes,omitempty"`
	ScoreReasons   []string          `json:"score_reasons,omitempty"`
}

type CorrelatedChain struct {
	EndpointID       string      `json:"endpoint_id"`
	Start            time.Time   `json:"start"`
	End              time.Time   `json:"end"`
	CompositeScore   int         `json:"composite_score"`
	Posterior        float64     `json:"posterior"`
	Pattern          string      `json:"pattern"`
	ATTACKTechniques []ATTACKMap `json:"attack_techniques"`
	Events           []Event     `json:"events"`
}

type ATTACKMap struct {
	TechniqueID   string  `json:"technique_id"`
	TechniqueName string  `json:"technique_name"`
	TacticID      string  `json:"tactic_id"`
	TacticName    string  `json:"tactic_name"`
	Confidence    float64 `json:"confidence"`
}
