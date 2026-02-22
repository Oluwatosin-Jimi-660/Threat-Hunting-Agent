# Rule Management and Findings Architecture

This document defines the transparent, explainable, and secure-by-design hunting rule system implemented by the server.

## 1. Architecture and Separation of Concerns

The current implementation uses **central rule evaluation**:

1. Endpoint agent reads Windows events and forwards structured telemetry.
2. Ingest API authenticates requests and validates schema.
3. Rule engine evaluates incoming events against declarative rules.
4. Risk scoring uses rule `risk_weight` for each match.
5. Findings store keeps structured findings for retrieval APIs.

### Components

- **Log Collection**: `cmd/agent`, `internal/agent/reader.go`, `internal/agent/transmitter.go`
- **Rule Engine**: `internal/server/rules.go`
- **Risk Scoring**: rule `risk_weight` + existing Bayesian chain scoring in `internal/server/engine.go`
- **Findings Storage**: in-memory centralized store in `internal/server/findings.go`

## 2. Data Schema

## 2.1 Rules

```json
{
  "version": "1.0",
  "rules": [
    {
      "rule_id": "WIN-PS-ENCODED-001",
      "description": "PowerShell command line contains encoded command marker",
      "target_event_ids": [4688, 4104],
      "conditions": {
        "operator": "OR",
        "checks": [
          { "field": "command_line", "operator": "contains", "value": "-enc" },
          { "field": "command_line", "operator": "contains", "value": "encodedcommand" }
        ]
      },
      "mitre_technique": {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "confidence": 0.9
      },
      "risk_weight": 60,
      "enabled": true
    }
  ]
}
```

Supported field operators are: `equals`, `not_equals`, `contains`, `prefix`, `suffix`.

Condition groups support nested boolean logic via:
- `operator: AND|OR`
- `checks: []`
- `all: []RuleCondition`
- `any: []RuleCondition`

## 2.2 Findings

```json
{
  "timestamp": "2026-01-01T10:00:00Z",
  "endpoint_id": "endpoint-123",
  "rule_id": "WIN-PS-ENCODED-001",
  "matched_event_data": {
    "event_id": "...",
    "windows_event_id": 4104,
    "log_channel": "PowerShell",
    "recorded_at": "...",
    "local_score": 40,
    "data": { "command_line": "powershell -enc ..." }
  },
  "risk_score": 60,
  "explanation": "Matched because: command_line contains \"-enc\"",
  "mitre_technique": {
    "technique_id": "T1059.001",
    "technique_name": "PowerShell",
    "tactic_id": "TA0002",
    "tactic_name": "Execution",
    "confidence": 0.9
  }
}
```

## 2.3 Rule Match Explanation

Explanation is generated as a human-readable sentence assembled from matched checks, for example:

- `Matched because: command_line contains "-enc"`
- `Matched because: parent_process equals "winword.exe"; command_line contains "cmd.exe"`

## 3. API Design

### Active Rules
- `GET /api/rules` — list active hunts (includes ID, description, target IDs, conditions, MITRE, risk weight, status).
- `POST /api/rules` — create/update rule (requires `Authorization: Bearer <THREAT_ADMIN_KEY>`).
- `PUT /api/rules` — same as POST.
- `POST /api/rules/reload` — safe reload from file (requires admin key).

### Findings
- `GET /api/findings?endpoint_id=<id>`
- `GET /api/findings?rule_id=<id>`
- `GET /api/findings?start=<RFC3339>&end=<RFC3339>`
- Queries can be combined.
- `GET /api/findings/risk-distribution`

### Existing Transparency Endpoints
- `GET /api/overview`
- `GET /api/chains`

## 4. Secure-by-Design Controls

- Rule files are validated before load (`validateRuleSet`, `validateRule`, `validateCondition`).
- Rules are declarative JSON only; no embedded scripts and no runtime code execution.
- Rule modifications are logged to an audit file (`THREAT_RULE_AUDIT_LOG`, default `logs/rule_audit.log`).
- Authentication required for adding/updating/reloading rules (`THREAT_ADMIN_KEY`).
- Ingest API authentication required for telemetry (`THREAT_API_KEY`).
- No hardcoded secrets: runtime requires env-provided secrets, with generated ephemeral fallback for local dev.
- Encrypted communication supported via TLS by setting `TLS_CERT_FILE` and `TLS_KEY_FILE`.

## 5. Example Rule File

See `config/hunt-rules.json`.
