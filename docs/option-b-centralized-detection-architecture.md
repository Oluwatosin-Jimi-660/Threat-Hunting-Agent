# Option B: Centralized Detection and Risk Architecture

## 1) Architecture Overview

### Endpoint agent responsibilities (only)
1. Read selected Windows logs through documented APIs (`Get-WinEvent` over Event Log API):
   - Security
   - System
   - Microsoft-Windows-PowerShell/Operational
   - Microsoft-Windows-TaskScheduler/Operational
   - Microsoft-Windows-Windows Defender/Operational
2. Filter to high-value event IDs before serialization.
3. Normalize events to structured JSON (`schema.TelemetryEnvelope`).
4. Minimal preprocessing only (field normalization and XML extraction only).
5. Securely transmit telemetry with TLS 1.2+ and optional client certificate.
6. Run least privilege (read event logs + outbound HTTPS).
7. Emit tamper event if monitored config changes.

### Central system responsibilities
- Declarative rule engine (JSON/YAML), versioning, rollback, enable/disable.
- Signed rule package verification prior to activation.
- Multi-event correlation (time window + sequence logic).
- Bayesian compromise probability with decay and explainable update trail.
- Threat intel feed ingestion and enrichment at rule evaluation time.
- Structured findings storage and retention/pruning.
- Authenticated RBAC-ready APIs.

## 2) Data Schemas

### Telemetry envelope
```json
{
  "schema_version": "1.0",
  "envelope": {
    "agent_id": "agent-123",
    "endpoint_id": "endpoint-abc",
    "sent_at": "2026-02-22T10:00:00Z",
    "agent_version": "1.1.0",
    "batch_id": "uuid",
    "sequence_num": 94
  },
  "events": [
    {
      "event_id": "evt-1",
      "windows_event_id": 4688,
      "log_channel": "Security",
      "recorded_at": "2026-02-22T09:59:58Z",
      "data": {"process_name": "powershell.exe", "command_line": "..."}
    }
  ]
}
```

### Rule package
```json
{
  "package_version": "2026.02.22.1",
  "signed_at": "2026-02-22T10:00:00Z",
  "signer": "soc-platform-key-1",
  "payload": {
    "version": "2026.02.22",
    "rules": []
  },
  "signature": "base64-ed25519-signature"
}
```

### Finding record
```json
{
  "timestamp": "2026-02-22T10:00:02Z",
  "endpoint_id": "endpoint-abc",
  "rule_id": "RULE-PS-ENC-001",
  "risk_score": 71,
  "mitre_technique": {"technique_id": "T1059.001"},
  "matched_event_data": {}
}
```

### Correlation state
```json
{
  "endpoint_id": "endpoint-abc",
  "start": "...",
  "end": "...",
  "pattern": "security:4688 -> security:4698 -> system:7045",
  "events": []
}
```

### Risk API model
```json
{
  "endpoint_id": "endpoint-abc",
  "posterior": 0.71,
  "risk_score": 71,
  "explainability": [
    {
      "rule_id": "RULE-PS-ENC-001",
      "likelihood_compromised": 0.75,
      "likelihood_clean": 0.15,
      "reason": "command_line contains encodedcommand",
      "time": "..."
    }
  ]
}
```

## 3) Correlation Engine Design

- Event memory bounded per endpoint (`maxEventsPerHost`).
- Configurable window (`5m` to `60m`, default `15m`).
- Sequence-aware pattern representation (`A -> B -> C`).
- Emits one structured correlated finding per chain.

## 4) Bayesian Risk Model

- Prior default: `0.01`.
- Update formula:
  - `posterior = P(E|C)*prior / (P(E|C)*prior + P(E|~C)*(1-prior))`
- Time decay to prior using exponential half-life (default `6h`).
- Explainability persisted as update trail (`rule_id`, likelihoods, reason, time).

## 5) Rule Signing and Validation

- Rule packages are signed with Ed25519.
- Central server validates:
  1. Signature authenticity (`ed25519.Verify`).
  2. Declarative schema constraints (`validateRuleSet`).
  3. No embedded scripts; declarative operators only.

## 6) Retention and Pruning

- Findings retention configurable (30–180 days recommended).
- Periodic prune on write path removes expired entries.
- Indexed in memory by endpoint and rule ID.
- Tamper events retained/queryable via dedicated API.

## 7) Secure Update Flow

1. Endpoint polls separate update channel (`THREAT_UPDATE_URL`).
2. Downloads signed package + detached signature.
3. Verifies signature before install.
4. Applies atomic swap update.
5. Sends update audit event to central.

## 8) Example Correlation Rule

```yaml
rule_id: RULE-BEH-CHAIN-001
enabled: true
description: "PowerShell encoded command followed by task creation and service install"
target_event_ids: [4688, 4698, 7045]
sequence:
  - event_id: 4688
    field: command_line
    operator: contains
    value: encodedcommand
  - event_id: 4698
  - event_id: 7045
window_minutes: 20
risk_weight: 35
mitre_technique:
  technique_id: T1059.001
```

## 9) APIs (governance targets)

- `GET /api/rules`
- `GET /api/rules/versions`
- `POST /api/rules` (add/update)
- `POST /api/rules/rollback?version=...`
- `POST /api/rules/toggle?rule_id=...&enabled=true|false`
- `GET /api/findings`
- `GET /api/risk/{endpoint_id}`
- `GET /api/chains`
- `GET /api/tamper-events`

## 10) Security-by-design notes

- No hardcoded secrets required; env-only secrets and cert paths.
- Unknown field rejection and strict telemetry validation are preserved.
- Endpoint logic intentionally excludes detection/risk decisions.
