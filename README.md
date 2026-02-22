# Threat-Hunting-Agent

Production-oriented reference implementation of the **Threat Hunting AI Agent** architecture described in `docs/THREAT_HUNTING_AI_AGENT_Architecture_v1.0.md`.

## What is implemented

- Windows-oriented endpoint agent (`cmd/agent`) with:
  - Event ingestion (PowerShell-based `Get-WinEvent` query on Windows, synthetic feed fallback off-Windows)
  - High-value event ID filtering and structured normalization only (no local detection logic)
  - Bounded queue + periodic batched HTTPS transmission
  - TLS 1.2+ enforcement, optional mTLS cert support, and bearer token auth header
  - Tamper signal emission for monitored configuration changes
- Central intelligence server (`cmd/server`) with:
  - Authenticated ingest API (`/ingest/v1`)
  - Dynamic declarative hunting rules loaded from `config/hunt-rules.json`
  - Rule validation + reload endpoint (`/api/rules/reload`)
  - Rule versions, rollback, and enable/disable APIs
  - Active hunt transparency API (`/api/rules`)
  - Rule match findings store and query APIs (`/api/findings`, `/api/findings/risk-distribution`)
  - Strict unknown-field rejection (`DisallowUnknownFields`) and envelope validation
  - Batch deduplication by `batch_id`
  - Bayesian posterior updates + risk decay + explainability trail endpoint (`/api/risk/{endpoint}`)
  - 15-minute behavioral chain correlation
  - MITRE ATT&CK mapping output
  - Basic analyst dashboard endpoint (`/dashboard`) and chains API (`/api/chains`)
  - Architecture details in `docs/option-b-centralized-detection-architecture.md`
- Telemetry schema (`schema/telemetry.v1.json`)

## Run

```bash
go run ./cmd/server
```

In another shell:

```bash
go run ./cmd/agent
```

## Security posture highlights

- Read-only telemetry collection, no process injection/memory scraping.
- Least-privilege endpoint design with bounded queue fail-safe.
- TLS enforced in transport client.
- Schema contract with explicit field restrictions.
- Explainable scoring path (heuristics + Bayesian updates + ATT&CK mapping).


## Configuration

Set secrets using environment variables:

- `THREAT_API_KEY`: required for ingest authentication
- `THREAT_ADMIN_KEY`: required for rule add/update/reload APIs
- `THREAT_RULE_FILE`: optional path to rule JSON (default `config/hunt-rules.json`)
- `THREAT_RULE_AUDIT_LOG`: optional path to rule audit log (default `logs/rule_audit.log`)
- `TLS_CERT_FILE` + `TLS_KEY_FILE`: optional TLS cert/key pair for encrypted server transport

For complete rule and findings architecture + API details, see `docs/rule-management-and-findings.md`.
