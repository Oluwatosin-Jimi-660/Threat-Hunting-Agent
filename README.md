# Threat-Hunting-Agent

Production-oriented reference implementation of the **Threat Hunting AI Agent** architecture described in `docs/THREAT_HUNTING_AI_AGENT_Architecture_v1.0.md`.

## What is implemented

- Windows-oriented endpoint agent (`cmd/agent`) with:
  - Event ingestion (PowerShell-based `Get-WinEvent` query on Windows, synthetic feed fallback off-Windows)
  - Whitelist-driven local heuristics/risk scoring
  - Bounded queue + periodic batched HTTPS transmission
  - TLS 1.2+ enforcement and bearer token auth header
- Central intelligence server (`cmd/server`) with:
  - Authenticated ingest API (`/ingest/v1`)
  - Strict unknown-field rejection (`DisallowUnknownFields`) and envelope validation
  - Batch deduplication by `batch_id`
  - Bayesian posterior updates from event-pattern likelihoods
  - 15-minute behavioral chain correlation
  - MITRE ATT&CK mapping output
  - Basic analyst dashboard endpoint (`/dashboard`) and chains API (`/api/chains`)
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
