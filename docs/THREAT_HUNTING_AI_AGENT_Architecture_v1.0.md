# THREAT HUNTING AI AGENT
## Architecture Design & Implementation Reference
**Windows-Only | Secure-by-Design | MITRE ATT&CK Aligned**

**Version 1.0 | Confidential Engineering Reference**

---

## 1. Introduction & Design Philosophy

This document describes the complete architecture of a lightweight, Windows-native threat hunting AI agent. The system is designed from first principles around one core constraint: it must never behave like the malware it is hunting. Every design decision flows from this constraint.

The system consists of two tiers:
- **An Endpoint Agent** — a Windows service that reads existing telemetry (Event Logs, Defender data) and ships structured JSON to a central server.
- **A Central Intelligence Server** — a backend that correlates events across endpoints, scores behaviors probabilistically, maps detections to MITRE ATT&CK, and presents findings in a dashboard.

### 1.1 The Non-Malware Contract

Security tools that behave aggressively are a liability. Kernel drivers, memory scraping, process injection, and deep registry crawling are behaviors shared with sophisticated malware — using them creates detection blind spots, introduces instability, and undermines trust. This agent deliberately avoids all of them:

| Technique | Why Avoided | What We Do Instead |
|---|---|---|
| Kernel drivers | Instability, bypass risk | Windows Event Log API only |
| Memory scraping | AV detection, fragile | Event log process creation records |
| Process injection | Malware hallmark, AV flagging | Standalone service, no injection |
| Registry crawling | Performance cost, noisy | Event 4698/4699 for scheduled tasks |
| Filesystem scanning | High I/O, Defender conflicts | Defender alerts via Event Log |

### 1.2 Design Principles Summary

- Read, don't touch: consume existing Windows telemetry — never generate new system load
- Least privilege: only Event Log read rights and outbound HTTPS
- Transparent by design: every decision is loggable, auditable, explainable
- Defense in depth at the channel: TLS + mutual auth between agent and server
- Probabilistic, not brittle: Bayesian scoring resists single-event evasion

---

## 2. System Architecture

### 2.1 High-Level Architecture

The system follows a strict two-tier design with a clean separation between data collection and intelligence. The endpoint agent is deliberately "dumb" — it collects, filters, and ships. All intelligence lives centrally.

```text
System Architecture Overview
  ┌─────────────────────────────────────────────────────────────────┐
  │                     ENDPOINT (Windows Host)                    │
  │                                                                 │
  │  ┌─────────────┐   ┌──────────────┐   ┌────────────────────┐  │
  │  │ Event Log   │   │   Event Log  │   │  Local Risk        │  │
  │  │ Reader      │──▶│   Event Log  │──▶│  Scorer (optional) │  │
  │  │ (Win32 API) │   │   Filter     │   │                    │  │
  │  └─────────────┘   └──────────────┘   └────────┬───────────┘  │
  │                                                 │              │
  │                                          ┌──────▼──────┐       │
  │                                          │ TLS+Auth    │       │
  │                                          │ Transmitter │       │
  │                                          └──────┬──────┘       │
  └─────────────────────────────────────────────── │ ─────────────┘
                                                    │ HTTPS/TLS
                                                    │ (API Key or mTLS)
  ┌─────────────────────────────────────────────── │ ─────────────┐
  │                CENTRAL SERVER                   │              │
  │                                          ┌──────▼──────┐       │
  │                                          │  Ingest API │       │
  │                                          └──────┬──────┘       │
  │                                                 │              │
  │  ┌─────────────┐   ┌──────────────┐   ┌────────▼───────────┐  │
  │  │ MITRE ATT&CK│   │ Threat Intel │   │  Event Correlation  │  │
  │  │ Mapper      │◀──│ Enrichment   │◀──│  Engine (Bayesian)  │  │
  │  └──────┬──────┘   └──────────────┘   └────────────────────┘  │
  │         │                                                       │
  │  ┌──────▼──────────────────────────────────────────────────┐  │
  │  │         Analyst Dashboard (Risk Scores, TTP View)       │  │
  │  └─────────────────────────────────────────────────────────┘  │
  └─────────────────────────────────────────────────────────────────┘
```

### 2.2 Component Responsibilities

**Endpoint Agent Components**
- **Event Log Reader:** Uses the Windows EvtQuery/EvtNext API (via Go's `golang.org/x/sys/windows` package or CGo) to subscribe to specific Event Log channels. Only selected event IDs are retrieved — no bulk log reading.
- **Event Filter:** A whitelist-based filter that discards events not matching a curated set of security-relevant Event IDs. Reduces noise before transmission.
- **Local Risk Scorer:** An optional lightweight module that assigns a preliminary risk score (0-100) to each event based on simple heuristics. This reduces bandwidth by allowing the agent to suppress very low-risk events.
- **TLS Transmitter:** Buffers events into batches, serializes to JSON, and ships via HTTPS POST with authentication. Implements retry with exponential backoff and a local disk queue (bounded size) as a circuit breaker.

**Central Server Components**
- **Ingest API:** Validates, authenticates, and deserializes incoming telemetry. Enforces strict JSON schema validation before any processing.
- **Event Correlation Engine:** Groups related events by endpoint, user, and time window. Detects behavioral chains (e.g., PowerShell execution followed by a new service within 60 seconds) and scores them using Bayesian methods.
- **Threat Intelligence Enrichment:** Queries internal/external TI feeds for IP reputation, file hashes, and domain classification. Enriches events before scoring.
- **MITRE ATT&CK Mapper:** Maps scored behavioral chains to ATT&CK techniques and tactics. Provides structured output consumed by the dashboard.
- **Analyst Dashboard:** Presents risk scores, behavioral chains, TTP distribution, and supports analyst feedback to tune scoring weights.

---

## 3. Privilege Model

The privilege model is the most security-critical part of the endpoint agent design. Getting this wrong either leaves the agent blind to key events or causes it to run with unnecessary power — both failures.

### 3.1 Required Privileges

| Privilege / Right | Why Needed | How Granted | Risk If Revoked |
|---|---|---|---|
| Event Log Read (Security) | Read Security event channel | Member of 'Event Log Readers' group | Cannot read 4688, 4625, etc. |
| Event Log Read (System) | Read service/driver events | Default for service accounts | Misses 7045 service installs |
| Event Log Read (Application) | PowerShell and app logs | Default for service accounts | Misses PowerShell events |
| Outbound HTTPS (port 443) | Telemetry transmission | Windows Firewall allow rule | Agent goes silent |
| File system write (one dir) | Local event queue/buffering | ACL on `%ProgramData%\Agent` | Cannot buffer during outages |

### 3.2 Explicitly NOT Required (and NOT Requested)

- `SeDebugPrivilege` — This would allow reading other process memory. Never requested.
- `SeTcbPrivilege` — Acts as part of the OS. Never requested.
- `SeLoadDriverPrivilege` — Load kernel drivers. Never requested.
- Local Administrator rights — Service account is a dedicated low-privilege account.
- Registry write access — Agent never modifies registry values.
- Network share access — Agent is strictly outbound-only.

### 3.3 Service Account Configuration

The agent runs as a dedicated Windows service account (e.g., `NT SERVICE\ThreatHuntAgent`). At deployment:
1. Create a dedicated service account with no interactive logon rights.
2. Add the account to the built-in 'Event Log Readers' local group.
3. Grant 'Log on as a service' right via Local Security Policy.
4. Restrict the service binary directory: SYSTEM (Full), ThreatHuntAgent (Read/Execute), Everyone (None).
5. Configure Windows Firewall to allow only outbound TCP/443 for this process.

**Security Note on the Security Event Log**
Reading the Security log normally requires membership in the Event Log Readers group OR local Administrator. This design uses the Event Log Readers group — which is the specifically intended mechanism for this use case, avoiding any need for admin rights at runtime.

---

## 4. Monitored Events & Telemetry Schema

### 4.1 Monitored Windows Event IDs

| Event ID | Log Channel | Description | ATT&CK Relevance |
|---|---|---|---|
| 4688 | Security | Process creation (with command line) | T1059 Execution, T1036 Masquerading |
| 4624/4625 | Security | Logon success / failure | T1078 Valid Accounts, T1110 Brute Force |
| 4648 | Security | Logon with explicit credentials | T1550 Pass-the-Hash/Ticket |
| 4698/4699 | Security | Scheduled task created/deleted | T1053.005 Scheduled Task Persistence |
| 4657 | Security | Registry value modified | T1547 Boot/Logon Autostart |
| 4104 | PowerShell/Operational | Script block logging (full PS code) | T1059.001 PowerShell |
| 4103 | PowerShell/Operational | Pipeline/module execution | T1059.001 PowerShell |
| 7045 | System | New service installed | T1543.003 Windows Service |
| 7040 | System | Service start type changed | T1543.003 Persistence |
| 1102 | Security | Audit log cleared | T1070.001 Log Clearing |
| 5001/5004 | Windows Defender/Operational | Defender real-time protection changed | T1562.001 Disable Security Tools |
| 1116/1117 | Windows Defender/Operational | Malware detected / action taken | Execution confirmation signal |
| 4660/4663 | Security | Object deleted / access attempt | T1485 Data Destruction |

### 4.2 Prerequisites: Enabling Key Events

Several of these events require explicit enablement in Group Policy. Specifically:
- Event 4688 (Process Creation): Enable 'Audit Process Creation' in Security Policy AND enable 'Include command line in process creation events' via GPO (`Computer Configuration > Administrative Templates > System > Audit Process Creation`).
- Event 4104 (PowerShell Script Block): Enable via GPO or registry: `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging = 1`
- Event 4698/4699 (Task Scheduler): Enable 'Audit Other Object Access Events' in Security Policy.

### 4.3 Telemetry JSON Schema

Every event shipped to the central server uses this schema. The schema is validated at both the agent (before send) and the server (on receipt) using JSON Schema Draft 7.

```json
{
  "$schema": "https://example.com/threat-agent/telemetry/v1.json",
  "schema_version": "1.0",
  "envelope": {
    "agent_id": "uuid-v4-per-install",
    "endpoint_id": "sha256(hostname+machineGUID)",
    "sent_at": "2025-01-15T14:23:01.234Z",
    "agent_version": "1.2.3",
    "batch_id": "uuid-v4",
    "sequence_num": 42
  },
  "events": [
    {
      "event_id": "uuid-v4",
      "windows_event_id": 4688,
      "log_channel": "Security",
      "recorded_at": "2025-01-15T14:22:58.123Z",
      "local_score": 72,
      "data": {
        "process_name": "powershell.exe",
        "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\",
        "command_line": "powershell -enc <base64>",
        "parent_process": "cmd.exe",
        "parent_pid": 1234,
        "new_pid": 5678,
        "subject_user_sid": "S-1-5-21-...",
        "subject_user_name": "DOMAIN\\user",
        "logon_id": "0x3e7",
        "token_elevation": "TokenElevationTypeFull"
      },
      "hashes": {
        "sha256": "abc123..."
      }
    }
  ]
}
```

The schema deliberately omits raw full event XML to limit data volume and to enforce a contract between agent and server. Fields not in the schema are dropped at the agent, never forwarded. This prevents accidental leakage of PII or sensitive data embedded in event fields.

---

## 5. Probabilistic Risk Scoring Model

The scoring model operates in two stages: a lightweight local stage at the endpoint, and a full Bayesian stage at the central server.

### 5.1 Local (Endpoint) Scoring

The endpoint performs minimal scoring to enable bandwidth reduction. A simple additive scoring model assigns base scores:

| Condition | Score Delta | Rationale |
|---|---|---|
| PowerShell with `-enc` or `-encodedcommand` | +35 | Encoding is primary obfuscation vector |
| PowerShell with `-nop -w hidden` | +30 | Evasion flags common in malware |
| Process parent anomaly (e.g., Word→cmd.exe) | +40 | Office macros spawning shells |
| New service with driver path or network path | +35 | Suspicious service install target |
| Defender real-time protection disabled | +50 | Tamper indicator |
| Security log cleared (1102) | +60 | Anti-forensics |
| Process running from TEMP/AppData/Downloads | +25 | Non-standard execution path |
| Known benign process, normal hours, known path | -20 | Whitelist reduction |

Events scoring below 20 may be dropped locally to save bandwidth (configurable). All events scoring 50+ are always transmitted regardless of bandwidth constraints.

### 5.2 Central Bayesian Scoring

The central server uses a Bayesian update model to compute endpoint-level threat scores. The model maintains a prior probability that an endpoint is currently compromised, and updates it as evidence arrives.

```go
// Prior:  P(compromised) = 0.001
// For each new event E:
//   P(C | E) = P(E | C) * P(C)
//              ─────────────────────────────────
//              P(E | C) * P(C) + P(E | ¬C) * P(¬C)

type LikelihoodEntry struct {
    EventPattern string
    PGivenComp   float64
    PGivenClean  float64
}

var LikelihoodTable = []LikelihoodEntry{
    {"powershell_encoded",       0.85, 0.02},
    {"defender_disabled",        0.70, 0.005},
    {"log_cleared",              0.60, 0.001},
    {"new_service_from_temp",    0.75, 0.01},
    {"office_spawns_shell",      0.90, 0.003},
    {"scheduled_task_at_logon",  0.50, 0.05},
    {"lateral_move_logon",       0.65, 0.02},
}
```

### 5.3 Behavioral Chain Correlation

Individual events are grouped into behavioral chains by correlating events on the same endpoint within a configurable time window (default: 15 minutes). Chains trigger higher composite scores:

| Chain Pattern | Composite Score | ATT&CK Sequence |
|---|---|---|
| Office app → cmd → PowerShell (encoded) → outbound connection | CRITICAL (>90) | T1566→T1059.001→T1071 |
| PowerShell download → new service created | HIGH (75-89) | T1059.001→T1543.003 |
| Many logon failures → logon success (same user) | HIGH (70-84) | T1110→T1078 |
| Defender disabled → scheduled task created | CRITICAL (85+) | T1562.001→T1053 |
| Process from temp dir → log cleared | CRITICAL (88+) | T1059→T1070.001 |

### 5.4 Analyst Feedback Loop

Analysts can mark alerts as True Positive, False Positive, or Benign Activity. These labels feed a supervised update cycle that runs weekly:
- False Positives for a pattern increase `P(E | ¬C)` for that pattern, reducing future scores.
- Confirmed True Positives increase `P(E | C)`, sharpening future detection sensitivity.
- Bulk false positives on a specific endpoint or user can trigger a context-aware whitelist entry.

All feedback is stored in the audit log with analyst identity, timestamp, and justification. No model change is silent.

---

## 6. Threat Intelligence Integration

Threat intelligence (TI) enriches events at the central server — never at the endpoint. The endpoint has no TI connectivity, keeping its network footprint minimal and its behavior predictable.

### 6.1 Integration Points

| TI Type | Applied To | Data Source (examples) | Score Impact |
|---|---|---|---|
| File Hash Reputation | Hashes in 4688 events | VirusTotal API, CIRCL HASHLOOKUP, internal blocklist | +40 if known-malicious |
| IP Reputation | Destination IPs in network events | AbuseIPDB, AlienVault OTX, Shodan | +30 if C2/Tor/known-bad |
| Domain Reputation / DGA detection | DNS query events, command lines | Cisco Umbrella, Cloudflare Radar, internal DGA model | +25 if DGA-like |
| CVE / Vulnerability Context | Process versions observed | NVD API, internal vulnerability scanner feed | Context only, no score |
| Known TTP Signatures | Command line / script patterns | Sigma rules converted to patterns, YARA via Defender results | +20 to +50 per match |

### 6.2 TI Caching and Freshness

- All TI lookups are cached locally on the server with configurable TTL (default: hash = 24h, IP/domain = 4h).
- Lookups are performed asynchronously — incoming events are never blocked waiting for TI responses.
- TI sources are rate-limited and queued; no thundering herd on TI APIs.
- Offline/stale TI results in score reduction of 10 points (uncertainty penalty) but does not block analysis.

### 6.3 MITRE ATT&CK Mapping

ATT&CK mapping occurs as a post-scoring enrichment step. Each scored behavioral chain produces a list of candidate techniques:

```go
type ATTACKMapping struct {
    TechniqueID   string
    TechniqueName string
    TacticID      string
    TacticName    string
    Confidence    float64
}
```

---

## 7. Secure Communications & Secrets Management

### 7.1 Transport Security

- All communication uses TLS 1.2 minimum (TLS 1.3 preferred). The agent enforces minimum TLS version and rejects downgrade negotiation.
- Server certificate is pinned on the agent using the server's CA certificate public key hash (SPKI pinning), not the full certificate. This survives certificate renewal without agent updates.
- The agent validates the full certificate chain, not just the leaf certificate.

### 7.2 Authentication — Two Options

**Option A: API Key Authentication (Simpler)**
Each endpoint receives a unique API key at enrollment. The key is sent in the Authorization header (Bearer token). Keys are rotated on a 90-day schedule via an enrollment API.

```http
Authorization: Bearer <endpoint-specific-api-key>
X-Agent-ID: <agent-uuid>
X-Agent-Version: 1.2.3
Content-Type: application/json
```

**Option B: Mutual TLS (mTLS) — Recommended for Enterprise**
Each endpoint receives a client certificate at enrollment, signed by an internal CA. Both sides present certificates. This provides stronger authentication and enables certificate-based access control on the server.

### 7.3 Secrets Storage on Endpoint

API keys or client certificates are stored in the Windows Certificate Store (for certs) or in the Windows Data Protection API (DPAPI) encrypted file for API keys. Neither is stored in plaintext on disk or in the registry.
- DPAPI encryption binds the secret to the machine AND the service account SID — decryption only works on the same machine with the same account.
- No secrets appear in environment variables, command-line arguments, or config files in plaintext.
- The agent binary contains no embedded secrets — it loads secrets at runtime from DPAPI storage.

---

## 8. Enterprise Deployment Considerations

### 8.1 Deployment Methods

| Method | Notes | Recommended For |
|---|---|---|
| Group Policy (MSI) | MSI package deployed via GPO Computer Startup script. MSI must be signed with a trusted code-signing certificate (no SHA-1). | Most enterprise AD environments |
| SCCM / Intune | Win32 App package. Supports compliance reporting on installation status. | Intune-managed endpoints |
| Ansible / Chef / Puppet | Idempotent deployment module. Validates service running state. | Mixed OS, DevOps-managed fleets |
| Manual (testing only) | `Install-Agent.ps1` script. Not for production scale. | Lab / PoC environments |

### 8.2 Signing and Integrity

- The agent binary **MUST** be code-signed with an Extended Validation (EV) certificate. This prevents Windows SmartScreen warnings and enables AppLocker/WDAC policies to target it.
- The MSI package must also be signed. Verify with: `Get-AuthenticodeSignature agent.msi`
- Updates are delivered as signed MSI packages and verified before installation. The agent's auto-update mechanism verifies the signature using Windows APIs before executing any update.
- A SHA-256 manifest of all agent files is published to a tamper-evident log (hash tree) after each build.

### 8.3 Exclusions and Coexistence

The agent binary and data directory should be excluded from Microsoft Defender AV scanning (not real-time protection — just the on-access scanner for those specific paths) to prevent performance conflicts. This is **not** a security bypass — Defender still monitors behavior. The exclusion prevents Defender from repeatedly scanning the agent's own telemetry queue files.
- Add exclusion path: `%ProgramData%\ThreatHuntAgent`
- Add exclusion process: `ThreatHuntAgent.exe`

Add these exclusions via GPO (Defender exclusions policy) to ensure they are centrally managed and auditable.

### 8.4 Network Requirements

| Direction | Protocol/Port | Destination | Purpose |
|---|---|---|---|
| Outbound from endpoint | HTTPS / TCP 443 | Central server FQDN | Telemetry transmission |
| Inbound to server | HTTPS / TCP 443 | Server NIC | Receive agent telemetry |
| Server outbound | HTTPS / TCP 443 | TI feed APIs | Threat intelligence enrichment |
| Analyst inbound | HTTPS / TCP 443 | Dashboard server | Web UI access |

---

## 9. Prototype Go Code — Endpoint Agent

The following Go code demonstrates a minimal but realistic endpoint agent. Every section includes comments explaining what it does, why it exists, and what security decisions are being made. The code is intentionally readable over clever.

Go is chosen because it compiles to a single static binary (easy deployment), has excellent Windows API support, low memory footprint, and produces code that is easy to audit.

### 9.1 Main Entry Point: `main.go`

```go
// main.go — Threat Hunt Agent Entry Point
package main

import (
    "log"
    "os"

    "golang.org/x/sys/windows/svc"
)

func main() {
    isService, err := svc.IsWindowsService()
    if err != nil {
        log.Fatalf("Failed to determine service mode: %v", err)
    }

    if isService {
        if err := svc.Run("ThreatHuntAgent", &agentService{}); err != nil {
            log.Fatalf("Service failed: %v", err)
        }
    } else {
        log.Println("Running in interactive debug mode. Press Ctrl+C to stop.")
        runAgent(os.Exit)
    }
}
```

### 9.2 Event Log Reader: `reader.go`

```go
// reader.go — Windows Event Log Reader
package main

import (
    "time"

    winevt "github.com/0xrawsec/golang-evtx/evtx"
)

type LogSubscription struct {
    Channel string
    Query   string
}

var subscriptions = []LogSubscription{
    {Channel: "Security", Query: `*[System/EventID=4688 or System/EventID=4624 or System/EventID=4625 or System/EventID=4648 or System/EventID=4698 or System/EventID=4699 or System/EventID=1102]`},
    {Channel: "System", Query: `*[System/EventID=7045 or System/EventID=7040]`},
    {Channel: "Microsoft-Windows-PowerShell/Operational", Query: `*[System/EventID=4104 or System/EventID=4103]`},
    {Channel: "Microsoft-Windows-Windows Defender/Operational", Query: `*[System/EventID=5001 or System/EventID=5004 or System/EventID=1116 or System/EventID=1117]`},
}

func (r *EventReader) readChannel(sub LogSubscription) {
    handle, err := winevt.SubscribeChannel(sub.Channel, sub.Query)
    if err != nil {
        logErr("Failed to subscribe to channel %s: %v", sub.Channel, err)
        return
    }
    defer winevt.Close(handle)

    for {
        select {
        case <-r.stopChan:
            return
        default:
            events, err := winevt.FetchEvents(handle, 50)
            if err != nil {
                if isNoMoreItems(err) {
                    time.Sleep(2 * time.Second)
                    continue
                }
                logErr("Error reading from %s: %v", sub.Channel, err)
                continue
            }
            _ = events
        }
    }
}
```

### 9.3 Event Filter & Local Scorer: `scorer.go`

```go
// scorer.go — Local event filtering and preliminary risk scoring
package main

import (
    "path/filepath"
    "strings"
)

func ScoreEvent(raw RawEvent) *ScoredEvent {
    se := &ScoredEvent{Raw: raw, LocalScore: 10}
    switch raw.EventID {
    case 4688:
        se = score4688(raw)
    case 4625:
        se.LocalScore = 15
    case 4698:
        se.LocalScore = 40
    case 1102:
        se.LocalScore = 80
    case 5001, 5004:
        se.LocalScore = 75
    }
    if se.LocalScore < 15 {
        return nil
    }
    return se
}
```

### 9.4 Transmitter: `transmitter.go`

```go
// transmitter.go — Secure HTTPS telemetry transmission
package main

import (
    "crypto/tls"
    "net/http"
    "time"
)

func NewTransmitter(cfg TransmitterConfig) *Transmitter {
    tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
    transport := &http.Transport{
        TLSClientConfig:    tlsConfig,
        MaxIdleConns:       2,
        IdleConnTimeout:    90 * time.Second,
        DisableCompression: false,
    }

    return &Transmitter{
        cfg:    cfg,
        client: &http.Client{Transport: transport, Timeout: 30 * time.Second},
        queue:  make([]ScoredEvent, 0, cfg.BatchSize),
    }
}
```

---

## 10. Central Server Design

The central server is responsible for all intelligence. The endpoint agent is intentionally kept simple and dumb — the server is where complexity lives, and where it is easier to update, scale, and audit.

### 10.1 Recommended Stack

| Component | Technology | Rationale |
|---|---|---|
| Ingest API | Go or Python (FastAPI) | Handles validation, auth, schema enforcement at wire speed |
| Event Store | Elasticsearch or OpenSearch | Excellent for time-series security event queries; SIEM-compatible |
| Correlation Engine | Python (pandas/numpy) or Go | Sliding-window joins; Bayesian scoring is CPU-light |
| TI Cache | Redis | Fast TTL-aware cache for hash/IP/domain lookups |
| Dashboard | Grafana + Kibana, or custom React | Grafana has native Elasticsearch support; Kibana for ad-hoc queries |
| Auth | NGINX reverse proxy + mTLS or JWT | Terminate TLS at proxy; internal services on internal network only |

### 10.2 Ingest API Validation

The ingest endpoint validates every submission before it touches the database:
1. Authenticate the request (API key or client certificate).
2. Validate JSON schema — reject any event with unknown fields or wrong types.
3. Rate-limit per agent ID (e.g., max 1000 events/minute per agent).
4. Deduplicate using `batch_id` — idempotent re-sends are safe.
5. Strip any fields not in the schema — defense against schema injection.
6. Write to event store — only after all validation passes.

### 10.3 Dashboard Metrics

- Endpoint Risk Score: Rolling 24h Bayesian posterior probability, 0-100 display.
- TTP Heatmap: MITRE ATT&CK matrix heatmap showing technique frequency across the fleet.
- Behavioral Chain Timeline: Visual timeline of correlated event chains per endpoint.
- Alert Queue: Sorted by composite score; analyst can Accept, Dismiss, or Escalate.
- Feedback Integration: Each alert disposition feeds back into the scoring model.

---

## 11. Operational Security Considerations

### 11.1 Protecting the Agent Itself

- Tamper protection: The agent service is protected by Windows Service Control Manager. Stopping or modifying it generates Event 7036 (Service state changed), which the agent itself would log before shutdown — creating a tamper trail.
- The agent monitors for its own Defender exclusion being removed (if removed, it cannot receive Defender events — but it will still operate and log other event types).
- If the security event log is cleared (Event 1102), the agent will have already shipped this event before any follow-on activity occurs.

### 11.2 Evasion Resistance

An attacker aware of this system might attempt to evade detection. The design addresses this:
- Name spoofing (renaming malware as `svchost.exe`): Scored on full path, not name alone. `svchost.exe` outside `System32` is flagged.
- Defender kill: The Defender tamper event fires before protection is fully disabled, and the agent ships it immediately with priority handling.
- Event log clearing: Event 1102 fires as the log is cleared — the agent will have already seen and shipped prior events.
- Network blocking: The local queue buffers up to MaxQueueSize events. The agent retries with exponential backoff. An attacker cannot permanently silence it by temporarily blocking the network.
- Agent kill: Killing the agent service generates Event 7036. The central server notices the endpoint goes silent and can alert on "agent heartbeat missing" (if heartbeat telemetry is implemented).

### 11.3 Privacy and Data Minimization

- Command lines may contain passwords or sensitive arguments. The schema allows truncation at 512 characters for command lines. This captures most malicious patterns while limiting sensitive data exposure.
- PowerShell script block content (Event 4104) can be very large and sensitive. The agent ships only the first 512 characters plus a SHA-256 hash of the full content. Analysts can request the full content from the endpoint directly if needed.
- User account names are collected (needed for lateral movement detection) but `endpoint_id` uses a hashed identifier, not raw hostname, to slightly pseudonymize the source in the telemetry stream.
- Data retention policy should be defined: recommend 90 days hot storage, 1 year cold archive, with PII fields eligible for earlier deletion under privacy policies.

---

## 12. Quick Reference — Security Decisions Summary

| Decision | What We Chose | What We Rejected & Why |
|---|---|---|
| Log reading mechanism | Windows EvtQuery API (documented, supported) | Raw log file parsing — fragile, bypasses access control |
| Process inspection | Event 4688 (log-based) | OpenProcess + ReadProcessMemory — malware behavior |
| Service account privileges | Event Log Readers group only | Local Admin — excessive, violates least privilege |
| Secrets storage | Windows DPAPI | Plaintext config file — trivially extracted |
| TLS | TLS 1.2+ mandatory, cert pinning | InsecureSkipVerify — MITM vulnerable |
| Scoring model | Bayesian posterior with analyst feedback | Signature-only — bypassed by trivial modification |
| PowerShell script content | First 512 chars + SHA-256 hash | Full content — data volume, PII risk |
| Queue overflow policy | Drop oldest events (bounded queue) | Unbounded growth — DoS via disk exhaustion |
| Binary integrity | EV code signing, signed MSI | Unsigned binary — easily replaced/modified |

---

**End of Document — Threat Hunt Agent Architecture v1.0**
