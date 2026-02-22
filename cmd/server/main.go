package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"threat-hunting-agent/internal/schema"
	"threat-hunting-agent/internal/server"
)

type ingestStore struct {
	mu      sync.Mutex
	batches map[string]struct{}
}

func main() {
	eng := server.NewEngine()
	ruleManager, err := server.NewRuleManager(env("THREAT_RULE_FILE", "config/hunt-rules.json"), env("THREAT_RULE_AUDIT_LOG", "logs/rule_audit.log"))
	if err != nil {
		log.Fatalf("unable to load rules: %v", err)
	}
	findings := server.NewFindingsStore()
	keys := map[string]struct{}{requiredSecret("THREAT_API_KEY"): {}}
	adminKeys := map[string]struct{}{requiredSecret("THREAT_ADMIN_KEY"): {}}
	store := &ingestStore{batches: map[string]struct{}{}}

	http.HandleFunc("/ingest/v1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		auth := r.Header.Get("Authorization")
		if len(auth) < 8 || auth[:7] != "Bearer " {
			http.Error(w, `{"error":"missing bearer"}`, http.StatusUnauthorized)
			return
		}
		if _, ok := keys[auth[7:]]; !ok {
			http.Error(w, `{"error":"bad key"}`, http.StatusUnauthorized)
			return
		}

		b, _ := io.ReadAll(r.Body)
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		var env schema.TelemetryEnvelope
		if err := dec.Decode(&env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := server.ValidateTelemetryEnvelope(env); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		store.mu.Lock()
		if _, ok := store.batches[env.Envelope.BatchID]; ok {
			store.mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"status":"duplicate"}`))
			return
		}
		store.batches[env.Envelope.BatchID] = struct{}{}
		store.mu.Unlock()
		for _, evt := range env.Events {
			matches := server.EvaluateRules(evt, ruleManager.Rules())
			for _, match := range matches {
				findings.Add(server.Finding{
					Timestamp:    time.Now().UTC().Format(time.RFC3339Nano),
					EndpointID:   env.Envelope.EndpointID,
					RuleID:       match.Rule.RuleID,
					MatchedEvent: evt,
					RiskScore:    match.Rule.RiskWeight,
					Explanation:  "Matched because: " + strings.Join(match.Reasons, "; "),
					MITRE:        match.Rule.MITRETechnique,
				})
			}
		}
		eng.Ingest(env)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"accepted"}`))
	})

	http.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"rules": ruleManager.Rules()})
		case http.MethodPost, http.MethodPut:
			auth := r.Header.Get("Authorization")
			if len(auth) < 8 || auth[:7] != "Bearer " {
				http.Error(w, `{"error":"missing bearer"}`, http.StatusUnauthorized)
				return
			}
			if _, ok := adminKeys[auth[7:]]; !ok {
				http.Error(w, `{"error":"admin key required"}`, http.StatusUnauthorized)
				return
			}
			var rule server.HuntRule
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			if err := dec.Decode(&rule); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := ruleManager.UpsertRule(rule, "api_admin"); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"status":"rule_saved"}`))
		default:
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/api/rules/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		auth := r.Header.Get("Authorization")
		if len(auth) < 8 || auth[:7] != "Bearer " {
			http.Error(w, `{"error":"missing bearer"}`, http.StatusUnauthorized)
			return
		}
		if _, ok := adminKeys[auth[7:]]; !ok {
			http.Error(w, `{"error":"admin key required"}`, http.StatusUnauthorized)
			return
		}
		if err := ruleManager.Load(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"status":"reloaded"}`))
	})

	http.HandleFunc("/api/findings", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		endpointID := q.Get("endpoint_id")
		ruleID := q.Get("rule_id")
		start, _ := time.Parse(time.RFC3339, q.Get("start"))
		end, _ := time.Parse(time.RFC3339, q.Get("end"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"findings": findings.Query(endpointID, ruleID, start, end)})
	})

	http.HandleFunc("/api/findings/risk-distribution", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(findings.RiskDistribution())
	})

	http.HandleFunc("/api/chains", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(eng.Chains())
	})
	http.HandleFunc("/api/overview", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(eng.Overview())
	})
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	http.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(dashboardHTML))
	})
	cert := os.Getenv("TLS_CERT_FILE")
	key := os.Getenv("TLS_KEY_FILE")
	if cert != "" && key != "" {
		log.Fatal(http.ListenAndServeTLS(":8443", cert, key, nil))
	}
	log.Println("WARNING: TLS_CERT_FILE/TLS_KEY_FILE not set, running HTTP for local development only")
	log.Fatal(http.ListenAndServe(":8443", nil))
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func requiredSecret(name string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	generated := hex.EncodeToString(b)
	fmt.Printf("%s was not set; generated ephemeral secret for this process: %s\n", name, generated)
	return generated
}

const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Threat Hunting AI Agent Dashboard</title>
  <style>
    :root { color-scheme: dark; }
    body { font-family: Arial, sans-serif; background:#0f172a; color:#e2e8f0; margin:0; }
    .container { max-width:1100px; margin:0 auto; padding:24px; }
    .grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap:12px; margin-bottom:20px; }
    .card { background:#1e293b; border-radius:10px; padding:14px; box-shadow:0 1px 2px rgba(0,0,0,.4); }
    h1, h2 { margin:0 0 12px; }
    h1 { margin-bottom:16px; }
    .value { font-size:1.6rem; font-weight:bold; }
    table { width:100%; border-collapse: collapse; background:#1e293b; border-radius:10px; overflow:hidden; }
    th, td { text-align:left; padding:10px; border-bottom:1px solid #334155; font-size:0.92rem; }
    .risk-high { color:#f87171; font-weight:bold; }
    .risk-med { color:#fbbf24; font-weight:bold; }
    .risk-low { color:#4ade80; font-weight:bold; }
    .row { display:grid; grid-template-columns:2fr 3fr; gap:14px; margin-bottom:16px; }
    canvas { width:100%; background:#1e293b; border-radius:10px; padding:10px; box-sizing:border-box; }
    .meta { color:#94a3b8; font-size:0.85rem; margin-top:8px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Threat Hunting Monitoring Dashboard</h1>
    <div class="grid" id="summary"></div>
    <div class="row">
      <canvas id="techniquesChart" height="220"></canvas>
      <canvas id="endpointChart" height="220"></canvas>
    </div>
    <h2>Latest Correlated Chains</h2>
    <table>
      <thead><tr><th>Endpoint</th><th>Window</th><th>Score</th><th>Posterior</th><th>Pattern</th></tr></thead>
      <tbody id="chains"></tbody>
    </table>
    <p class="meta">Data source: <code>/api/overview</code>, <code>/api/chains</code>. Refreshes every 10 seconds.</p>
  </div>
  <script>
    function riskClass(score){ return score >= 70 ? 'risk-high' : (score >= 40 ? 'risk-med' : 'risk-low'); }

    function drawBars(canvasId, labels, values, color) {
      const canvas = document.getElementById(canvasId);
      const ctx = canvas.getContext('2d');
      const w = canvas.width = canvas.clientWidth;
      const h = canvas.height;
      ctx.clearRect(0, 0, w, h);

      if (!labels.length) {
        ctx.fillStyle = '#94a3b8';
        ctx.fillText('No data yet', 20, 40);
        return;
      }

      const max = Math.max(...values, 1);
      const barH = Math.max(18, Math.floor((h - 30) / labels.length) - 6);
      labels.forEach((label, i) => {
        const y = 20 + i * (barH + 6);
        const barW = Math.floor((values[i] / max) * (w - 260));
        ctx.fillStyle = '#cbd5e1';
        ctx.fillText(label.slice(0, 32), 12, y + barH - 5);
        ctx.fillStyle = color;
        ctx.fillRect(220, y, barW, barH);
        ctx.fillStyle = '#e2e8f0';
        ctx.fillText(String(values[i]), 228 + barW, y + barH - 5);
      });
    }

    async function load() {
      const [overviewRes, chainsRes] = await Promise.all([fetch('/api/overview'), fetch('/api/chains')]);
      const overview = await overviewRes.json();
      const chains = await chainsRes.json();

      const summary = document.getElementById('summary');
      summary.innerHTML = [
        ['Total Endpoints', overview.total_endpoints],
        ['Total Events', overview.total_events],
        ['Correlated Chains', overview.total_chains],
        ['High Risk Endpoints', overview.high_risk_endpoints]
      ].map(([k,v]) => '<div class="card"><div>'+k+'</div><div class="value">'+v+'</div></div>').join('');

      const techniqueEntries = Object.entries(overview.attack_technique_map || {}).sort((a,b)=>b[1]-a[1]).slice(0,6);
      drawBars('techniquesChart', techniqueEntries.map(([k])=>k), techniqueEntries.map(([,v])=>v), '#38bdf8');

      const endpointEntries = (overview.endpoint_scores || []).slice(0,6);
      drawBars('endpointChart', endpointEntries.map(e=>e.endpoint_id), endpointEntries.map(e=>e.score), '#fb7185');

      document.getElementById('chains').innerHTML = (chains || []).slice(-10).reverse().map(c => {
        const score = Math.round((c.posterior || 0) * 100);
        return '<tr>' +
          '<td>'+c.endpoint_id+'</td>' +
          '<td>'+new Date(c.start).toLocaleTimeString()+' - '+new Date(c.end).toLocaleTimeString()+'</td>' +
          '<td class="'+riskClass(c.composite_score)+'">'+c.composite_score+'</td>' +
          '<td class="'+riskClass(score)+'">'+score+'%</td>' +
          '<td>'+c.pattern+'</td>' +
        '</tr>';
      }).join('');
    }

    load();
    setInterval(load, 10000);
  </script>
</body>
</html>`
