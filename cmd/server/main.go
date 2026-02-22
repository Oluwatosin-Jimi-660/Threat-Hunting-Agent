package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sync"

	"threat-hunting-agent/internal/schema"
	"threat-hunting-agent/internal/server"
)

type ingestStore struct {
	mu      sync.Mutex
	batches map[string]struct{}
}

func main() {
	eng := server.NewEngine()
	keys := map[string]struct{}{env("THREAT_API_KEY", "dev-key"): {}}
	store := &ingestStore{batches: map[string]struct{}{}}

	http.HandleFunc("/ingest/v1", func(w http.ResponseWriter, r *http.Request) {
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
		if env.SchemaVersion != "1.0" || len(env.Events) == 0 || len(env.Events) > 100 {
			http.Error(w, `{"error":"invalid schema envelope"}`, http.StatusBadRequest)
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
		eng.Ingest(env)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"accepted"}`))
	})

	http.HandleFunc("/api/chains", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(eng.Chains())
	})
	http.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(dashboardHTML))
	})
	_ = http.ListenAndServe(":8443", nil)
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

const dashboardHTML = `<!doctype html><html><body><h1>Threat Hunting AI Agent Dashboard</h1><p>Use <code>/api/chains</code> for ATT&CK-mapped correlated chains.</p></body></html>`
