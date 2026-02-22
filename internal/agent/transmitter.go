package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"threat-hunting-agent/internal/schema"
	"threat-hunting-agent/internal/util"
)

type Config struct {
	ServerURL    string
	APIKey       string
	AgentID      string
	EndpointID   string
	AgentVersion string
	BatchSize    int
	FlushEvery   time.Duration
	MaxQueueSize int
}

type Transmitter struct {
	cfg    Config
	client *http.Client
	mu     sync.Mutex
	queue  []schema.Event
	seq    int64
}

func NewTransmitter(cfg Config) *Transmitter {
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	return &Transmitter{cfg: cfg, client: &http.Client{Timeout: 30 * time.Second, Transport: tr}}
}

func (t *Transmitter) Enqueue(evt schema.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.queue) >= t.cfg.MaxQueueSize {
		t.queue = t.queue[1:]
	}
	t.queue = append(t.queue, evt)
}

func (t *Transmitter) Run(ctx context.Context) {
	tick := time.NewTicker(t.cfg.FlushEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			t.flush()
			return
		case <-tick.C:
			t.flush()
		}
	}
}

func (t *Transmitter) flush() {
	t.mu.Lock()
	if len(t.queue) == 0 {
		t.mu.Unlock()
		return
	}
	n := t.cfg.BatchSize
	if len(t.queue) < n {
		n = len(t.queue)
	}
	batch := append([]schema.Event{}, t.queue[:n]...)
	t.queue = t.queue[n:]
	t.seq++
	seq := t.seq
	t.mu.Unlock()

	p := schema.TelemetryEnvelope{SchemaVersion: "1.0", Envelope: schema.EnvelopeMeta{AgentID: t.cfg.AgentID, EndpointID: t.cfg.EndpointID, SentAt: time.Now().UTC().Format(time.RFC3339Nano), AgentVersion: t.cfg.AgentVersion, BatchID: util.NewID(), SequenceNum: seq}, Events: batch}
	b, _ := json.Marshal(p)
	req, _ := http.NewRequest(http.MethodPost, t.cfg.ServerURL, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+t.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", t.cfg.AgentID)
	resp, err := t.client.Do(req)
	if err != nil || (resp != nil && resp.StatusCode >= 300) {
		t.mu.Lock()
		t.queue = append(batch, t.queue...)
		t.mu.Unlock()
	}
	if resp != nil {
		_ = resp.Body.Close()
	}
}
