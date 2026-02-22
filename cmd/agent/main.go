package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"
	"os/signal"
	"time"

	"threat-hunting-agent/internal/agent"
	"threat-hunting-agent/internal/schema"
	"threat-hunting-agent/internal/util"
)

func main() {
	host, _ := os.Hostname()
	h := sha256.Sum256([]byte(host))
	cfg := agent.Config{
		ServerURL:    env("THREAT_SERVER_URL", "http://localhost:8443/ingest/v1"),
		APIKey:       env("THREAT_API_KEY", "dev-key"),
		AgentID:      env("THREAT_AGENT_ID", util.NewID()),
		EndpointID:   hex.EncodeToString(h[:]),
		AgentVersion: "1.0.0",
		BatchSize:    100,
		FlushEvery:   15 * time.Second,
		MaxQueueSize: 10000,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	reader := &agent.Reader{}
	tx := agent.NewTransmitter(cfg)
	raw := make(chan schema.Event, 2048)

	go tx.Run(ctx)
	go func() {
		if err := reader.Stream(ctx, raw); err != nil {
			log.Printf("reader stopped: %v", err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			log.Println("agent stopped")
			return
		case evt := <-raw:
			sc := agent.ScoreEvent(evt)
			if sc != nil {
				tx.Enqueue(sc.Event)
			}
		}
	}
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
