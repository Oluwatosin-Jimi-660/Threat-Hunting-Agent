package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"time"

	"threat-hunting-agent/internal/schema"
	"threat-hunting-agent/internal/util"
)

const TamperEventID = 900001

// MonitorTamper watches critical files for unexpected changes and emits a tamper event.
func MonitorTamper(ctx context.Context, path string, out chan<- schema.Event) {
	if strings.TrimSpace(path) == "" {
		return
	}
	baseline := fileHash(path)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := fileHash(path)
			if current == "" || baseline == "" {
				continue
			}
			if current != baseline {
				out <- schema.Event{
					EventID:        util.NewID(),
					WindowsEventID: TamperEventID,
					LogChannel:     "AgentTamper",
					RecordedAt:     time.Now().UTC().Format(time.RFC3339Nano),
					Data: map[string]string{
						"tamper_type": "config_modified",
						"path":        path,
					},
				}
				baseline = current
			}
		}
	}
}

func fileHash(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
