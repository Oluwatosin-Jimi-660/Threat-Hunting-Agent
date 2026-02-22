package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"time"

	"threat-hunting-agent/internal/schema"
	"threat-hunting-agent/internal/util"
)

type Reader struct{}

func (r *Reader) Stream(ctx context.Context, out chan<- schema.Event) error {
	if runtime.GOOS != "windows" {
		return r.streamSynthetic(ctx, out)
	}
	ticker := time.NewTicker(8 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			events, err := fetchWindowsEvents()
			if err != nil {
				continue
			}
			for _, evt := range events {
				out <- evt
			}
		}
	}
}

func (r *Reader) streamSynthetic(ctx context.Context, out chan<- schema.Event) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case t := <-ticker.C:
			out <- schema.Event{EventID: util.NewID(), WindowsEventID: 4688, LogChannel: "Security", RecordedAt: t.UTC().Format(time.RFC3339Nano), Data: map[string]string{"process_name": "powershell.exe", "command_line": "powershell -enc SQBtAG...", "parent_process": "winword.exe"}}
		}
	}
}

func fetchWindowsEvents() ([]schema.Event, error) {
	query := "Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688,4624,4625,4648,4698,4699,4657,1102,4660,4663} -MaxEvents 20 | Select-Object Id,TimeCreated,LogName,Message | ConvertTo-Json -Depth 4"
	b, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", query).Output()
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	var raw []struct {
		ID          int       `json:"Id"`
		TimeCreated time.Time `json:"TimeCreated"`
		LogName     string    `json:"LogName"`
		Message     string    `json:"Message"`
	}
	if len(b) == 0 {
		return nil, nil
	}
	if b[0] == '{' {
		var one struct {
			ID          int       `json:"Id"`
			TimeCreated time.Time `json:"TimeCreated"`
			LogName     string    `json:"LogName"`
			Message     string    `json:"Message"`
		}
		if err := json.Unmarshal(b, &one); err == nil {
			raw = append(raw, one)
		}
	} else if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	out := make([]schema.Event, 0, len(raw))
	for _, r := range raw {
		out = append(out, schema.Event{EventID: util.NewID(), WindowsEventID: r.ID, LogChannel: r.LogName, RecordedAt: r.TimeCreated.UTC().Format(time.RFC3339Nano), Data: map[string]string{"message": r.Message}})
	}
	return out, nil
}
