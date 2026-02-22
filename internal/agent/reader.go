package agent

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
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
	query := "Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688,4624,4625,4648,4698,4699,4657,1102,4660,4663} -MaxEvents 20 | Select-Object Id,TimeCreated,LogName,Message,@{Name='Xml';Expression={$_.ToXml()}} | ConvertTo-Json -Depth 6"
	b, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", query).Output()
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	var raw []struct {
		ID          int       `json:"Id"`
		TimeCreated time.Time `json:"TimeCreated"`
		LogName     string    `json:"LogName"`
		Message     string    `json:"Message"`
		XML         string    `json:"Xml"`
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
			XML         string    `json:"Xml"`
		}
		if err := json.Unmarshal(b, &one); err == nil {
			raw = append(raw, one)
		}
	} else if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	out := make([]schema.Event, 0, len(raw))
	for _, r := range raw {
		data := map[string]string{"message": r.Message}
		for k, v := range extractEventDataFromXML(r.XML) {
			if v != "" {
				data[k] = v
			}
		}
		normalizeEventData(r.ID, data)
		out = append(out, schema.Event{EventID: util.NewID(), WindowsEventID: r.ID, LogChannel: r.LogName, RecordedAt: r.TimeCreated.UTC().Format(time.RFC3339Nano), Data: data})
	}
	return out, nil
}

type eventXML struct {
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
	UserData struct {
		Inner string `xml:",innerxml"`
	} `xml:"UserData"`
}

func extractEventDataFromXML(raw string) map[string]string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var evt eventXML
	if err := xml.Unmarshal([]byte(raw), &evt); err != nil {
		return nil
	}
	out := make(map[string]string)
	for _, d := range evt.EventData.Data {
		name := strings.TrimSpace(d.Name)
		value := strings.TrimSpace(d.Value)
		if name != "" && value != "" {
			out[name] = value
		}
	}
	return out
}

func normalizeEventData(eventID int, data map[string]string) {
	setIfPresent := func(target string, aliases ...string) {
		for _, alias := range aliases {
			if v := strings.TrimSpace(data[alias]); v != "" {
				data[target] = v
				return
			}
		}
	}

	switch eventID {
	case 4688:
		setIfPresent("process_name", "NewProcessName", "ProcessName", "Image", "Application")
		setIfPresent("command_line", "ProcessCommandLine", "CommandLine")
		setIfPresent("parent_process", "ParentProcessName", "CreatorProcessName")
	case 4698, 4699:
		setIfPresent("task_name", "TaskName")
		setIfPresent("task_content", "TaskContent")
		setIfPresent("command_line", "TaskContent")
	case 7045:
		setIfPresent("service_name", "ServiceName")
		setIfPresent("service_path", "ImagePath", "ServiceFileName")
		setIfPresent("process_name", "ImagePath", "ServiceFileName")
	}
}
