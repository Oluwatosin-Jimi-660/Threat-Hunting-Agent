package agent

import (
	"path/filepath"
	"strings"

	"threat-hunting-agent/internal/schema"
)

const DropThreshold = 20

type ScoredEvent struct {
	Event   schema.Event
	Reasons []string
}

func ScoreEvent(evt schema.Event) *ScoredEvent {
	s := &ScoredEvent{Event: evt}
	s.Event.LocalScore = 10

	switch evt.WindowsEventID {
	case 4688:
		score4688(s)
	case 4698:
		s.Event.LocalScore = 40
		s.Reasons = append(s.Reasons, "scheduled task created")
	case 1102:
		s.Event.LocalScore = 80
		s.Reasons = append(s.Reasons, "security log cleared")
	case 5001, 5004:
		s.Event.LocalScore = 75
		s.Reasons = append(s.Reasons, "defender tamper")
	case 7045:
		s.Event.LocalScore = 45
		if pathLike(evt.Data["service_path"], []string{`\\`, `\\temp\\`, `\\appdata\\`}) {
			s.Event.LocalScore += 25
			s.Reasons = append(s.Reasons, "new service from suspicious path")
		}
	default:
		s.Event.LocalScore = 20
	}

	if s.Event.LocalScore < DropThreshold {
		return nil
	}
	s.Event.ScoreReasons = append([]string{}, s.Reasons...)
	return s
}

func score4688(s *ScoredEvent) {
	cmd := strings.ToLower(s.Event.Data["command_line"])
	proc := strings.ToLower(s.Event.Data["process_name"])
	parent := strings.ToLower(s.Event.Data["parent_process"])
	dir := filepath.ToSlash(filepath.Dir(proc))
	s.Event.LocalScore = 20

	if strings.Contains(cmd, "-enc") || strings.Contains(cmd, "-encodedcommand") {
		s.Event.LocalScore += 35
		s.Reasons = append(s.Reasons, "powershell encoded command")
	}
	if strings.Contains(cmd, "-nop") && strings.Contains(cmd, "hidden") {
		s.Event.LocalScore += 30
		s.Reasons = append(s.Reasons, "evasion flags")
	}
	if pathLike(parent, []string{"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}) &&
		pathLike(proc, []string{"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"}) {
		s.Event.LocalScore += 40
		s.Reasons = append(s.Reasons, "office spawned shell")
	}
	if strings.Contains(dir, "/temp") || strings.Contains(dir, "/downloads") || strings.Contains(dir, "/users/public") {
		s.Event.LocalScore += 25
		s.Reasons = append(s.Reasons, "execution from suspicious directory")
	}
	if proc == `c:\windows\system32\svchost.exe` {
		s.Event.LocalScore -= 20
	}
}

func pathLike(s string, list []string) bool {
	s = strings.ToLower(s)
	for _, x := range list {
		if strings.Contains(s, strings.ToLower(x)) {
			return true
		}
	}
	return false
}
