package server

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"threat-hunting-agent/internal/schema"
)

type likelihood struct{ PC, PnC float64 }

var likelihoods = map[string]likelihood{
	"powershell_encoded":      {0.85, 0.02},
	"defender_disabled":       {0.70, 0.005},
	"log_cleared":             {0.60, 0.001},
	"new_service_from_temp":   {0.75, 0.01},
	"office_spawns_shell":     {0.90, 0.003},
	"scheduled_task_at_logon": {0.50, 0.05},
	"lateral_move_logon":      {0.65, 0.02},
}

type Engine struct {
	mu                 sync.Mutex
	eventsByEndpoint   map[string][]schema.Event
	posterior          map[string]float64
	progressByEndpoint map[string]endpointProgress
	chainsByEndpoint   map[string][]schema.CorrelatedChain
	chains             []schema.CorrelatedChain
}

type DashboardOverview struct {
	TotalEndpoints     int                    `json:"total_endpoints"`
	TotalEvents        int                    `json:"total_events"`
	TotalChains        int                    `json:"total_chains"`
	HighRiskEndpoints  int                    `json:"high_risk_endpoints"`
	AttackTechniqueMap map[string]int         `json:"attack_technique_map"`
	EndpointScores     []EndpointRiskSnapshot `json:"endpoint_scores"`
}

type EndpointRiskSnapshot struct {
	EndpointID string  `json:"endpoint_id"`
	Score      int     `json:"score"`
	Posterior  float64 `json:"posterior"`
	Events     int     `json:"events"`
}

type endpointProgress struct {
	LastProcessedIndex int
	LastProcessedAt    string
}

func NewEngine() *Engine {
	return &Engine{
		eventsByEndpoint:   map[string][]schema.Event{},
		posterior:          map[string]float64{},
		progressByEndpoint: map[string]endpointProgress{},
		chainsByEndpoint:   map[string][]schema.CorrelatedChain{},
	}
}

func (e *Engine) Ingest(env schema.TelemetryEnvelope) {
	e.mu.Lock()
	defer e.mu.Unlock()
	p := e.posterior[env.Envelope.EndpointID]
	if p == 0 {
		p = 0.001
	}
	for _, evt := range env.Events {
		e.eventsByEndpoint[env.Envelope.EndpointID] = append(e.eventsByEndpoint[env.Envelope.EndpointID], evt)
		for _, pat := range patterns(evt) {
			lh := likelihoods[pat]
			p = (lh.PC * p) / ((lh.PC * p) + (lh.PnC * (1 - p)))
		}
	}
	e.posterior[env.Envelope.EndpointID] = p
	e.buildChains(env.Envelope.EndpointID)
}

func patterns(evt schema.Event) []string {
	out := []string{}
	msg := strings.ToLower(evt.Data["command_line"] + " " + strings.Join(evt.ScoreReasons, " "))
	if strings.Contains(msg, "encoded") || strings.Contains(msg, "-enc") {
		out = append(out, "powershell_encoded")
	}
	if evt.WindowsEventID == 5001 || evt.WindowsEventID == 5004 {
		out = append(out, "defender_disabled")
	}
	if evt.WindowsEventID == 1102 {
		out = append(out, "log_cleared")
	}
	if evt.WindowsEventID == 7045 && strings.Contains(strings.ToLower(evt.Data["service_path"]), "temp") {
		out = append(out, "new_service_from_temp")
	}
	if strings.Contains(msg, "office spawned shell") {
		out = append(out, "office_spawns_shell")
	}
	return out
}

func (e *Engine) buildChains(endpoint string) {
	events := e.eventsByEndpoint[endpoint]
	if len(events) == 0 {
		return
	}
	sort.Slice(events, func(i, j int) bool { return events[i].RecordedAt < events[j].RecordedAt })
	e.eventsByEndpoint[endpoint] = events

	progress := e.progressByEndpoint[endpoint]
	if progress.LastProcessedIndex >= len(events) {
		return
	}

	startIdx := progress.LastProcessedIndex
	if startIdx < 0 {
		startIdx = 0
	}
	if startIdx > len(events) {
		startIdx = len(events)
	}

	window := 15 * time.Minute
	chains := append([]schema.CorrelatedChain{}, e.chainsByEndpoint[endpoint]...)
	for _, evt := range events[startIdx:] {
		t, _ := time.Parse(time.RFC3339Nano, evt.RecordedAt)
		if len(chains) == 0 {
			chains = append(chains, e.correlatedChain(endpoint, []schema.Event{evt}))
			continue
		}

		lastChain := chains[len(chains)-1]
		if t.Sub(lastChain.Start) <= window {
			updatedEvents := append(append([]schema.Event{}, lastChain.Events...), evt)
			chains[len(chains)-1] = e.correlatedChain(endpoint, updatedEvents)
		} else {
			chains = append(chains, e.correlatedChain(endpoint, []schema.Event{evt}))
		}
	}

	e.chainsByEndpoint[endpoint] = chains
	e.progressByEndpoint[endpoint] = endpointProgress{
		LastProcessedIndex: len(events),
		LastProcessedAt:    events[len(events)-1].RecordedAt,
	}
	e.refreshGlobalChains()
}

func (e *Engine) correlatedChain(endpoint string, events []schema.Event) schema.CorrelatedChain {
	score := 0
	for _, ev := range events {
		score += ev.LocalScore
	}
	if score > 100 {
		score = 100
	}
	maps := mapATTACK(events)
	start, _ := time.Parse(time.RFC3339Nano, events[0].RecordedAt)
	end, _ := time.Parse(time.RFC3339Nano, events[len(events)-1].RecordedAt)
	return schema.CorrelatedChain{EndpointID: endpoint, Start: start, End: end, CompositeScore: score, Posterior: e.posterior[endpoint], Pattern: chainPattern(events), ATTACKTechniques: maps, Events: events}
}

func (e *Engine) refreshGlobalChains() {
	allChains := make([]schema.CorrelatedChain, 0)
	for _, endpointChains := range e.chainsByEndpoint {
		allChains = append(allChains, endpointChains...)
	}
	sort.Slice(allChains, func(i, j int) bool {
		if allChains[i].Start.Equal(allChains[j].Start) {
			return allChains[i].End.Before(allChains[j].End)
		}
		return allChains[i].Start.Before(allChains[j].Start)
	})
	e.chains = allChains
	if len(e.chains) > 5000 {
		e.chains = e.chains[len(e.chains)-5000:]
	}
}

func chainPattern(events []schema.Event) string {
	ids := make([]string, 0, len(events))
	for _, e := range events {
		ids = append(ids, strings.TrimSpace(strings.ToLower(e.LogChannel))+":"+strconv.Itoa(e.WindowsEventID))
	}
	return strings.Join(ids, " -> ")
}

func mapATTACK(events []schema.Event) []schema.ATTACKMap {
	seen := map[string]schema.ATTACKMap{}
	for _, evt := range events {
		switch evt.WindowsEventID {
		case 4688, 4103, 4104:
			seen["T1059.001"] = schema.ATTACKMap{TechniqueID: "T1059.001", TechniqueName: "PowerShell", TacticID: "TA0002", TacticName: "Execution", Confidence: 0.9}
		case 4698, 4699:
			seen["T1053.005"] = schema.ATTACKMap{TechniqueID: "T1053.005", TechniqueName: "Scheduled Task", TacticID: "TA0003", TacticName: "Persistence", Confidence: 0.8}
		case 7045, 7040:
			seen["T1543.003"] = schema.ATTACKMap{TechniqueID: "T1543.003", TechniqueName: "Windows Service", TacticID: "TA0003", TacticName: "Persistence", Confidence: 0.85}
		case 1102:
			seen["T1070.001"] = schema.ATTACKMap{TechniqueID: "T1070.001", TechniqueName: "Clear Windows Event Logs", TacticID: "TA0005", TacticName: "Defense Evasion", Confidence: 0.95}
		}
	}
	out := make([]schema.ATTACKMap, 0, len(seen))
	for _, m := range seen {
		out = append(out, m)
	}
	return out
}

func (e *Engine) Chains() []schema.CorrelatedChain {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]schema.CorrelatedChain{}, e.chains...)
}
func (e *Engine) EndpointScore(endpoint string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return int(math.Round(e.posterior[endpoint] * 100))
}

func (e *Engine) Overview() DashboardOverview {
	e.mu.Lock()
	defer e.mu.Unlock()

	overview := DashboardOverview{
		TotalEndpoints:     len(e.eventsByEndpoint),
		TotalChains:        len(e.chains),
		AttackTechniqueMap: map[string]int{},
		EndpointScores:     make([]EndpointRiskSnapshot, 0, len(e.eventsByEndpoint)),
	}

	for endpoint, events := range e.eventsByEndpoint {
		overview.TotalEvents += len(events)
		posterior := e.posterior[endpoint]
		score := int(math.Round(posterior * 100))
		if score >= 70 {
			overview.HighRiskEndpoints++
		}
		overview.EndpointScores = append(overview.EndpointScores, EndpointRiskSnapshot{
			EndpointID: endpoint,
			Score:      score,
			Posterior:  posterior,
			Events:     len(events),
		})
	}

	for _, chain := range e.chains {
		for _, attack := range chain.ATTACKTechniques {
			overview.AttackTechniqueMap[attack.TechniqueID+" "+attack.TechniqueName]++
		}
	}

	sort.Slice(overview.EndpointScores, func(i, j int) bool {
		if overview.EndpointScores[i].Score == overview.EndpointScores[j].Score {
			return overview.EndpointScores[i].EndpointID < overview.EndpointScores[j].EndpointID
		}
		return overview.EndpointScores[i].Score > overview.EndpointScores[j].Score
	})

	return overview
}
