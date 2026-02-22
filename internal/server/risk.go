package server

import (
	"math"
	"sync"
	"time"
)

type RiskUpdate struct {
	RuleID      string  `json:"rule_id"`
	LikelihoodC float64 `json:"likelihood_compromised"`
	LikelihoodN float64 `json:"likelihood_clean"`
	Reason      string  `json:"reason"`
	Time        string  `json:"time"`
}

type endpointRiskState struct {
	Posterior      float64
	LastUpdated    time.Time
	UpdateTrail    []RiskUpdate
	Prior          float64
	DecayHalfLifeM float64
}

type RiskModel struct {
	mu           sync.Mutex
	states       map[string]endpointRiskState
	defaultPrior float64
	halfLife     time.Duration
}

func NewRiskModel(prior float64, halfLife time.Duration) *RiskModel {
	return &RiskModel{states: map[string]endpointRiskState{}, defaultPrior: prior, halfLife: halfLife}
}

func (r *RiskModel) Apply(endpointID string, update RiskUpdate, now time.Time) float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.states[endpointID]
	if s.Posterior == 0 {
		s.Posterior = r.defaultPrior
		s.Prior = r.defaultPrior
		s.DecayHalfLifeM = r.halfLife.Minutes()
		s.LastUpdated = now
	}
	s.Posterior = decayProbability(s.Posterior, s.Prior, now.Sub(s.LastUpdated), r.halfLife)
	denominator := (update.LikelihoodC * s.Posterior) + (update.LikelihoodN * (1 - s.Posterior))
	if denominator > 0 {
		s.Posterior = (update.LikelihoodC * s.Posterior) / denominator
	}
	s.LastUpdated = now
	update.Time = now.UTC().Format(time.RFC3339Nano)
	s.UpdateTrail = append(s.UpdateTrail, update)
	if len(s.UpdateTrail) > 200 {
		s.UpdateTrail = s.UpdateTrail[len(s.UpdateTrail)-200:]
	}
	r.states[endpointID] = s
	return s.Posterior
}

func (r *RiskModel) Score(endpointID string, now time.Time) (float64, []RiskUpdate) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.states[endpointID]
	if s.Posterior == 0 {
		return r.defaultPrior, nil
	}
	s.Posterior = decayProbability(s.Posterior, s.Prior, now.Sub(s.LastUpdated), r.halfLife)
	s.LastUpdated = now
	r.states[endpointID] = s
	return s.Posterior, append([]RiskUpdate{}, s.UpdateTrail...)
}

func decayProbability(current, prior float64, elapsed, halfLife time.Duration) float64 {
	if elapsed <= 0 || halfLife <= 0 {
		return current
	}
	lambda := math.Ln2 / halfLife.Hours()
	weight := math.Exp(-lambda * elapsed.Hours())
	return prior + (current-prior)*weight
}
