// Package service contains the domain logic: zone import, plan validation,
// deterministic simulation orchestration, rollback bookkeeping and export.
// All authoritative decisions live here; the browser UI is only a client.
package service

import (
	"time"

	"zonesim/internal/dns"
	"zonesim/internal/sim"
)

// ZoneDoc is the raw imported zone plus its derived fingerprint.
type ZoneDoc struct {
	ID          string    `json:"id"`
	Label       string    `json:"label"`
	Origin      string    `json:"origin"`
	Text        string    `json:"text"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
	zone        *dns.Zone `json:"-"`
}

// ParsedZone returns the cached parsed zone.
func (z *ZoneDoc) ParsedZone() *dns.Zone { return z.zone }

// Plan states.
const (
	StateDraft      = "draft"
	StateReady      = "ready"
	StateCommitted  = "committed"
	StateRolledBack = "rolled_back"
)

// PhaseDecision records the validation/commit decision for one stage.
type PhaseDecision struct {
	PhaseName          string        `json:"phase_name"`
	EffectiveAtSeconds int           `json:"effective_at_seconds"`
	Keys               []string      `json:"keys"`
	Decision           string        `json:"decision"` // "accepted" | "blocked"
	Reasons            []dns.Finding `json:"reasons,omitempty"`
	DecidedAt          time.Time     `json:"decided_at"`
}

// Plan is a staged release plan.
type Plan struct {
	ID                   string          `json:"id"`
	CurrentZoneID        string          `json:"current_zone_id"`
	CandidateZoneID      string          `json:"candidate_zone_id"`
	CurrentFingerprint   string          `json:"current_fingerprint"`
	CandidateFingerprint string          `json:"candidate_fingerprint"`
	Phases               []sim.Phase     `json:"phases"`
	Changes              []dns.Change    `json:"changes"`
	Findings             []dns.Finding   `json:"findings"`
	Status               string          `json:"status"`
	Revision             int             `json:"revision"`
	BasePlanID           string          `json:"base_plan_id,omitempty"`
	Decisions            []PhaseDecision `json:"decisions,omitempty"`
	CommittedAt          *time.Time      `json:"committed_at,omitempty"`
	RolledBackAt         *time.Time      `json:"rolled_back_at,omitempty"`
	CreatedAt            time.Time       `json:"created_at"`
	UpdatedAt            time.Time       `json:"updated_at"`
}

// Blocked reports whether pre-publish blockers exist.
func (p *Plan) Blocked() bool {
	for _, f := range p.Findings {
		if f.Blocking() {
			return true
		}
	}
	return false
}

// SimulationDoc wraps the deterministic sim result with plan linkage.
type SimulationDoc = sim.Simulation

// ExportBundle is the full export artifact.
type ExportBundle struct {
	ExportedAt    time.Time      `json:"exported_at"`
	Plan          *Plan          `json:"plan"`
	CurrentZone   *ZoneDoc       `json:"current_zone"`
	CandidateZone *ZoneDoc       `json:"candidate_zone"`
	Simulation    *SimulationDoc `json:"simulation"`
	Events        []EventView    `json:"events"`
	AdHoc         []AdHocView    `json:"ad_hoc_queries,omitempty"`
}

type EventView struct {
	Seq       int       `json:"seq"`
	At        time.Time `json:"at"`
	Type      string    `json:"type"`
	RequestID string    `json:"request_id,omitempty"`
	RefID     string    `json:"ref_id,omitempty"`
}

type AdHocView struct {
	AtSeconds int                    `json:"at_seconds"`
	Query     sim.Query              `json:"query"`
	Samples   map[string]*sim.Sample `json:"samples"`
	RequestID string                 `json:"request_id,omitempty"`
}
