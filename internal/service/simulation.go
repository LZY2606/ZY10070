package service

import (
	"fmt"
	"time"

	"zonesim/internal/sim"
	"zonesim/internal/store"
)

// RunSimulationInput creates (or reuses) a deterministic simulation.
type RunSimulationInput struct {
	PlanID          string           `json:"plan_id"`
	Seed            int64            `json:"seed"`
	AuthServers     []string         `json:"auth_servers,omitempty"`
	Nodes           []sim.NodeConfig `json:"nodes,omitempty"`
	Probes          []sim.Query      `json:"probes"`
	MaxDelaySeconds int              `json:"max_delay_seconds,omitempty"`
	QueryEvery      int              `json:"query_every_seconds,omitempty"`
	Horizon         int              `json:"horizon_seconds,omitempty"`
	RollbackAt      int              `json:"rollback_at_seconds,omitempty"`
}

func (s *Service) loadSimulation(id string) (*sim.Simulation, error) {
	var doc sim.Simulation
	if err := s.store.Get(store.KindSimulation, id, &doc); err != nil {
		if err == store.ErrNotFound {
			return nil, notFound("simulation " + id + " not found")
		}
		return nil, internalErr(err.Error())
	}
	return &doc, nil
}

// RunSimulation creates a simulation bound to a plan revision. Repeating the
// same candidate+configuration returns the previously computed document: the
// result is deterministic and keyed by identity. Node jitter is fully derived
// from the explicit seed.
func (s *Service) RunSimulation(in RunSimulationInput) (*sim.Simulation, bool, error) {
	p, err := s.loadPlan(in.PlanID)
	if err != nil {
		return nil, false, err
	}
	cur, err := s.GetZone(p.CurrentZoneID)
	if err != nil {
		return nil, false, err
	}
	cand, err := s.GetZone(p.CandidateZoneID)
	if err != nil {
		return nil, false, err
	}
	if len(in.Probes) == 0 {
		return nil, false, invalid("PROBES_REQUIRED", "at least one probe query is required")
	}

	cfg := sim.Config{
		CurrentFingerprint:   cur.Fingerprint,
		CandidateFingerprint: cand.Fingerprint,
		Phases:               append([]sim.Phase(nil), p.Phases...),
		AuthServers:          append([]string(nil), in.AuthServers...),
		Nodes:                append([]sim.NodeConfig(nil), in.Nodes...),
		Probes:               append([]sim.Query(nil), in.Probes...),
		Seed:                 in.Seed,
		MaxDelaySeconds:      in.MaxDelaySeconds,
		QueryEverySeconds:    in.QueryEvery,
		HorizonSeconds:       in.Horizon,
		RollbackAtSeconds:    in.RollbackAt,
	}
	if err := sim.Normalize(&cfg); err != nil {
		return nil, false, invalid("SIM_CONFIG_INVALID", err.Error())
	}
	identity := sim.Identity(cfg)

	if existing, err := s.findSimulationByIdentity(identity); err != nil {
		return nil, false, err
	} else if existing != nil {
		return existing, true, nil
	}

	report := sim.Run(cfg, cur.Origin, cur.ParsedZone(), cand.ParsedZone())
	doc := &sim.Simulation{
		ID:                   newID("sim"),
		PlanID:               p.ID,
		Identity:             identity,
		Seed:                 cfg.Seed,
		CurrentFingerprint:   cur.Fingerprint,
		CandidateFingerprint: cand.Fingerprint,
		Config:               cfg,
		Report:               report,
		CreatedAt:            time.Now().UTC(),
	}
	var rb *sim.Report
	if cfg.RollbackAtSeconds > 0 {
		rbCfg := cfg
		// Rollback report is derived from the same deterministic schedule;
		// convergence here is how long nodes need to re-observe base data
		// while still honouring cached new-data TTLs.
		rb = sim.Run(rbCfg, cur.Origin, cur.ParsedZone(), cand.ParsedZone())
		doc.RollbackReport = rb
	}
	if err := s.store.Put(store.KindSimulation, doc.ID, doc); err != nil {
		return nil, false, internalErr(err.Error())
	}
	if _, err := s.store.AppendEvent("simulation.created", "", doc.ID, map[string]any{
		"plan_id": p.ID, "identity": identity, "seed": cfg.Seed,
		"converged": report.ConvergedWithin, "converged_at": report.ConvergedAt,
	}); err != nil {
		return nil, false, internalErr(err.Error())
	}
	return doc, false, nil
}

// findSimulationByIdentity scans derived simulations for an identity match.
func (s *Service) findSimulationByIdentity(identity string) (*sim.Simulation, error) {
	ids, err := s.store.List(store.KindSimulation)
	if err != nil {
		return nil, internalErr(err.Error())
	}
	for _, id := range ids {
		doc, err := s.loadSimulation(id)
		if err != nil {
			return nil, err
		}
		if doc.Identity == identity {
			return doc, nil
		}
	}
	return nil, nil
}

// GetSimulation returns one simulation.
func (s *Service) GetSimulation(id string) (*sim.Simulation, error) {
	return s.loadSimulation(id)
}

// ListSimulations returns all simulations (reports omitted for the index).
func (s *Service) ListSimulations() ([]sim.Simulation, error) {
	ids, err := s.store.List(store.KindSimulation)
	if err != nil {
		return nil, internalErr(err.Error())
	}
	out := make([]sim.Simulation, 0, len(ids))
	for _, id := range ids {
		d, err := s.loadSimulation(id)
		if err != nil {
			return nil, err
		}
		cp := *d
		cp.Report = nil
		out = append(out, cp)
	}
	return out, nil
}

// SliderView is a per-node answer snapshot at one simulation instant.
type SliderView struct {
	AtSeconds int                    `json:"at_seconds"`
	Query     sim.Query              `json:"query"`
	Samples   map[string]*sim.Sample `json:"samples"`
}

// ViewAt answers the time-slider request by deterministically replaying node
// caches to t. Results are identical to the timeline stored at creation.
func (s *Service) ViewAt(simID string, q sim.Query, t int) (*SliderView, error) {
	doc, err := s.loadSimulation(simID)
	if err != nil {
		return nil, err
	}
	if t < 0 || t > doc.Config.HorizonSeconds {
		return nil, invalid("TIME_OUT_OF_RANGE",
			fmt.Sprintf("time %d is outside [0,%d]", t, doc.Config.HorizonSeconds))
	}
	curDoc, candDoc, err := s.planZones(doc.PlanID)
	if err != nil {
		return nil, err
	}
	samples := sim.QueryAtProbe(doc.Config, curDoc.Origin, curDoc.ParsedZone(), candDoc.ParsedZone(), q, t)
	return &SliderView{AtSeconds: t, Query: q, Samples: samples}, nil
}

func (s *Service) planZones(planID string) (*ZoneDoc, *ZoneDoc, error) {
	p, err := s.loadPlan(planID)
	if err != nil {
		return nil, nil, err
	}
	cur, err := s.GetZone(p.CurrentZoneID)
	if err != nil {
		return nil, nil, err
	}
	cand, err := s.GetZone(p.CandidateZoneID)
	if err != nil {
		return nil, nil, err
	}
	return cur, cand, nil
}

// AdHocQuery records an operator's on-demand query without altering the
// deterministic report. It is appended to the simulation's side log.
type AdHocQuery struct {
	AtSeconds int       `json:"at_seconds"`
	Query     sim.Query `json:"query"`
}

// RunAdHocQuery evaluates one extra query and durably records it. Repeating
// the same request id returns the prior view without appending a second side
// record, keeping the operation at-most-once.
func (s *Service) RunAdHocQuery(simID, reqID string, q AdHocQuery) (*AdHocView, error) {
	doc, err := s.loadSimulation(simID)
	if err != nil {
		return nil, err
	}
	cur, cand, err := s.planZones(doc.PlanID)
	if err != nil {
		return nil, err
	}
	if q.AtSeconds < 0 || q.AtSeconds > doc.Config.HorizonSeconds {
		return nil, invalid("TIME_OUT_OF_RANGE", "ad-hoc time outside horizon")
	}
	samples := sim.QueryAtProbe(doc.Config, cur.Origin, cur.ParsedZone(), cand.ParsedZone(), q.Query, q.AtSeconds)
	view := &AdHocView{AtSeconds: q.AtSeconds, Query: q.Query, Samples: samples, RequestID: reqID}

	log, _ := s.loadAdHoc(simID)
	if reqID != "" {
		for i := range log {
			if adHocMatches(log[i], q, reqID) {
				return &log[i], nil
			}
		}
	}
	log = append(log, *view)
	if err := s.store.Put(store.KindExport, adhocName(simID), adHocLog{Items: log}); err != nil {
		return nil, internalErr(err.Error())
	}
	if _, err := s.store.AppendEvent("simulation.adhoc_query", "", simID, map[string]any{
		"at_seconds": q.AtSeconds, "qname": q.Query.QName, "qtype": q.Query.QType,
	}); err != nil {
		return nil, internalErr(err.Error())
	}
	return view, nil
}

type adHocLog struct {
	Items []AdHocView `json:"items"`
}

func adhocName(simID string) string { return "adhoc_" + simID }

func (s *Service) loadAdHoc(simID string) ([]AdHocView, error) {
	var log adHocLog
	if err := s.store.Get(store.KindExport, adhocName(simID), &log); err != nil {
		if err == store.ErrNotFound {
			return nil, nil
		}
		return nil, internalErr(err.Error())
	}
	return log.Items, nil
}
