package service

import (
	"encoding/json"
	"time"

	"zonesim/internal/dns"
	"zonesim/internal/sim"
)

type copyPlanReq struct {
	RequestID string    `json:"request_id"`
	Plan      *dns.Plan `json:"plan"`
}

// CopyPlan duplicates a plan into a new editable document. The copy keeps a
// reference to the source plan fingerprint so old simulations visibly remain
// bound to the old plan rather than the modified copy.
func (s *Service) CopyPlan(planID string, raw []byte) ([]byte, *Error) {
	var req copyPlanReq
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, errInvalid("request body must be valid JSON", err.Error())
	}
	if req.RequestID == "" {
		return nil, errInvalid("request_id is required", nil)
	}
	if r := s.Store.LookupRequest(req.RequestID); r != nil {
		return replayOrConflict(r, fingerprintBytes(raw))
	}
	src, _, e := s.loadPlanDoc(planID)
	if e != nil {
		return nil, e
	}
	plan := src.Plan
	if req.Plan != nil {
		plan = *req.Plan
		if plan.ZoneName == "" {
			plan.ZoneName = src.ZoneName
		}
	}
	curBytes, ok := s.Store.GetZone(src.CurrentZoneID)
	if !ok {
		return nil, errNotFound("current zone not found")
	}
	base, _, e := mustParseZone(curBytes)
	if e != nil {
		return nil, e
	}
	blocks := dns.ValidatePlan(base, plan)
	dup := PlanDoc{ID: newID("plan"), SourcePlanID: src.ID, ZoneName: plan.ZoneName,
		CurrentZoneID: src.CurrentZoneID, Plan: plan,
		Fingerprint: sim.PlanFingerprint(plan), BaseZoneFp: base.Fingerprint(),
		Blocks: blocks, CurrentPhase: 0}
	if len(blocks) > 0 {
		dup.Status = "blocked"
	} else {
		dup.Status = "ready"
	}
	docBytes, err := s.Store.StagePlan(dup.ID, dup)
	if err != nil {
		return nil, errInternal(err)
	}
	resp := map[string]any{"plan_id": dup.ID, "source_plan_id": src.ID,
		"source_plan_fingerprint": src.Fingerprint, "status": dup.Status,
		"fingerprint": dup.Fingerprint, "blocks": dup.Blocks}
	out, e := s.commit(req.RequestID, "POST /api/plans/"+planID+"/copy", raw, dup.ID, "plan", docBytes, resp)
	if e != nil {
		return nil, e
	}
	if dup.Status == "blocked" {
		return out, errBlocked(blocks)
	}
	return out, nil
}

// ExportBundle is the full evidence package for a simulation.
type ExportBundle struct {
	ExportedAt     string          `json:"exported_at"`
	Plan           PlanDoc         `json:"plan"`
	Simulation     SimDoc          `json:"simulation"`
	QueryEvidence  []QueryEvidence `json:"query_evidence"`
	PhaseDecisions []PhaseDecision `json:"phase_decisions"`
	Events         []EventView     `json:"operation_events"`
}

// QueryEvidence is one monitored query with per-node timeline and convergence.
type QueryEvidence struct {
	Query            sim.Query      `json:"query"`
	FinalCanonical   string         `json:"final_canonical"`
	NodeConvergedSec map[string]int `json:"node_converged_sec"`
	AllConvergedSec  int            `json:"all_converged_sec"`
	Views            []sim.NodeView `json:"views"`
}

// PhaseDecision documents the staged timing choices.
type PhaseDecision struct {
	Index       int    `json:"index"`
	Name        string `json:"name"`
	EarliestSec int    `json:"earliest_sec"`
	DecidedSec  int    `json:"decided_sec"`
	StableAtSec int    `json:"stable_at_sec"`
}

// EventView surfaces operation/audit events in the export.
type EventView struct {
	Seq        int64  `json:"seq"`
	At         string `json:"at"`
	RequestID  string `json:"request_id"`
	Kind       string `json:"kind"`
	ResourceID string `json:"resource_id,omitempty"`
}

type exportReq struct {
	RequestID string `json:"request_id"`
}

// ExportSimulation assembles complete query evidence + phase decisions + events.
func (s *Service) ExportSimulation(simID string, raw []byte) ([]byte, *Error) {
	var req exportReq
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, errInvalid("request body must be valid JSON", err.Error())
	}
	if req.RequestID == "" {
		return nil, errInvalid("request_id is required", nil)
	}
	if r := s.Store.LookupRequest(req.RequestID); r != nil {
		return replayOrConflict(r, fingerprintBytes(raw))
	}
	simBytes, ok := s.Store.GetSimulation(simID)
	if !ok {
		return nil, errNotFound("simulation not found")
	}
	var sd SimDoc
	if err := json.Unmarshal(simBytes, &sd); err != nil {
		return nil, errInternal(err)
	}
	planDoc, _, e := s.loadPlanDoc(sd.PlanID)
	if e != nil {
		return nil, e
	}

	convByQuery := map[string]sim.Convergence{}
	for _, c := range sd.Result.Convergence {
		convByQuery[c.Query.Name+"|"+c.Query.Type] = c
	}
	evidence := []QueryEvidence{}
	for _, tr := range sd.Result.Traces {
		c := convByQuery[tr.Query.Name+"|"+tr.Query.Type]
		evidence = append(evidence, QueryEvidence{
			Query: tr.Query, FinalCanonical: c.FinalCanonical,
			NodeConvergedSec: c.NodeConvergedSec, AllConvergedSec: c.AllConvergedSec,
			Views: tr.Views,
		})
	}
	decisions := []PhaseDecision{}
	for _, pt := range sd.Result.PhaseSchedule {
		decisions = append(decisions, PhaseDecision{
			Index: pt.Index, Name: pt.Name, EarliestSec: pt.EarliestSec,
			DecidedSec: pt.DecidedSec, StableAtSec: pt.StableAtSec})
	}
	events, err := s.Store.ListEvents()
	if err != nil {
		return nil, errInternal(err)
	}
	ev := []EventView{}
	for _, x := range events {
		ev = append(ev, EventView{Seq: x.Seq, At: x.At, RequestID: x.RequestID,
			Kind: x.Kind, ResourceID: x.ResourceID})
	}
	bundle := ExportBundle{ExportedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Plan: *planDoc, Simulation: sd, QueryEvidence: evidence,
		PhaseDecisions: decisions, Events: ev}

	id := newID("export")
	docBytes, err := s.Store.StageExport(id, bundle)
	if err != nil {
		return nil, errInternal(err)
	}
	resp := map[string]any{"export_id": id}
	return s.commit(req.RequestID, "POST /api/simulations/"+simID+"/export", raw, id, "export", docBytes, resp)
}

// GetExport returns a stored evidence bundle.
func (s *Service) GetExport(id string) ([]byte, *Error) {
	b, ok := s.Store.GetExport(id)
	if !ok {
		return nil, errNotFound("export not found")
	}
	return b, nil
}
