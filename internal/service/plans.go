package service

import (
	"encoding/json"
	"strconv"

	"zonesim/internal/dns"
	"zonesim/internal/sim"
)

// PlanDoc is the stored raw plan plus derived identity/validation state.
type PlanDoc struct {
	ID            string         `json:"id"`
	SourcePlanID  string         `json:"source_plan_id,omitempty"`
	ZoneName      string         `json:"zone_name"`
	CurrentZoneID string         `json:"current_zone_id"`
	Plan          dns.Plan       `json:"plan"`
	Fingerprint   string         `json:"fingerprint"`
	BaseZoneFp    string         `json:"base_zone_fp"`
	Blocks        []dns.Block    `json:"blocks"`
	Status        string         `json:"status"` // ready | blocked | completed | rolled_back
	CurrentPhase  int            `json:"current_phase"`
	Decisions     []sim.Decision `json:"decisions,omitempty"`
	LatestSimID   string         `json:"latest_sim_id,omitempty"`
}

type createPlanReq struct {
	RequestID       string    `json:"request_id"`
	Name            string    `json:"name"`
	CurrentZoneID   string    `json:"current_zone_id"`
	CandidateZoneID string    `json:"candidate_zone_id,omitempty"`
	Plan            *dns.Plan `json:"plan,omitempty"`
}

// CreatePlan either diffs current->candidate or accepts explicit phases,
// then runs all safety validation before accepting the plan.
func (s *Service) CreatePlan(raw []byte) ([]byte, *Error) {
	var req createPlanReq
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, errInvalid("request body must be valid JSON", err.Error())
	}
	if req.RequestID == "" {
		return nil, errInvalid("request_id is required", nil)
	}
	if r := s.Store.LookupRequest(req.RequestID); r != nil {
		return replayOrConflict(r, fingerprintBytes(raw))
	}
	if req.CurrentZoneID == "" {
		return nil, errInvalid("current_zone_id is required", nil)
	}
	curBytes, ok := s.Store.GetZone(req.CurrentZoneID)
	if !ok {
		return nil, errNotFound("current zone not found")
	}
	base, _, e := mustParseZone(curBytes)
	if e != nil {
		return nil, e
	}

	plan := dns.Plan{}
	if req.Plan != nil {
		plan = *req.Plan
	}
	if plan.ZoneName == "" {
		plan.ZoneName = base.Origin
	}
	if len(plan.Phases) == 0 {
		if req.CandidateZoneID == "" {
			return nil, errInvalid("either plan.phases or candidate_zone_id is required", nil)
		}
		candBytes, ok := s.Store.GetZone(req.CandidateZoneID)
		if !ok {
			return nil, errNotFound("candidate zone not found")
		}
		cand, _, e := mustParseZone(candBytes)
		if e != nil {
			return nil, e
		}
		ops := dns.DiffZones(base, cand)
		if len(ops) == 0 {
			return nil, errInvalid("candidate zone is identical to current zone", nil)
		}
		plan.Phases = []dns.Phase{{Name: "candidate-cutover", Operations: ops, MinObserveSec: 300}}
	}
	if len(plan.Phases) == 0 {
		return nil, errInvalid("plan has no phases", nil)
	}
	for i, ph := range plan.Phases {
		if ph.Name == "" {
			plan.Phases[i].Name = "phase-" + strconv.Itoa(i)
		}
	}
	if plan.ZoneName != base.Origin {
		return nil, errInvalid("plan zone_name does not match current zone origin",
			map[string]any{"plan_zone": plan.ZoneName, "origin": base.Origin})
	}

	blocks := dns.ValidatePlan(base, plan)
	doc := PlanDoc{ID: newID("plan"), ZoneName: plan.ZoneName,
		CurrentZoneID: req.CurrentZoneID, Plan: plan,
		Fingerprint: sim.PlanFingerprint(plan), BaseZoneFp: base.Fingerprint(),
		Blocks: blocks, CurrentPhase: 0}
	if len(blocks) > 0 {
		doc.Status = "blocked"
	} else {
		doc.Status = "ready"
	}
	docBytes, _ := json.MarshalIndent(doc, "", "  ")
	if b, err := s.Store.StagePlan(doc.ID, doc); err != nil {
		return nil, errInternal(err)
	} else {
		docBytes = b
	}
	resp := map[string]any{"plan_id": doc.ID, "status": doc.Status,
		"fingerprint": doc.Fingerprint, "blocks": doc.Blocks, "phases": len(plan.Phases)}
	out, e2 := s.commit(req.RequestID, "POST /api/plans", raw, doc.ID, "plan", docBytes, resp)
	if e2 != nil {
		return nil, e2
	}
	if doc.Status == "blocked" {
		return out, errBlocked(blocks)
	}
	return out, nil
}

// ListPlans returns all stored plans.
func (s *Service) ListPlans() ([]byte, *Error) {
	var out []PlanDoc
	for _, id := range s.Store.ListPlans() {
		b, ok := s.Store.GetPlan(id)
		if !ok {
			continue
		}
		var d PlanDoc
		if json.Unmarshal(b, &d) == nil {
			out = append(out, d)
		}
	}
	b, err := json.Marshal(map[string]any{"plans": out})
	if err != nil {
		return nil, errInternal(err)
	}
	return b, nil
}

func (s *Service) loadPlanDoc(id string) (*PlanDoc, []byte, *Error) {
	b, ok := s.Store.GetPlan(id)
	if !ok {
		return nil, nil, errNotFound("plan not found")
	}
	var d PlanDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, nil, errInternal(err)
	}
	return &d, b, nil
}
