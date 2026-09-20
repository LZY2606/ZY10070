package service

import (
	"encoding/json"
	"strconv"

	"zonesim/internal/dns"
	"zonesim/internal/sim"
)

type decisionReq struct {
	RequestID string `json:"request_id"`
	Action    string `json:"action"`
	AtSec     int    `json:"at_sec"`
	Note      string `json:"note,omitempty"`
}

// AddDecision records a proceed/rollback choice after validating state and time.
func (s *Service) AddDecision(planID string, phaseIndex int, raw []byte) ([]byte, *Error) {
	var req decisionReq
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, errInvalid("request body must be valid JSON", err.Error())
	}
	if req.RequestID == "" {
		return nil, errInvalid("request_id is required", nil)
	}
	if r := s.Store.LookupRequest(req.RequestID); r != nil {
		return replayOrConflict(r, fingerprintBytes(raw))
	}
	doc, _, e := s.loadPlanDoc(planID)
	if e != nil {
		return nil, e
	}
	if doc.Status == "blocked" {
		return nil, errConflict("plan is blocked", doc.Blocks)
	}
	if req.Action != "proceed" && req.Action != "rollback" {
		return nil, errInvalid("action must be proceed or rollback", nil)
	}

	if req.Action == "proceed" {
		if doc.Status == "completed" || doc.Status == "rolled_back" {
			return nil, errConflict("plan already "+doc.Status, nil)
		}
		if phaseIndex < 0 || phaseIndex >= len(doc.Plan.Phases) {
			return nil, errInvalid("phase_index out of range", nil)
		}
		if phaseIndex != doc.CurrentPhase {
			return nil, errConflict("phase is not the current pending phase",
				map[string]any{"current_phase": doc.CurrentPhase, "requested": phaseIndex})
		}
		earliest := EarliestForPhase(doc.Plan, doc.Decisions, phaseIndex)
		if req.AtSec < earliest {
			return nil, errConflict("decision violates the phase minimum observation time",
				map[string]any{"at_sec": req.AtSec, "earliest_sec": earliest})
		}
		doc.Decisions = append(doc.Decisions, sim.Decision{
			PhaseIndex: phaseIndex, Action: "proceed", AtSec: req.AtSec, Note: req.Note})
		doc.CurrentPhase++
		if doc.CurrentPhase >= len(doc.Plan.Phases) {
			doc.Status = "completed"
		}
	} else {
		if doc.Status == "rolled_back" {
			return nil, errConflict("plan already rolled back", nil)
		}
		last := lastEventTime(doc.Decisions)
		if req.AtSec < last {
			return nil, errConflict("rollback cannot be scheduled before the last decision",
				map[string]any{"at_sec": req.AtSec, "last_decision_sec": last})
		}
		doc.Decisions = append(doc.Decisions, sim.Decision{
			PhaseIndex: phaseIndex, Action: "rollback", AtSec: req.AtSec, Note: req.Note})
		doc.Status = "rolled_back"
	}

	// New decisions change the timeline; prior derived simulations are stale.
	doc.LatestSimID = ""
	docBytes, err := s.Store.StagePlan(doc.ID, doc)
	if err != nil {
		return nil, errInternal(err)
	}
	resp := map[string]any{"plan_id": doc.ID, "status": doc.Status,
		"current_phase": doc.CurrentPhase, "decisions": doc.Decisions}
	return s.commit(req.RequestID, "POST /api/plans/"+planID+"/phases/"+strconv.Itoa(phaseIndex)+"/decision",
		raw, doc.ID, "plan", docBytes, resp)
}

// EarliestForPhase mirrors the engine scheduler: phases proceed sequentially,
// and phase i cannot occur before decided(i-1) + MinObserveSec(i).
func EarliestForPhase(plan dns.Plan, decisions []sim.Decision, idx int) int {
	t := 0
	for i := 0; i < idx; i++ {
		at := t + plan.Phases[i].MinObserveSec
		for _, d := range decisions {
			if d.Action == "proceed" && d.PhaseIndex == i && d.AtSec > at {
				at = d.AtSec
			}
		}
		t = at
	}
	return t + plan.Phases[idx].MinObserveSec
}

func lastEventTime(decisions []sim.Decision) int {
	last := 0
	for _, d := range decisions {
		if d.AtSec > last {
			last = d.AtSec
		}
	}
	return last
}
