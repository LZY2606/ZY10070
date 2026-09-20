package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"zonesim/internal/dns"
	"zonesim/internal/sim"
)

type simulateReq struct {
	RequestID string          `json:"request_id"`
	Params    *sim.Parameters `json:"parameters"`
}

// SimDoc is the stored derived simulation plus identity fingerprints.
type SimDoc struct {
	ID         string      `json:"id"`
	PlanID     string      `json:"plan_id"`
	PlanFp     string      `json:"plan_fp"`
	ParamsFp   string      `json:"params_fp"`
	DecisionFp string      `json:"decision_fp"`
	Reused     bool        `json:"reused"`
	Result     *sim.Result `json:"result"`
}

// RunSimulation executes (or deterministically reuses) a simulation.
func (s *Service) RunSimulation(planID string, raw []byte) ([]byte, *Error) {
	var req simulateReq
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
		return nil, errConflict("plan is blocked and cannot be simulated", doc.Blocks)
	}
	params := sim.Parameters{}
	if req.Params != nil {
		params = *req.Params
	}
	params.Defaults()

	curBytes, ok := s.Store.GetZone(doc.CurrentZoneID)
	if !ok {
		return nil, errNotFound("current zone not found")
	}
	base, _, e := mustParseZone(curBytes)
	if e != nil {
		return nil, e
	}

	planFp := sim.PlanFingerprint(doc.Plan)
	paramsFp := sim.ParamsFingerprint(params)
	decFp := sim.DecisionFingerprint(doc.Decisions)

	// Deterministic reuse: same candidate plan + params + decisions -> same result.
	if existing := s.findSimulation(planID, planFp, paramsFp, decFp); existing != "" {
		b, _ := s.Store.GetSimulation(existing)
		_ = b
		resp := map[string]any{"simulation_id": existing, "reused": true}
		out, _ := json.Marshal(resp)
		// Replay record still stores the idempotent response, but no new business doc.
		return out, nil
	}

	result, err := sim.Run(sim.Input{Base: base, Plan: doc.Plan, Params: params, Decisions: doc.Decisions})
	if err != nil {
		return nil, errInvalid("simulation failed: "+err.Error(), nil)
	}
	id := newID("sim")
	result.ID = id
	result.PlanFingerprint = planFp
	result.ParamsFingerprint = paramsFp
	result.DecisionFingerprint = decFp

	simDoc := SimDoc{ID: id, PlanID: planID, PlanFp: planFp, ParamsFp: paramsFp,
		DecisionFp: decFp, Result: result}
	docBytes, err := s.Store.StageSimulation(id, simDoc)
	if err != nil {
		return nil, errInternal(err)
	}
	doc.LatestSimID = id
	planBytes, _ := s.Store.StagePlan(doc.ID, doc)
	_ = planBytes

	resp := map[string]any{"simulation_id": id, "reused": false,
		"earliest_all_converged_sec": result.EarliestConverged,
		"horizon_sec":                result.HorizonSec,
		"plan_fingerprint":           planFp, "params_fingerprint": paramsFp,
		"decision_fingerprint": decFp}
	out, e2 := s.commit(req.RequestID, "POST /api/plans/"+planID+"/simulations", raw, id, "simulation", docBytes, resp)
	if e2 != nil {
		return nil, e2
	}
	return out, nil
}

func (s *Service) findSimulation(planID, planFp, paramsFp, decFp string) string {
	for _, id := range s.Store.ListSimulations() {
		b, ok := s.Store.GetSimulation(id)
		if !ok {
			continue
		}
		var d SimDoc
		if json.Unmarshal(b, &d) != nil {
			continue
		}
		if d.PlanID == planID && d.PlanFp == planFp && d.ParamsFp == paramsFp && d.DecisionFp == decFp {
			return id
		}
	}
	return ""
}

// GetSimulation returns a stored derived simulation.
func (s *Service) GetSimulation(id string) ([]byte, *Error) {
	b, ok := s.Store.GetSimulation(id)
	if !ok {
		return nil, errNotFound("simulation not found")
	}
	return b, nil
}

func fingerprintBytes(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// silence unused import in some build configs
var _ = dns.RR{}
