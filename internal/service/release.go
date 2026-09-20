package service

import (
	"fmt"
	"sort"
	"time"

	"zonesim/internal/sim"
)

// ValidatePlan re-runs pre-publish checks and records per-phase decisions.
func (s *Service) ValidatePlan(id string) (*Plan, error) {
	p, err := s.loadPlan(id)
	if err != nil {
		return nil, err
	}
	cur, err := s.GetZone(p.CurrentZoneID)
	if err != nil {
		return nil, err
	}
	cand, err := s.GetZone(p.CandidateZoneID)
	if err != nil {
		return nil, err
	}
	p.Findings = append(p.Findings[:0:0], dnsValidate(cur.ParsedZone(), cand.ParsedZone())...)
	// Build per-phase decisions.
	blockedByKey := map[string][]string{}
	for _, f := range p.Findings {
		if f.Blocking() {
			blockedByKey[f.Name+" "+f.Type] = append(blockedByKey[f.Name+" "+f.Type], f.Code)
		}
	}
	now := time.Now().UTC()
	cursor := 0
	p.Decisions = p.Decisions[:0]
	for _, ph := range p.Phases {
		cursor += ph.MinHoldSeconds
		d := PhaseDecision{PhaseName: ph.Name, EffectiveAtSeconds: cursor, Keys: append([]string(nil), ph.ChangedKeys...), DecidedAt: now}
		blocked := false
		for _, k := range ph.ChangedKeys {
			if codes := blockedByKey[k]; len(codes) > 0 {
				blocked = true
				d.Reasons = append(d.Reasons, findFor(p.Findings, k)...)
			}
		}
		if blocked {
			d.Decision = "blocked"
		} else {
			d.Decision = "accepted"
		}
		p.Decisions = append(p.Decisions, d)
	}
	if p.Blocked() {
		p.Status = StateDraft
	} else {
		p.Status = StateReady
	}
	p.Revision++
	if err := s.savePlan(p); err != nil {
		return nil, err
	}
	if _, err := s.Store().AppendEvent("plan.validated", "", p.ID, map[string]any{
		"blocked": p.Blocked(), "status": p.Status,
	}); err != nil {
		return nil, internalErr(err.Error())
	}
	return p, nil
}

func findFor(fs []dnsFinding, key string) []dnsFinding {
	name, typ := splitRRKey(key)
	var out []dnsFinding
	for _, f := range fs {
		if f.Name == name && f.Type == typ {
			out = append(out, f)
		}
	}
	return out
}

// CommitPlan commits only when no blockers remain.
func (s *Service) CommitPlan(id string) (*Plan, error) {
	p, err := s.loadPlan(id)
	if err != nil {
		return nil, err
	}
	if p.Status == StateCommitted {
		return nil, conflict("PLAN_ALREADY_COMMITTED", "plan is already committed")
	}
	if p.Status == StateRolledBack {
		return nil, conflict("PLAN_ROLLED_BACK", "a rolled-back plan cannot be committed; copy it first")
	}
	cur, err := s.GetZone(p.CurrentZoneID)
	if err != nil {
		return nil, err
	}
	cand, err := s.GetZone(p.CandidateZoneID)
	if err != nil {
		return nil, err
	}
	p.Findings = append(p.Findings[:0:0], dnsValidate(cur.ParsedZone(), cand.ParsedZone())...)
	if err := s.validatePhasesAgainstDiff(p); err != nil {
		return nil, err
	}
	if p.Blocked() {
		return nil, conflict("PLAN_HAS_BLOCKERS",
			"cannot commit: "+summarizeBlockers(p.Findings))
	}
	now := time.Now().UTC()
	p.Status = StateCommitted
	p.CommittedAt = &now
	p.Revision++
	if err := s.savePlan(p); err != nil {
		return nil, err
	}
	if _, err := s.Store().AppendEvent("plan.committed", "", p.ID, map[string]any{
		"fingerprint": planFingerprint(p),
	}); err != nil {
		return nil, internalErr(err.Error())
	}
	return p, nil
}

func (s *Service) validatePhasesAgainstDiff(p *Plan) error {
	return validatePhases(p.Phases, p.Changes)
}

func summarizeBlockers(fs []dnsFinding) string {
	var codes []string
	for _, f := range fs {
		if f.Blocking() {
			codes = append(codes, f.Code)
		}
	}
	sort.Strings(codes)
	uniq := codes[:0]
	for _, c := range codes {
		if len(uniq) == 0 || uniq[len(uniq)-1] != c {
			uniq = append(uniq, c)
		}
	}
	return joinStrings(uniq, ", ")
}

func joinStrings(ss []string, sep string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += sep
		}
		out += s
	}
	return out
}

// RollbackPlan marks a plan rolled back. The simulation timeline proves that
// old records only reappear subject to previously emitted TTLs.
func (s *Service) RollbackPlan(id string, atSeconds int) (*Plan, error) {
	p, err := s.loadPlan(id)
	if err != nil {
		return nil, err
	}
	if p.Status != StateCommitted {
		return nil, conflict("PLAN_NOT_COMMITTED", "only a committed plan can be rolled back")
	}
	if atSeconds < 0 {
		return nil, invalid("ROLLBACK_TIME_NEGATIVE", "rollback time cannot be negative")
	}
	now := time.Now().UTC()
	p.Status = StateRolledBack
	p.RolledBackAt = &now
	p.Revision++
	if err := s.savePlan(p); err != nil {
		return nil, err
	}
	if _, err := s.Store().AppendEvent("plan.rollback_initiated", "", p.ID, map[string]any{
		"at_seconds": atSeconds,
	}); err != nil {
		return nil, internalErr(err.Error())
	}
	return p, nil
}

var _ = sim.DefaultMaxDelay
var _ = fmt.Sprint
