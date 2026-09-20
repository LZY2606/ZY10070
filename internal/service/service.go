package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"zonesim/internal/dns"
	"zonesim/internal/sim"
	"zonesim/internal/store"
)

// Service wires the store to the domain logic.
type Service struct {
	store *store.Store
}

// New constructs a service over dataDir.
func New(dataDir string) (*Service, error) {
	st, err := store.Open(dataDir)
	if err != nil {
		return nil, err
	}
	return &Service{store: st}, nil
}

// Store exposes the persistence layer (used for event/export reads).
func (s *Service) Store() *store.Store { return s.store }

func newID(prefix string) string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return prefix + "_" + hex.EncodeToString(b[:])
}

// ImportZoneInput is the raw import request.
type ImportZoneInput struct {
	Label  string `json:"label"`
	Origin string `json:"origin"`
	Text   string `json:"text"`
}

// ImportZone parses and persists raw zone input.
func (s *Service) ImportZone(in ImportZoneInput) (*ZoneDoc, error) {
	if strings.TrimSpace(in.Text) == "" {
		return nil, invalid("ZONE_EMPTY", "zone text must not be empty")
	}
	origin := in.Origin
	if strings.TrimSpace(origin) == "" {
		origin = guessOrigin(in.Text)
	}
	if strings.TrimSpace(origin) == "" {
		return nil, invalid("ZONE_ORIGIN_MISSING", "origin must be provided or declared with $ORIGIN")
	}
	origin = dns.CanonicalName(origin, dns.CanonicalName(origin, origin))
	z, err := dns.ParseZone(in.Text, origin)
	if err != nil {
		return nil, invalid("ZONE_PARSE_FAILED", err.Error())
	}
	doc := &ZoneDoc{
		ID: newID("zone"), Label: in.Label, Origin: z.Origin, Text: in.Text,
		Fingerprint: z.Fingerprint(), CreatedAt: time.Now().UTC(), zone: z,
	}
	if err := s.store.Put(store.KindZone, doc.ID, doc); err != nil {
		return nil, internalErr(err.Error())
	}
	if _, err := s.store.AppendEvent("zone.imported", "", doc.ID, map[string]any{
		"fingerprint": doc.Fingerprint, "origin": doc.Origin,
	}); err != nil {
		return nil, internalErr(err.Error())
	}
	return doc, nil
}

func guessOrigin(text string) string {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && strings.EqualFold(f[0], "$ORIGIN") {
			return f[1]
		}
	}
	return ""
}

// GetZone loads a zone and re-parses it for in-memory use.
func (s *Service) GetZone(id string) (*ZoneDoc, error) {
	var doc ZoneDoc
	if err := s.store.Get(store.KindZone, id, &doc); err != nil {
		if err == store.ErrNotFound {
			return nil, notFound("zone " + id + " not found")
		}
		return nil, internalErr(err.Error())
	}
	z, err := dns.ParseZone(doc.Text, doc.Origin)
	if err != nil {
		return nil, internalErr("stored zone is unparseable: " + err.Error())
	}
	doc.zone = z
	return &doc, nil
}

// ListZones returns zone summaries.
func (s *Service) ListZones() ([]ZoneDoc, error) {
	ids, err := s.store.List(store.KindZone)
	if err != nil {
		return nil, internalErr(err.Error())
	}
	out := make([]ZoneDoc, 0, len(ids))
	for _, id := range ids {
		doc, err := s.GetZone(id)
		if err != nil {
			return nil, err
		}
		doc.Text = ""
		out = append(out, *doc)
	}
	return out, nil
}

// CreatePlanInput defines a new staged plan.
type CreatePlanInput struct {
	CurrentZoneID   string      `json:"current_zone_id"`
	CandidateZoneID string      `json:"candidate_zone_id"`
	Phases          []sim.Phase `json:"phases"`
	BasePlanID      string      `json:"base_plan_id,omitempty"`
}

func (s *Service) loadPlan(id string) (*Plan, error) {
	var p Plan
	if err := s.store.Get(store.KindPlan, id, &p); err != nil {
		if err == store.ErrNotFound {
			return nil, notFound("plan " + id + " not found")
		}
		return nil, internalErr(err.Error())
	}
	return &p, nil
}

func (s *Service) savePlan(p *Plan) error {
	p.UpdatedAt = time.Now().UTC()
	if err := s.store.Put(store.KindPlan, p.ID, p); err != nil {
		return internalErr(err.Error())
	}
	return nil
}

// CreatePlan computes the RRset diff, runs pre-publish validation and
// verifies each phase only touches changed keys.
func (s *Service) CreatePlan(in CreatePlanInput) (*Plan, error) {
	cur, err := s.GetZone(in.CurrentZoneID)
	if err != nil {
		return nil, err
	}
	cand, err := s.GetZone(in.CandidateZoneID)
	if err != nil {
		return nil, err
	}
	if cur.Origin != cand.Origin {
		return nil, invalid("ORIGIN_MISMATCH",
			fmt.Sprintf("current origin %s differs from candidate origin %s", cur.Origin, cand.Origin))
	}
	if len(in.Phases) == 0 {
		return nil, invalid("PHASES_REQUIRED", "a release plan needs at least one phase")
	}
	changes := dns.Diff(cur.zone, cand.zone)
	changeKeys := map[string]bool{}
	for _, c := range changes {
		changeKeys[c.Name+" "+c.Type] = true
	}
	seenKey := map[string]bool{}
	for i, ph := range in.Phases {
		if strings.TrimSpace(ph.Name) == "" {
			return nil, invalid("PHASE_NAME_MISSING", fmt.Sprintf("phase %d has no name", i))
		}
		if ph.MinHoldSeconds < 0 {
			return nil, invalid("PHASE_HOLD_NEGATIVE", "min hold cannot be negative: "+ph.Name)
		}
		if len(ph.ChangedKeys) == 0 {
			return nil, invalid("PHASE_KEYS_EMPTY", "phase changes nothing: "+ph.Name)
		}
		for _, k := range ph.ChangedKeys {
			if !changeKeys[k] {
				return nil, invalid("PHASE_KEY_UNCHANGED",
					fmt.Sprintf("phase %q may not change %s: not part of current->candidate diff", ph.Name, k))
			}
			key := ph.Name + "|" + k
			if seenKey[key] {
				return nil, invalid("PHASE_KEY_DUPLICATE",
					fmt.Sprintf("key %s listed twice in phase %q", k, ph.Name))
			}
			seenKey[key] = true
		}
	}
	covered := map[string]bool{}
	for _, ph := range in.Phases {
		for _, k := range ph.ChangedKeys {
			covered[k] = true
		}
	}
	for k := range changeKeys {
		if !covered[k] {
			return nil, invalid("CHANGE_NOT_PHASED",
				fmt.Sprintf("changed RRset %s is not assigned to any phase", k))
		}
	}
	findings := dns.ValidateCandidate(cur.zone, cand.zone)

	p := &Plan{
		ID: newID("plan"), CurrentZoneID: cur.ID, CandidateZoneID: cand.ID,
		CurrentFingerprint:   cur.Fingerprint,
		CandidateFingerprint: cand.Fingerprint,
		Phases:               in.Phases, Changes: changes, Findings: findings,
		Status: StateDraft, Revision: 1, BasePlanID: in.BasePlanID,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := s.savePlan(p); err != nil {
		return nil, err
	}
	if _, err := s.store.AppendEvent("plan.created", "", p.ID, map[string]any{
		"blocked": p.Blocked(), "phases": len(p.Phases),
		"current_fp": p.CurrentFingerprint, "candidate_fp": p.CandidateFingerprint,
	}); err != nil {
		return nil, internalErr(err.Error())
	}
	return p, nil
}

// GetPlan returns one plan.
func (s *Service) GetPlan(id string) (*Plan, error) { return s.loadPlan(id) }

// ListPlans lists all plan ids with summaries.
func (s *Service) ListPlans() ([]Plan, error) {
	ids, err := s.store.List(store.KindPlan)
	if err != nil {
		return nil, internalErr(err.Error())
	}
	out := make([]Plan, 0, len(ids))
	for _, id := range ids {
		p, err := s.loadPlan(id)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, nil
}

// CopyPlan duplicates a plan (typically so a user can edit phases). The copy
// starts at revision 1 and remains bound to the same zone fingerprints.
func (s *Service) CopyPlan(id string) (*Plan, error) {
	src, err := s.loadPlan(id)
	if err != nil {
		return nil, err
	}
	cp := *src
	cp.ID = newID("plan")
	cp.BasePlanID = src.ID
	cp.Revision = 1
	cp.Status = StateDraft
	cp.Decisions = nil
	cp.CommittedAt = nil
	cp.RolledBackAt = nil
	cp.CreatedAt = time.Now().UTC()
	cp.UpdatedAt = cp.CreatedAt
	if err := s.savePlan(&cp); err != nil {
		return nil, err
	}
	if _, err := s.store.AppendEvent("plan.copied", "", cp.ID, map[string]any{"from": src.ID}); err != nil {
		return nil, internalErr(err.Error())
	}
	return &cp, nil
}

// UpdatePlanInput replaces phases on a draft plan, bumping its revision.
type UpdatePlanInput struct {
	Phases []sim.Phase `json:"phases"`
	Label  string      `json:"label,omitempty"`
}

// UpdatePlan edits a draft plan. Old simulation results remain bound to the
// old configuration (they carry their own identity hash) and are never reused
// against the changed phases.
func (s *Service) UpdatePlan(id string, in UpdatePlanInput, expectedRevision int) (*Plan, error) {
	p, err := s.loadPlan(id)
	if err != nil {
		return nil, err
	}
	if p.Status != StateDraft {
		return nil, conflict("PLAN_NOT_DRAFT", "only draft plans can be edited; plan is "+p.Status)
	}
	if expectedRevision != 0 && expectedRevision != p.Revision {
		return nil, conflict("PLAN_REVISION_CONFLICT",
			fmt.Sprintf("revision %d is stale; current is %d", expectedRevision, p.Revision))
	}
	cur, err := s.GetZone(p.CurrentZoneID)
	if err != nil {
		return nil, err
	}
	cand, err := s.GetZone(p.CandidateZoneID)
	if err != nil {
		return nil, err
	}
	rebuild := CreatePlanInput{
		CurrentZoneID: cur.ID, CandidateZoneID: cand.ID, Phases: in.Phases,
	}
	if err := validatePhases(rebuild.Phases, p.Changes); err != nil {
		return nil, err
	}
	p.Phases = in.Phases
	p.Findings = dns.ValidateCandidate(cur.zone, cand.zone)
	p.Revision++
	if err := s.savePlan(p); err != nil {
		return nil, err
	}
	if _, err := s.store.AppendEvent("plan.updated", "", p.ID, map[string]any{
		"revision": p.Revision, "blocked": p.Blocked(),
	}); err != nil {
		return nil, internalErr(err.Error())
	}
	return p, nil
}

func validatePhases(phases []sim.Phase, changes []dns.Change) error {
	changeKeys := map[string]bool{}
	for _, c := range changes {
		changeKeys[c.Name+" "+c.Type] = true
	}
	seenKey := map[string]bool{}
	covered := map[string]bool{}
	for i, ph := range phases {
		if strings.TrimSpace(ph.Name) == "" {
			return invalid("PHASE_NAME_MISSING", fmt.Sprintf("phase %d has no name", i))
		}
		if ph.MinHoldSeconds < 0 {
			return invalid("PHASE_HOLD_NEGATIVE", "min hold cannot be negative: "+ph.Name)
		}
		if len(ph.ChangedKeys) == 0 {
			return invalid("PHASE_KEYS_EMPTY", "phase changes nothing: "+ph.Name)
		}
		for _, k := range ph.ChangedKeys {
			if !changeKeys[k] {
				return invalid("PHASE_KEY_UNCHANGED",
					fmt.Sprintf("phase %q may not change %s: not part of diff", ph.Name, k))
			}
			tok := ph.Name + "|" + k
			if seenKey[tok] {
				return invalid("PHASE_KEY_DUPLICATE", fmt.Sprintf("key %s repeated in %q", k, ph.Name))
			}
			seenKey[tok] = true
			covered[k] = true
		}
	}
	for k := range changeKeys {
		if !covered[k] {
			return invalid("CHANGE_NOT_PHASED", "changed RRset not assigned to a phase: "+k)
		}
	}
	return nil
}

// planFingerprint hashes the phase configuration so simulations stay bound to
// the exact plan revision they were generated from.
func planFingerprint(p *Plan) string {
	parts := []string{p.CurrentFingerprint, p.CandidateFingerprint}
	for _, ph := range p.Phases {
		keys := append([]string(nil), ph.ChangedKeys...)
		sort.Strings(keys)
		parts = append(parts, ph.Name+"|"+strings.Join(keys, ",")+"|"+fmt.Sprint(ph.MinHoldSeconds))
	}
	h := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(h[:])
}
