package service

import (
	"testing"

	"zonesim/internal/sim"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	svc, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func importPair(t *testing.T, svc *Service) (cur, cand *ZoneDoc) {
	t.Helper()
	cur, err := svc.ImportZone(ImportZoneInput{Origin: "example.", Text: `$ORIGIN example.
$TTL 300
@ IN SOA ns1.example. admin.example. 2026010100 7200 3600 1209600 300
@ IN NS ns1.example.
ns1 IN A 192.0.2.10
www IN A 192.0.2.20
old IN A 192.0.2.99
`})
	if err != nil {
		t.Fatal(err)
	}
	cand, err = svc.ImportZone(ImportZoneInput{Origin: "example.", Text: `$ORIGIN example.
$TTL 300
@ IN SOA ns1.example. admin.example. 2026011500 7200 3600 1209600 300
@ IN NS ns1.example.
ns1 IN A 192.0.2.10
www IN A 192.0.2.21
`})
	if err != nil {
		t.Fatal(err)
	}
	return cur, cand
}

func validPlan(t *testing.T, svc *Service, cur, cand *ZoneDoc) *Plan {
	t.Helper()
	p, err := svc.CreatePlan(CreatePlanInput{
		CurrentZoneID: cur.ID, CandidateZoneID: cand.ID,
		Phases: []sim.Phase{{Name: "p1", MinHoldSeconds: 0, ChangedKeys: []string{
			"www.example. A", "old.example. A", "example. SOA",
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPlanBlocksAndCommits(t *testing.T) {
	svc := newTestService(t)
	bundle, err := svc.SeedDemo()
	if err != nil {
		t.Fatal(err)
	}
	if !bundle.BadPlan.Blocked() {
		t.Fatal("bad demo plan should be blocked")
	}
	if _, err := svc.CommitPlan(bundle.BadPlan.ID); err == nil {
		t.Fatal("commit of blocked plan must fail")
	} else if se, ok := err.(*Error); !ok || se.Class != ClassConflict {
		t.Fatalf("expected conflict error, got %v", err)
	}
	committed, err := svc.CommitPlan(bundle.Plan.ID)
	if err != nil {
		t.Fatalf("valid plan should commit: %v", err)
	}
	if committed.Status != StateCommitted {
		t.Fatalf("status = %s", committed.Status)
	}
	// Editing a committed plan is a state conflict.
	if _, err := svc.UpdatePlan(committed.ID, UpdatePlanInput{Phases: committed.Phases}, committed.Revision); err == nil {
		t.Fatal("editing committed plan must fail")
	}
}

func TestSimulationReuseAndConvergence(t *testing.T) {
	svc := newTestService(t)
	cur, cand := importPair(t, svc)
	p := validPlan(t, svc, cur, cand)
	if _, err := svc.CommitPlan(p.ID); err != nil {
		t.Fatal(err)
	}
	in := RunSimulationInput{
		PlanID: p.ID, Seed: 7,
		Probes:          simQuery("www.example.", "A"),
		MaxDelaySeconds: 10, QueryEvery: 10, Horizon: 3600,
	}
	first, reused, err := svc.RunSimulation(in)
	if err != nil {
		t.Fatal(err)
	}
	if reused {
		t.Fatal("first simulation cannot be a replay")
	}
	second, reused, err := svc.RunSimulation(in)
	if err != nil {
		t.Fatal(err)
	}
	if !reused || first.ID != second.ID {
		t.Fatal("identical candidate run must reuse deterministic result")
	}
	if !first.Report.ConvergedWithin {
		t.Fatal("expected convergence within horizon")
	}
	view, err := svc.ViewAt(first.ID, simQ("www.example.", "A"), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Samples) == 0 {
		t.Fatal("slider returned no samples")
	}
}

func TestPlanEditInvalidatesOldSimulations(t *testing.T) {
	svc := newTestService(t)
	cur, cand := importPair(t, svc)
	// Build a two-phase plan so we can edit it.
	p, err := svc.CreatePlan(CreatePlanInput{
		CurrentZoneID: cur.ID, CandidateZoneID: cand.ID,
		Phases: []sim.Phase{
			{Name: "a", MinHoldSeconds: 0, ChangedKeys: []string{"www.example. A", "example. SOA"}},
			{Name: "b", MinHoldSeconds: 100, ChangedKeys: []string{"old.example. A"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	in := RunSimulationInput{PlanID: p.ID, Seed: 1, Probes: simQuery("www.example.", "A"),
		MaxDelaySeconds: 5, QueryEvery: 10, Horizon: 3600}
	first, _, err := svc.RunSimulation(in)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := svc.UpdatePlan(p.ID, UpdatePlanInput{Phases: []sim.Phase{
		{Name: "a", MinHoldSeconds: 600, ChangedKeys: []string{"www.example. A", "example. SOA"}},
		{Name: "b", MinHoldSeconds: 500, ChangedKeys: []string{"old.example. A"}},
	}}, p.Revision)
	if err != nil {
		t.Fatal(err)
	}
	in.PlanID = updated.ID
	second, reused, err := svc.RunSimulation(in)
	if err != nil {
		t.Fatal(err)
	}
	if reused || second.ID == first.ID {
		t.Fatal("phase edit must produce a new simulation; old result stays fingerprint-bound")
	}
}

func TestExportBundleComplete(t *testing.T) {
	svc := newTestService(t)
	cur, cand := importPair(t, svc)
	p := validPlan(t, svc, cur, cand)
	if _, err := svc.CommitPlan(p.ID); err != nil {
		t.Fatal(err)
	}
	doc, _, err := svc.RunSimulation(RunSimulationInput{
		PlanID: p.ID, Seed: 3, Probes: simQuery("www.example.", "A"),
		MaxDelaySeconds: 5, QueryEvery: 10, Horizon: 1800,
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := svc.ExportSimulation(doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Plan == nil || bundle.Simulation == nil || bundle.CurrentZone == nil || bundle.CandidateZone == nil {
		t.Fatal("export missing key evidence")
	}
	if len(bundle.Events) == 0 {
		t.Fatal("export missing event journal")
	}
	if len(bundle.Plan.Decisions) == 0 {
		// Decisions are populated during validate; run it then re-export.
		if _, err := svc.ValidatePlan(p.ID); err != nil {
			t.Fatal(err)
		}
		bundle, _ = svc.ExportSimulation(doc.ID)
		if len(bundle.Plan.Decisions) == 0 {
			t.Fatal("export missing phase decisions")
		}
	}
}

func TestInvalidInputClassified(t *testing.T) {
	svc := newTestService(t)
	if _, err := svc.ImportZone(ImportZoneInput{Text: ""}); err == nil {
		t.Fatal("empty zone should fail")
	} else if se, ok := err.(*Error); !ok || se.Class != ClassInvalid {
		t.Fatalf("expected invalid_request, got %v", err)
	}
}
