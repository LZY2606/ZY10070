package service

import (
	"testing"

	"zonesim/internal/dns"
	"zonesim/internal/sim"
)

func TestEarliestForPhaseCumulative(t *testing.T) {
	plan := dns.Plan{Phases: []dns.Phase{
		{Name: "p0", MinObserveSec: 100},
		{Name: "p1", MinObserveSec: 200},
		{Name: "p2", MinObserveSec: 50},
	}}
	if got := EarliestForPhase(plan, nil, 0); got != 100 {
		t.Fatalf("p0 earliest = %d, want 100", got)
	}
	// Phase 0 delayed to 150 -> p1 earliest 350 -> p2 earliest 400.
	dec := []sim.Decision{{PhaseIndex: 0, Action: "proceed", AtSec: 150}}
	if got := EarliestForPhase(plan, dec, 1); got != 350 {
		t.Fatalf("p1 earliest = %d, want 350", got)
	}
	dec = append(dec, sim.Decision{PhaseIndex: 1, Action: "proceed", AtSec: 400})
	if got := EarliestForPhase(plan, dec, 2); got != 450 {
		t.Fatalf("p2 earliest = %d, want 450", got)
	}
}
