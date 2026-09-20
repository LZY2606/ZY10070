package sim

import (
	"zonesim/internal/dns"
)

// buildSchedule turns plan phases + decisions into absolute phase timing.
// Decisions may only move a phase later than its earliest legal time.
func buildSchedule(in Input, auths []AuthNode) ([]PhaseTiming, int) {
	sched := make([]PhaseTiming, len(in.Plan.Phases))
	rollbackAt := 0
	decisionByPhase := map[int]Decision{}
	var rollbacks []Decision
	for _, d := range in.Decisions {
		if d.Action == "rollback" {
			rollbacks = append(rollbacks, d)
			continue
		}
		decisionByPhase[d.PhaseIndex] = d
	}
	slowest := 0
	for _, a := range auths {
		if a.DelaySec > slowest {
			slowest = a.DelaySec
		}
	}
	t := 0
	for i, ph := range in.Plan.Phases {
		earliest := t + ph.MinObserveSec
		decided := earliest
		if d, ok := decisionByPhase[i]; ok && d.AtSec >= earliest {
			decided = d.AtSec
		}
		sched[i] = PhaseTiming{
			Index: i, Name: ph.Name, EarliestSec: earliest, DecidedSec: decided,
			AppliedAtSec: decided, StableAtSec: decided + slowest,
		}
		t = decided
	}
	if len(rollbacks) > 0 {
		latest := 0
		for _, d := range rollbacks {
			if d.AtSec > latest {
				latest = d.AtSec
			}
		}
		rollbackAt = latest
	}
	return sched, rollbackAt
}

func buildEvents(sched []PhaseTiming, auths []AuthNode, zones []*dns.Zone, rollbackAt int) []Event {
	var ev []Event
	fp := func(i int) string {
		if i >= 0 && i < len(zones) {
			return zones[i].Fingerprint()
		}
		return ""
	}
	for _, pt := range sched {
		for _, a := range auths {
			ev = append(ev, Event{
				AtSec: pt.DecidedSec + a.DelaySec, AuthNode: a.ID,
				FromZoneFp: fp(pt.Index), ToZoneFp: fp(pt.Index + 1),
				PhaseIndex: pt.Index, Kind: "phase",
			})
		}
	}
	if rollbackAt > 0 {
		for _, a := range auths {
			ev = append(ev, Event{
				AtSec: rollbackAt + a.DelaySec, AuthNode: a.ID,
				FromZoneFp: fp(len(zones) - 1), ToZoneFp: fp(0),
				PhaseIndex: -1, Kind: "rollback",
			})
		}
	}
	sortEvents(ev)
	return ev
}
