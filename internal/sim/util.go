package sim

import "sort"

func sortEvents(ev []Event) {
	sort.SliceStable(ev, func(i, j int) bool {
		if ev[i].AtSec != ev[j].AtSec {
			return ev[i].AtSec < ev[j].AtSec
		}
		return ev[i].AuthNode < ev[j].AuthNode
	})
}

// effectiveZoneIndex returns the zone version an auth node serves at ref time.
func effectiveZoneIndex(sched []PhaseTiming, rollbackAt int, node AuthNode, atSec int) int {
	idx := 0
	for _, pt := range sched {
		applyAt := pt.DecidedSec + node.DelaySec
		if atSec >= applyAt {
			idx = pt.Index + 1
		}
	}
	if rollbackAt > 0 && atSec >= rollbackAt+node.DelaySec {
		idx = 0
	}
	return idx
}
