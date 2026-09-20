package sim

import (
	"zonesim/internal/dns"
)

// computeConvergence finds, per query, the earliest probe from which every
// later view equals the final-zone answer. Requiring equality through the end
// guarantees both authoritative convergence and stale-cache expiry.
func computeConvergence(res *Result, queries []Query, zones []*dns.Zone, rollbackAt int) int {
	finalZone := zones[len(zones)-1]
	if rollbackAt > 0 {
		finalZone = zones[0]
	}
	grid := res.Params.ProbeIntervalSec
	nNodes := len(res.RecvNodes)
	earliestAll := 0

	for _, tr := range res.Traces {
		finalAns := (&resolverAt{}).answer(finalZone, tr.Query, ReferenceEpoch+int64(res.HorizonSec))
		canon := finalAns.Canonical()
		conv := Convergence{Query: tr.Query, FinalCanonical: canon, NodeConvergedSec: map[string]int{}}

		probeCount := len(tr.Views) / nNodes
		allSec := 0
		for n := 0; n < nNodes; n++ {
			firstStable := -1
			// Scan backward; once a differing view is seen, the stable suffix starts after it.
			for p := probeCount - 1; p >= 0; p-- {
				v := tr.Views[p*nNodes+n]
				if v.Answer.Canonical() != canon {
					break
				}
				firstStable = p
			}
			if firstStable < 0 {
				conv.NodeConvergedSec[res.RecvNodes[n].ID] = -1
				allSec = -1
				continue
			}
			sec := firstStable * grid
			conv.NodeConvergedSec[res.RecvNodes[n].ID] = sec
			if allSec >= 0 && sec > allSec {
				allSec = sec
			}
		}
		conv.AllConvergedSec = allSec
		res.Convergence = append(res.Convergence, conv)
		if allSec > earliestAll {
			earliestAll = allSec
		}
	}
	return earliestAll
}

var _ = dns.Answer{}
