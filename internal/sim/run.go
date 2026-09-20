package sim

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"

	"zonesim/internal/dns"
)

// Input assembles everything the engine needs.
type Input struct {
	Base      *dns.Zone
	Plan      dns.Plan
	Params    Parameters
	Decisions []Decision
}

type cacheEntry struct {
	answer   dns.Answer
	expireAt int64 // local node clock seconds
	negative bool
}

type authState struct {
	node    AuthNode
	current *dns.Zone
	fp      string
}

// Run executes a deterministic simulation.
func Run(in Input) (*Result, error) {
	in.Params.Defaults()
	base := in.Base
	if base == nil {
		return nil, fmt.Errorf("base zone required")
	}

	// Independent seeded streams so fleet shape never depends on query count.
	rng := rand.New(rand.NewSource(in.Params.Seed))
	auths := make([]AuthNode, in.Params.AuthoritativeNodes)
	for i := range auths {
		auths[i] = AuthNode{
			ID:           fmt.Sprintf("auth-%d", i+1),
			DelaySec:     rng.Intn(in.Params.MaxAuthDelaySec + 1),
			ClockSkewSec: rng.Intn(2*in.Params.MaxClockSkewSec+1) - in.Params.MaxClockSkewSec,
		}
	}
	recvs := make([]RecvNode, in.Params.RecursiveNodes)
	for i := range recvs {
		recvs[i] = RecvNode{
			ID:           fmt.Sprintf("rec-%d", i+1),
			DelaySec:     rng.Intn(in.Params.MaxRecvDelaySec + 1),
			ClockSkewSec: rng.Intn(2*in.Params.MaxClockSkewSec+1) - in.Params.MaxClockSkewSec,
		}
	}

	// Effective zone for each phase and the final tail.
	zones := make([]*dns.Zone, len(in.Plan.Phases)+1)
	zones[0] = base
	for i, ph := range in.Plan.Phases {
		z, err := dns.ApplyPhase(zones[i], ph)
		if err != nil {
			return nil, err
		}
		zones[i+1] = z
	}

	// Schedule phase applications from decisions (or earliest time).
	schedule, rollbackAt := buildSchedule(in, auths)

	// Event list for evidence.
	events := buildEvents(schedule, auths, zones, rollbackAt)

	// Monitored queries: derive from all changed records plus extras.
	queries := deriveQueries(in.Plan, in.Params.ExtraQueries)
	normQueries(queries)

	// Horizon covers slowest propagation plus worst-case cached TTL tail.
	stableFrom := 0
	for _, pt := range schedule {
		if pt.StableAtSec > stableFrom {
			stableFrom = pt.StableAtSec
		}
	}
	if rollbackAt > 0 {
		stableFrom = rollbackAt + maxAuthDelay(auths)
	}
	maxTTL := maxZoneTTL(base)
	for _, z := range zones[1:] {
		if t := maxZoneTTL(z); t > maxTTL {
			maxTTL = t
		}
	}
	horizon := stableFrom + maxTTL + in.Params.ProbeIntervalSec + 1
	if horizon < in.Params.ProbeIntervalSec*4 {
		horizon = in.Params.ProbeIntervalSec * 4
	}

	res := &Result{
		Params:        in.Params,
		Queries:       queries,
		PhaseSchedule: schedule,
		AuthNodes:     auths,
		RecvNodes:     recvs,
		Events:        events,
		Traces:        []QueryTrace{},
		Convergence:   []Convergence{},
		HorizonSec:    horizon,
		StableFromSec: stableFrom,
		Decisions:     append([]Decision(nil), in.Decisions...),
		BaseZoneFp:    base.Fingerprint(),
	}

	simulate(res, zones, schedule, rollbackAt, auths, recvs, queries)
	res.EarliestConverged = computeConvergence(res, queries, zones, rollbackAt)
	return res, nil
}

func maxAuthDelay(auths []AuthNode) int {
	m := 0
	for _, a := range auths {
		if a.DelaySec > m {
			m = a.DelaySec
		}
	}
	return m
}

func maxZoneTTL(z *dns.Zone) int {
	m := 0
	for _, rr := range z.Records {
		if rr.TTL > m {
			m = rr.TTL
		}
	}
	if z.SOA != nil && z.SOA.Minimum > m {
		m = z.SOA.Minimum
	}
	return m
}

// deriveQueries builds monitored (name,type) pairs from changed records.
func deriveQueries(plan dns.Plan, extras []Query) []Query {
	seen := map[string]bool{}
	var out []Query
	add := func(q Query) {
		q.Name = strings.TrimSuffix(strings.ToLower(q.Name), ".")
		q.Type = strings.ToUpper(q.Type)
		k := q.Name + "|" + q.Type
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, q)
	}
	for _, ph := range plan.Phases {
		for _, op := range ph.Operations {
			t := strings.ToUpper(op.Type)
			qt := t
			if t == "RRSIG" && len(op.Data) > 0 {
				qt = strings.ToUpper(op.Data[0])
			}
			// Skip meta rrtypes and literal wildcard owners (wildcards are
			// observed through the concrete synthesized names via extra queries).
			if t == "NS" || t == "SOA" || t == "RRSIG" {
				continue
			}
			if strings.HasPrefix(strings.ToLower(op.Name), "*.") {
				continue
			}
			add(Query{Name: op.Name, Type: qt})
		}
	}
	for _, q := range extras {
		add(q)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Type < out[j].Type
	})
	return out
}
