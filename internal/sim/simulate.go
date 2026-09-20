package sim

import (
	"math/rand"

	"zonesim/internal/dns"
)

type recvRuntime struct {
	node  RecvNode
	rng   *rand.Rand
	cache map[string]cacheEntry
}

func simulate(res *Result, zones []*dns.Zone, sched []PhaseTiming, rollbackAt int,
	auths []AuthNode, recvs []RecvNode, queries []Query) {

	runtimes := make([]*recvRuntime, len(recvs))
	for i, rv := range recvs {
		// Per-node stream derived from the master seed: independent but reproducible.
		runtimes[i] = &recvRuntime{
			node:  rv,
			rng:   rand.New(rand.NewSource(res.Params.Seed + int64(i+1)*7919)),
			cache: map[string]cacheEntry{},
		}
	}

	traces := make([]QueryTrace, len(queries))
	for qi, q := range queries {
		traces[qi].Query = q
	}
	grid := res.Params.ProbeIntervalSec
	probe := 0
	for tick := 0; tick <= res.HorizonSec; tick += grid {
		for qi, q := range queries {
			for _, rt := range runtimes {
				view := rt.probe(probe, tick, q, zones, sched, rollbackAt, auths)
				traces[qi].Views = append(traces[qi].Views, view)
			}
		}
		probe++
	}
	res.Traces = traces
}

func (rt *recvRuntime) probe(probeIdx, tick int, q Query,
	zones []*dns.Zone, sched []PhaseTiming, rollbackAt int, auths []AuthNode) NodeView {

	localNow := int64(tick + rt.node.ClockSkewSec)
	key := q.Name + "|" + q.Type
	view := NodeView{ProbeIndex: probeIdx, AtSec: tick}

	if e, ok := rt.cache[key]; ok && localNow < e.expireAt {
		view.Source = "cache"
		if e.negative {
			view.Source = "negative_cache"
		}
		view.Answer = e.answer
		return view
	}
	delete(rt.cache, key)

	// Cache miss: pick an authoritative node from this node's deterministic stream.
	authIdx := int(rt.rng.Int63()) % len(auths)
	if authIdx < 0 {
		authIdx = -authIdx
	}
	// Recursive-side network delay shifts the authority state actually observed.
	fetchTick := tick - rt.node.DelaySec
	if fetchTick < 0 {
		fetchTick = 0
	}
	an := auths[authIdx]
	zoneIdx := effectiveZoneIndex(sched, rollbackAt, an, fetchTick)
	zone := zones[zoneIdx]
	resolver := &dns.Resolver{Zone: zone, Now: localNow + ReferenceEpoch}
	ans := resolver.Resolve(q.Name, q.Type)
	ans.Authority = an.ID
	view.Answer = ans

	negative := ans.Status == "NXDOMAIN" || ans.Status == "NODATA"
	ttl := answerTTL(ans)
	rt.cache[key] = cacheEntry{answer: ans, expireAt: localNow + int64(ttl), negative: negative}
	view.Source = "authoritative"
	return view
}

func answerTTL(a dns.Answer) int {
	if a.NegTTL > 0 {
		return a.NegTTL
	}
	m := 0
	for _, r := range a.Records {
		if m == 0 || r.TTL < m {
			m = r.TTL
		}
	}
	if m == 0 {
		m = 30
	}
	return m
}
