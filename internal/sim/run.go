package sim

import (
	"sort"
	"time"

	"zonesim/internal/dns"
)

// zoneToKeyed converts a parsed zone into flat RRset buckets. RRSIG records
// are stored under the key they cover.
func zoneToKeyed(z *dns.Zone) []keyedRecords {
	byKey := map[string][]dns.Record{}
	for _, r := range z.Records {
		if r.Type == "RRSIG" {
			continue
		}
		k := r.Key()
		byKey[k] = append(byKey[k], r)
	}
	out := make([]keyedRecords, 0, len(byKey))
	for k, recs := range byKey {
		kr := keyedRecords{key: k}
		for _, r := range recs {
			kr.records = append(kr.records, recordView{name: r.Name, typ: r.Type, ttl: r.TTL, data: r.Data})
		}
		for _, s := range z.SignaturesAt(recs[0].Name) {
			if s.RRSIG != nil && s.RRSIG.TypeCovered == recs[0].Type {
				kr.sigs = append(kr.sigs, recordView{
					name: recs[0].Name, typ: "RRSIG", ttl: s.TTL,
					sigStart: s.RRSIG.Inception.Unix(), sigEnd: s.RRSIG.Expiration.Unix(),
					sigTag: s.RRSIG.KeyTag,
				})
			}
		}
		out = append(out, kr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

func materialize(origin string, snap *snapshot) *dns.Zone {
	z := &dns.Zone{Origin: origin}
	keys := make([]string, 0, len(snap.records))
	for k := range snap.records {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, rv := range snap.records[k] {
			z.Records = append(z.Records, dns.Record{Name: rv.name, Type: rv.typ, TTL: rv.ttl, Data: rv.data})
		}
		for _, sv := range snap.sigs[k] {
			sig := &dns.RRSIG{
				TypeCovered: typeOfKey(k),
				Inception:   time.Unix(sv.sigStart, 0).UTC(),
				Expiration:  time.Unix(sv.sigEnd, 0).UTC(),
				KeyTag:      sv.sigTag,
				SignerName:  origin,
				TTL:         sv.ttl,
			}
			z.Records = append(z.Records, dns.Record{Name: nameOfKey(k), Type: "RRSIG", TTL: sv.ttl, RRSIG: sig})
		}
	}
	return z
}

func typeOfKey(k string) string {
	for i := len(k) - 1; i >= 0; i-- {
		if k[i] == ' ' {
			return k[i+1:]
		}
	}
	return ""
}

func nameOfKey(k string) string {
	for i := len(k) - 1; i >= 0; i-- {
		if k[i] == ' ' {
			return k[:i]
		}
	}
	return k
}

// cacheEntry is a recursive node's stored answer.
type cacheEntry struct {
	answer    *dns.Answer
	fetchedAt int
	ttl       uint32
	server    string
	negative  bool
}

func (e *cacheEntry) validAt(t int) bool {
	if e == nil || e.ttl == 0 {
		return false
	}
	return t < e.fetchedAt+int(e.ttl)
}

type nodeRuntime struct {
	cfg    NodeConfig
	server string
	cache  map[string]*cacheEntry
}

func newNodeRuntime(cfg Config, nc NodeConfig) *nodeRuntime {
	return &nodeRuntime{
		cfg:    nc,
		server: preferredServer(cfg, nc.ID),
		cache:  map[string]*cacheEntry{},
	}
}

func securityFor(ans *dns.Answer, signedInZone bool, nodeTime time.Time) string {
	if len(ans.Signatures) == 0 {
		if signedInZone {
			// RRset is expected to be signed in this zone state but the
			// server view exposed no valid signatures: bogus.
			return Bogus
		}
		return Insecure
	}
	for _, s := range ans.Signatures {
		if s.RRSIG == nil {
			continue
		}
		lo := s.RRSIG.Inception
		hi := s.RRSIG.Expiration
		if (nodeTime.After(lo) || nodeTime.Equal(lo)) && (nodeTime.Before(hi) || nodeTime.Equal(hi)) {
			return Secure
		}
	}
	return Bogus
}

// queryAt performs one node query at simulation second t.
func queryAt(cfg Config, tls map[string]*serverTimeline, origin string, rt *nodeRuntime, q Query, t int) *Sample {
	key := q.key()
	now := Epoch.Add(time.Duration(t) * time.Second)
	nodeNow := now.Add(time.Duration(rt.cfg.SkewSeconds) * time.Second)

	if e := rt.cache[key]; e.validAt(t) {
		src := SourceCache
		if e.negative {
			src = SourceNegative
		}
		return sampleFromAnswer(e.answer, t, src, e.server, nodeNow)
	}
	tl := tls[rt.server]
	z := materialize(origin, tl.snapshotAt(t))
	ans := dns.Resolve(z, q.QName, q.QType)
	negative := ans.Status == dns.StatusNXDOMAIN || ans.Status == dns.StatusNODATA
	ttl := ans.TTL
	rt.cache[key] = &cacheEntry{answer: ans, fetchedAt: t, ttl: ttl, server: rt.server, negative: negative}
	return sampleFromAnswer(ans, t, SourceAuthority, rt.server, nodeNow)
}

func sampleFromAnswer(ans *dns.Answer, at int, source, server string, nodeNow time.Time) *Sample {
	signedInZone := len(ans.Signatures) > 0
	sec := securityFor(ans, signedInZone, nodeNow)
	return &Sample{
		AtSeconds: at, Source: source, Status: ans.Status, Security: sec,
		Wildcard: ans.Wildcard, TTL: ans.TTL, Records: append([]dns.Record(nil), ans.Records...),
		Reason: ans.Reason, Server: server,
	}
}

func answerIdentity(status, security, wildcard string, records []dns.Record) string {
	parts := make([]string, 0, len(records)+3)
	parts = append(parts, status, security, wildcard)
	rs := make([]string, 0, len(records))
	for _, r := range records {
		rs = append(rs, r.Name+"|"+r.Type+"|"+r.Data)
	}
	sort.Strings(rs)
	return joinAll(append(parts, rs...))
}

func joinAll(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ";"
		}
		out += p
	}
	return out
}

func sampleIdentity(s *Sample) string {
	return answerIdentity(s.Status, s.Security, s.Wildcard, s.Records)
}

func queryTimes(cfg Config) []int {
	step := cfg.QueryEverySeconds
	if step <= 0 {
		step = 30
	}
	var out []int
	for t := 0; t <= cfg.HorizonSeconds; t += step {
		out = append(out, t)
	}
	if out[len(out)-1] != cfg.HorizonSeconds {
		out = append(out, cfg.HorizonSeconds)
	}
	return out
}

// collapse turns sampled points into half-open intervals. Constant answers
// merge into one interval whose source reflects the query at its start; when
// a TTL expiry triggers an authority re-fetch with the same data, a zero-width
// authority instant is preserved so the evidence trail never hides a fetch.
func collapse(seq []intervalPoint, horizon int) []Interval {
	if len(seq) == 0 {
		return nil
	}
	var out []Interval
	start := seq[0].at
	curID := seq[0].sample.AnswerFingerprint()
	cur := seq[0]
	for i := 1; i < len(seq); i++ {
		id := seq[i].sample.AnswerFingerprint()
		same := id == curID
		reauth := same && seq[i].sample.Source == SourceAuthority && cur.sample.Source != SourceAuthority
		if !same {
			out = append(out, Interval{From: start, To: seq[i].at, Source: cur.sample.Source, Sample: cur.sample})
			start = seq[i].at
		} else if reauth {
			// Cache window ends exactly at the re-fetch instant.
			out = append(out, Interval{From: start, To: seq[i].at, Source: cur.sample.Source, Sample: cur.sample})
			start = seq[i].at
		}
		curID = id
		cur = seq[i]
	}
	out = append(out, Interval{From: start, To: horizon, Source: cur.sample.Source, Sample: cur.sample})
	return out
}

type intervalPoint struct {
	at     int
	sample *Sample
}

// Run executes the deterministic simulation for cfg.
func Run(cfg Config, origin string, base, candidate *dns.Zone) *Report {
	baseKR := zoneToKeyed(base)
	targetKR := zoneToKeyed(candidate)
	changes := makeChangeMap(baseKR, targetKR)
	tls := buildTimelines(cfg, baseKR, targetKR, changes)

	times := queryTimes(cfg)
	reports := make([]ProbeReport, 0, len(cfg.Probes))
	lastChange := 0
	readyAt := map[string]int{}
	for server, tl := range tls {
		lc := tl.lastChange()
		readyAt[server] = lc
		if lc > lastChange {
			lastChange = lc
		}
	}

	for _, q := range cfg.Probes {
		pr := ProbeReport{Query: q}
		// Final identity per node is the last query sample in horizon.
		var finalIDs []string
		maxConv := -1
		for _, nc := range cfg.Nodes {
			rt := newNodeRuntime(cfg, nc)
			points := make([]intervalPoint, 0, len(times))
			for _, t := range times {
				s := queryAt(cfg, tls, origin, rt, q, t)
				points = append(points, intervalPoint{at: t, sample: s})
			}
			pr.Series = append(pr.Series, NodeSeries{NodeID: nc.ID, Intervals: collapse(points, cfg.HorizonSeconds)})
			finalIDs = append(finalIDs, points[len(points)-1].sample.AnswerFingerprint())
			// Earliest t >= lastChange from which this node stays at final.
			final := points[len(points)-1].sample.AnswerFingerprint()
			conv := -1
			for i := len(points) - 1; i >= 0; i-- {
				if points[i].sample.AnswerFingerprint() == final {
					if points[i].at >= lastChange {
						conv = points[i].at
					}
				} else {
					break
				}
			}
			if conv > maxConv {
				maxConv = conv
			}
		}
		allSame := true
		for _, id := range finalIDs {
			if id != finalIDs[0] {
				allSame = false
				break
			}
		}
		pr.ConvergedAnswer = finalIDs[0]
		if allSame && maxConv >= 0 {
			pr.ConvergedAt = maxConv
			pr.ConvergedWithin = maxConv <= cfg.HorizonSeconds
		} else {
			pr.ConvergedAt = -1
		}
		reports = append(reports, pr)
	}

	rep := &Report{
		HorizonSeconds:   cfg.HorizonSeconds,
		LastAuthChangeAt: lastChange,
		AuthReadyAt:      readyAt,
		Probes:           reports,
	}
	overall := -1
	all := true
	for _, pr := range reports {
		if !pr.ConvergedWithin {
			all = false
			continue
		}
		if pr.ConvergedAt > overall {
			overall = pr.ConvergedAt
		}
	}
	rep.ConvergedWithin = all && overall >= 0
	if rep.ConvergedWithin {
		rep.ConvergedAt = overall
		rep.FinalStableFrom = overall
	} else {
		rep.ConvergedAt = -1
	}
	return rep
}

// QueryAtProbe returns per-node samples for a specific probe at instant t.
func QueryAtProbe(cfg Config, origin string, base, candidate *dns.Zone, q Query, t int) map[string]*Sample {
	baseKR := zoneToKeyed(base)
	targetKR := zoneToKeyed(candidate)
	changes := makeChangeMap(baseKR, targetKR)
	tls := buildTimelines(cfg, baseKR, targetKR, changes)

	step := cfg.QueryEverySeconds
	if step <= 0 {
		step = 30
	}
	out := map[string]*Sample{}
	for _, nc := range cfg.Nodes {
		rt := newNodeRuntime(cfg, nc)
		for st := 0; st < t; st += step {
			queryAt(cfg, tls, origin, rt, q, st)
		}
		out[nc.ID] = queryAt(cfg, tls, origin, rt, q, t)
	}
	return out
}
