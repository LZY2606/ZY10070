package sim

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
)

// serverTimeline holds, for one authoritative server, the ordered seconds at
// which any RRset changes and the full record snapshot in force at each point.
type serverTimeline struct {
	serverID string
	seconds  []int
	snaps    []*snapshot
}

// snapshot is an RRset-keyed record set at one instant on one server.
type snapshot struct {
	records map[string][]recordView
	sigs    map[string][]recordView
}

func copyRecords(m map[string][]recordView) map[string][]recordView {
	cp := make(map[string][]recordView, len(m))
	for k, v := range m {
		cp[k] = append([]recordView(nil), v...)
	}
	return cp
}

func snapshotFrom(s *snapshot) *snapshot {
	return &snapshot{records: copyRecords(s.records), sigs: copyRecords(s.sigs)}
}

type keyedRecords struct {
	key     string
	records []recordView
	sigs    []recordView
}

func baseSnapshot(baseRecords []keyedRecords) *snapshot {
	rec := map[string][]recordView{}
	sig := map[string][]recordView{}
	for _, kr := range baseRecords {
		rec[kr.key] = kr.records
		sig[kr.key] = kr.sigs
	}
	return &snapshot{records: rec, sigs: sig}
}

type recordView struct {
	name     string
	typ      string
	ttl      uint32
	data     string
	rrsig    bool
	sigStart int64
	sigEnd   int64
	sigTag   uint16
}

type delayEvent struct {
	at        int
	key       string
	after     []recordView
	afterSigs []recordView
	exists    bool
}

type changeEntry struct {
	base       []recordView
	baseSigs   []recordView
	target     []recordView
	targetSigs []recordView
}

type changeMap map[string]changeEntry

// seededRNG is a deterministic LCG; a given seed always replays identically.
type seededRNG struct{ state uint64 }

func newRNG(seed int64, salt string) *seededRNG {
	h := fnv.New64a()
	fmt.Fprintf(h, "%d|%s", seed, salt)
	return &seededRNG{state: h.Sum64() | 1}
}

func (r *seededRNG) intn(n int) int {
	if n <= 0 {
		return 0
	}
	r.state = r.state*6364136223846793005 + 1442695040888963407
	return int((r.state >> 33) % uint64(n))
}

func hashMod(salt string, seed int64, mod int) int {
	h := fnv.New64a()
	fmt.Fprintf(h, "%d|%s", seed, salt)
	return int(h.Sum64() % uint64(mod))
}

func serverDelay(cfg Config, serverID, salt, key string) int {
	rng := newRNG(cfg.Seed, salt+"|"+serverID+"|"+key)
	return 1 + rng.intn(cfg.MaxDelaySeconds)
}

func preferredServer(cfg Config, nodeID string) string {
	idx := hashMod("pref|"+nodeID, cfg.Seed, len(cfg.AuthServers))
	return cfg.AuthServers[idx]
}

func phaseStarts(cfg Config) []int {
	starts := make([]int, len(cfg.Phases))
	cursor := 0
	for i, p := range cfg.Phases {
		cursor += p.MinHoldSeconds
		starts[i] = cursor
	}
	return starts
}

func makeChangeMap(base, target []keyedRecords) changeMap {
	bm := map[string][]recordView{}
	tm := map[string][]recordView{}
	bs := map[string][]recordView{}
	ts := map[string][]recordView{}
	for _, kr := range base {
		bm[kr.key] = kr.records
		bs[kr.key] = kr.sigs
	}
	for _, kr := range target {
		tm[kr.key] = kr.records
		ts[kr.key] = kr.sigs
	}
	out := changeMap{}
	keys := map[string]bool{}
	for k := range bm {
		keys[k] = true
	}
	for k := range tm {
		keys[k] = true
	}
	for k := range keys {
		bv, bok := bm[k]
		tv, tok := tm[k]
		if bok && tok && sameViews(bv, tv) && sameViews(bs[k], ts[k]) {
			continue
		}
		out[k] = changeEntry{
			base: bv, baseSigs: bs[k],
			target: tv, targetSigs: ts[k],
		}
	}
	return out
}

func sameViews(a, b []recordView) bool {
	if len(a) != len(b) {
		return false
	}
	ka := make([]string, len(a))
	kb := make([]string, len(b))
	for i, r := range a {
		ka[i] = viewSig(r)
	}
	for i, r := range b {
		kb[i] = viewSig(r)
	}
	sort.Strings(ka)
	sort.Strings(kb)
	return strings.Join(ka, ",") == strings.Join(kb, ",")
}

func viewSig(r recordView) string {
	return fmt.Sprintf("%s|%d|%s|%d|%d|%d", r.typ, r.ttl, r.data, r.sigStart, r.sigEnd, r.sigTag)
}

func buildTimelines(cfg Config, base, target []keyedRecords, changes changeMap) map[string]*serverTimeline {
	tls := map[string]*serverTimeline{}
	starts := phaseStarts(cfg)

	for _, server := range cfg.AuthServers {
		events := map[int]map[string]delayEvent{}
		add := func(at int, ev delayEvent) {
			if events[at] == nil {
				events[at] = map[string]delayEvent{}
			}
			events[at][ev.key] = ev
		}
		for phaseIdx, phase := range cfg.Phases {
			for _, key := range phase.ChangedKeys {
				ch, ok := changes[key]
				if !ok {
					continue
				}
				d := serverDelay(cfg, server, fmt.Sprintf("phase:%d:%s", phaseIdx, phase.Name), key)
				add(starts[phaseIdx]+d, delayEvent{
					at: starts[phaseIdx] + d, key: key,
					after: ch.target, afterSigs: ch.targetSigs, exists: ch.target != nil,
				})
			}
		}
		if cfg.RollbackAtSeconds > 0 {
			seenKey := map[string]bool{}
			for _, phase := range cfg.Phases {
				for _, key := range phase.ChangedKeys {
					if seenKey[key] {
						continue
					}
					seenKey[key] = true
					ch := changes[key]
					d := serverDelay(cfg, server, "rollback", key)
					add(cfg.RollbackAtSeconds+d, delayEvent{
						at: cfg.RollbackAtSeconds + d, key: key,
						after: ch.base, afterSigs: ch.baseSigs, exists: ch.base != nil,
					})
				}
			}
		}

		times := make([]int, 0, len(events))
		for t := range events {
			times = append(times, t)
		}
		sort.Ints(times)
		tl := &serverTimeline{serverID: server}
		cur := baseSnapshot(toList(base))
		tl.seconds = append(tl.seconds, 0)
		tl.snaps = append(tl.snaps, snapshotFrom(cur))
		for _, t := range times {
			for _, ev := range events[t] {
				if ev.exists {
					cur.records[ev.key] = append([]recordView(nil), ev.after...)
					cur.sigs[ev.key] = append([]recordView(nil), ev.afterSigs...)
				} else {
					delete(cur.records, ev.key)
					delete(cur.sigs, ev.key)
				}
			}
			tl.seconds = append(tl.seconds, t)
			tl.snaps = append(tl.snaps, snapshotFrom(cur))
		}
		tls[server] = tl
	}
	return tls
}

func toList(kr []keyedRecords) []keyedRecords { return kr }

func (tl *serverTimeline) snapshotAt(t int) *snapshot {
	idx := 0
	for i, sec := range tl.seconds {
		if sec <= t {
			idx = i
		} else {
			break
		}
	}
	return tl.snaps[idx]
}

func (tl *serverTimeline) lastChange() int {
	if len(tl.seconds) <= 1 {
		return 0
	}
	return tl.seconds[len(tl.seconds)-1]
}
