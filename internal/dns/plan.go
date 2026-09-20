package dns

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Operation is a single record change inside a phase.
type Operation struct {
	Action string   `json:"action"` // upsert | delete
	Name   string   `json:"name"`
	Type   string   `json:"type"`
	TTL    int      `json:"ttl,omitempty"`
	Data   []string `json:"data,omitempty"`
	Raw    string   `json:"raw,omitempty"`

	// RRSIG metadata (populated for type == RRSIG).
	Algorithm  int   `json:"algorithm,omitempty"`
	Labels     int   `json:"labels,omitempty"`
	OrigTTL    int   `json:"orig_ttl,omitempty"`
	Expiration int64 `json:"expiration,omitempty"`
	Inception  int64 `json:"inception,omitempty"`
	KeyTag     int   `json:"keytag,omitempty"`
}

// Phase groups operations that may be applied together.
type Phase struct {
	Name          string      `json:"name"`
	Operations    []Operation `json:"operations"`
	MinObserveSec int         `json:"min_observe_sec"`
}

// Plan describes the staged publication path for one zone.
type Plan struct {
	ZoneName string  `json:"zone_name"`
	Phases   []Phase `json:"phases"`
}

// Block describes a reason publication must be refused.
type Block struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Where   string `json:"where,omitempty"`
}

// ValidatePlan checks every consecutive effective zone transition.
func ValidatePlan(base *Zone, plan Plan) []Block {
	var blocks []Block
	current := base
	for _, ph := range plan.Phases {
		next, err := ApplyPhase(current, ph)
		if err != nil {
			blocks = append(blocks, Block{Code: "invalid_operation", Message: err.Error(), Where: ph.Name})
			continue
		}
		if next.SOA == nil {
			blocks = append(blocks, Block{Code: "invalid_operation", Message: "phase removes apex SOA", Where: ph.Name})
		}
		blocks = append(blocks, ValidateTransition(current, next)...)
		blocks = append(blocks, CheckCNAMELoops(next, ph.Name)...)
		current = next
	}
	return dedupeBlocks(blocks)
}

// ApplyPhase returns a new zone after executing the phase operations.
func ApplyPhase(z *Zone, phase Phase) (*Zone, error) {
	out := &Zone{Origin: z.Origin, SOA: z.SOA, RRSIGs: map[string][]RRSigInfo{}}
	for k, v := range z.RRSIGs {
		out.RRSIGs[k] = append([]RRSigInfo(nil), v...)
	}
	replaced := map[string]bool{}
	var recs []RR
	for _, op := range phase.Operations {
		key := Key(op.Name, op.Type)
		switch op.Action {
		case "upsert":
			replaced[key] = true
			recs = append(recs, RR{Name: op.Name, Type: op.Type, TTL: op.TTL,
				Data: append([]string(nil), op.Data...), Raw: op.Raw})
			if op.Type == "SOA" {
				info, err := parseSOA(op.Data)
				if err != nil {
					return nil, fmt.Errorf("invalid SOA in phase %q: %v", phase.Name, err)
				}
				out.SOA = info
			}
			if op.Type == "RRSIG" {
				covered := strings.ToUpper(op.Data[0])
				sigKey := Key(op.Name, covered)
				info := RRSigInfo{TypeCovered: covered, Algorithm: op.Algorithm, Labels: op.Labels,
					OrigTTL: op.OrigTTL, Expiration: op.Expiration, Inception: op.Inception, KeyTag: op.KeyTag}
				out.RRSIGs[sigKey] = append(out.RRSIGs[sigKey], info)
			}
		case "delete":
			replaced[key] = true
			delete(out.RRSIGs, key)
		default:
			return nil, fmt.Errorf("unknown action %q in phase %q", op.Action, phase.Name)
		}
	}
	for _, rr := range z.Records {
		if replaced[Key(rr.Name, rr.Type)] {
			continue
		}
		recs = append(recs, rr)
	}
	out.Records = recs
	out.index()
	return out, nil
}

// ValidateTransition checks serial rollback, broken delegations and RRSIG
// window disjointness between two consecutive effective zones.
func ValidateTransition(old, next *Zone) []Block {
	var blocks []Block
	if old.SOA != nil && next.SOA != nil && serialLess(next.SOA.Serial, old.SOA.Serial) {
		blocks = append(blocks, Block{Code: "serial_rollback",
			Message: fmt.Sprintf("SOA serial regresses from %d to %d", old.SOA.Serial, next.SOA.Serial)})
	}
	blocks = append(blocks, checkBrokenDelegations(next)...)
	blocks = append(blocks, checkRRSIGOverlap(old, next)...)
	return blocks
}

// serialLess implements RFC 1982 ordering for 32-bit serials.
func serialLess(a, b uint32) bool {
	if a == b {
		return false
	}
	d := int64(a) - int64(b)
	if d < 0 {
		d = -d
	}
	if d >= 1<<31 {
		return a > b
	}
	return a < b
}

func checkBrokenDelegations(z *Zone) []Block {
	var blocks []Block
	for _, name := range sortedDelegations(z) {
		targets := nsTargets(z, name)
		if len(targets) == 0 {
			blocks = append(blocks, Block{Code: "broken_delegation",
				Message: fmt.Sprintf("delegation %q has no NS target", name), Where: name})
			continue
		}
		if !delegationGluePresent(z, name, targets) {
			blocks = append(blocks, Block{Code: "broken_delegation",
				Message: fmt.Sprintf("delegation %q has no A/AAAA (or in-zone glue) for its nameservers", name),
				Where:   name})
		}
	}
	return blocks
}

func sortedDelegations(z *Zone) []string {
	out := make([]string, 0, len(z.deleg))
	for n := range z.deleg {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func nsTargets(z *Zone, name string) []string {
	var out []string
	for _, rr := range z.RecordsAt(name) {
		if rr.Type == "NS" {
			out = append(out, rr.Data[0])
		}
	}
	return out
}

func delegationGluePresent(z *Zone, name string, targets []string) bool {
	for _, t := range targets {
		if !strings.HasSuffix(t, "."+name) && t != name {
			return true // out-of-bailiwick NS needs no glue in this zone
		}
		if z.Lookup(t, "A") != nil || z.Lookup(t, "AAAA") != nil {
			return true
		}
	}
	return false
}

// checkRRSIGOverlap flags rrset signatures whose validity windows do not
// intersect between consecutive versions.
func checkRRSIGOverlap(old, next *Zone) []Block {
	var blocks []Block
	keys := map[string]bool{}
	for k := range next.RRSIGs {
		keys[k] = true
	}
	for k := range old.RRSIGs {
		keys[k] = true
	}
	for k := range keys {
		o := old.RRSIGs[k]
		n := next.RRSIGs[k]
		if len(o) == 0 || len(n) == 0 {
			continue
		}
		if !windowsIntersect(o, n) {
			parts := strings.SplitN(k, "|", 2)
			blocks = append(blocks, Block{Code: "signature_window_disjoint",
				Message: fmt.Sprintf("RRSIG windows for %s %s do not overlap between successive zones", parts[0], parts[1]),
				Where:   k})
		}
	}
	return blocks
}

func windowsIntersect(a, b []RRSigInfo) bool {
	for _, x := range a {
		for _, y := range b {
			if x.Inception <= y.Expiration && y.Inception <= x.Expiration {
				return true
			}
		}
	}
	return false
}

// CheckCNAMELoops detects cycles reachable by following CNAME records.
func CheckCNAMELoops(z *Zone, phaseName string) []Block {
	var blocks []Block
	starters := map[string]bool{}
	for _, rr := range z.Records {
		if rr.Type == "CNAME" {
			starters[rr.Name] = true
		}
	}
	for start := range starters {
		path := []string{}
		index := map[string]int{}
		cur := start
		for {
			if idx, ok := index[cur]; ok {
				cycle := append(append([]string{}, path[idx:]...), cur)
				blocks = append(blocks, Block{Code: "cname_loop",
					Message: "CNAME cycle: " + strings.Join(cycle, " -> "), Where: phaseName})
				break
			}
			index[cur] = len(path)
			path = append(path, cur)
			c := z.Lookup(cur, "CNAME")
			if len(c) == 0 || len(path) > 256 {
				if len(path) > 256 {
					blocks = append(blocks, Block{Code: "cname_loop", Message: "CNAME chain exceeds 256 hops", Where: phaseName})
				}
				break
			}
			cur = c[0].Data[0]
		}
	}
	return dedupeBlocks(blocks)
}

func dedupeBlocks(bs []Block) []Block {
	seen := map[string]bool{}
	out := bs[:0]
	for _, b := range bs {
		k := b.Code + "|" + b.Where + "|" + b.Message
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, b)
	}
	return out
}

// DiffZones produces the minimal operations to transform a into b.
func DiffZones(a, b *Zone) []Operation {
	idxA := map[string]RR{}
	for _, rr := range a.Records {
		idxA[Key(rr.Name, rr.Type)] = rr
	}
	idxB := map[string]RR{}
	for _, rr := range b.Records {
		idxB[Key(rr.Name, rr.Type)] = rr
	}
	keys := map[string]bool{}
	for k := range idxA {
		keys[k] = true
	}
	for k := range idxB {
		keys[k] = true
	}
	ordered := make([]string, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Strings(ordered)
	ops := []Operation{}
	for _, k := range ordered {
		ra, oa := idxA[k]
		rb, ob := idxB[k]
		parts := strings.SplitN(k, "|", 2)
		switch {
		case oa && !ob:
			ops = append(ops, Operation{Action: "delete", Name: parts[0], Type: parts[1]})
		case !oa && ob:
			ops = append(ops, upsertOp(rb))
		case oa && ob && (ra.Raw != rb.Raw || ra.TTL != rb.TTL):
			ops = append(ops, upsertOp(rb))
		}
	}
	return ops
}

func upsertOp(rr RR) Operation {
	op := Operation{Action: "upsert", Name: rr.Name, Type: rr.Type, TTL: rr.TTL,
		Data: append([]string(nil), rr.Data...), Raw: rr.Raw}
	if rr.Type == "RRSIG" {
		sigs := rr // Data holds the seven metadata fields
		if alg, err := strconv.Atoi(sigs.Data[1]); err == nil {
			op.Algorithm = alg
		}
		if v, err := strconv.Atoi(sigs.Data[2]); err == nil {
			op.Labels = v
		}
		if v, err := strconv.Atoi(sigs.Data[3]); err == nil {
			op.OrigTTL = v
		}
		if v, err := strconv.ParseInt(sigs.Data[4], 10, 64); err == nil {
			op.Expiration = v
		}
		if v, err := strconv.ParseInt(sigs.Data[5], 10, 64); err == nil {
			op.Inception = v
		}
		if v, err := strconv.Atoi(sigs.Data[6]); err == nil {
			op.KeyTag = v
		}
	}
	return op
}
