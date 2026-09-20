package dns

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// KeyTagString renders the numeric key tag.
func (s *RRSIG) KeyTagString() string { return strconv.FormatUint(uint64(s.KeyTag), 10) }

// Finding is one publish-blocking (or warning-level) problem found while
// validating a candidate zone against its current zone.
type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"` // "blocker" | "warning"
	Message  string `json:"message"`
	Name     string `json:"name,omitempty"`
	Type     string `json:"type,omitempty"`
}

// Blocking reports whether the finding prevents a release plan.
func (f Finding) Blocking() bool { return f.Severity == "blocker" }

// serialLess implements RFC 1982 serial number arithmetic comparison.
func serialLess(a, b uint32) (bool, bool) {
	if a == b {
		return false, false
	}
	diff := int64(b) - int64(a)
	if diff < 0 {
		diff += 1 << 32
	}
	if diff > 0 && diff < (1<<31) {
		return true, true // a < b, comparable
	}
	if diff > (1 << 31) {
		return false, true // a > b, comparable
	}
	return false, false // equal-distance: unordered
}

// CNAMEChainProblems detects CNAME loops and illegal CNAME/other-data
// coexistence within one zone.
func CNAMEChainProblems(z *Zone) []Finding {
	var out []Finding
	z.index()
	for name, recs := range z.byName {
		if cname := recordsOfType(recs, "CNAME"); len(cname) > 0 {
			if len(recs) > len(cname) {
				others := map[string]bool{}
				for _, r := range recs {
					if r.Type != "CNAME" {
						others[r.Type] = true
					}
				}
				out = append(out, Finding{
					Code: "CNAME_COEXISTS", Severity: "blocker",
					Name: name, Type: "CNAME",
					Message: fmt.Sprintf("CNAME at %s coexists with other data (%s)", name, joinSorted(others)),
				})
			}
			target := cname[0].Data
			seen := map[string]bool{name: true}
			cur := target
			for IsBelow(cur, z.Origin) {
				if seen[cur] {
					out = append(out, Finding{
						Code: "CNAME_LOOP", Severity: "blocker",
						Name: name, Type: "CNAME",
						Message: fmt.Sprintf("CNAME chain from %s closes a loop at %s", name, cur),
					})
					break
				}
				seen[cur] = true
				next := recordsOfType(z.byName[cur], "CNAME")
				if len(next) == 0 {
					break
				}
				cur = next[0].Data
			}
		}
	}
	sortFindings(out)
	return out
}

func joinSorted(set map[string]bool) string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// brokenDelegations finds non-apex NS cuts whose target name is neither
// in-zone address-bearing nor glue, and whose nameserver name itself lives
// within this zone but has no address records.
func brokenDelegations(z *Zone) []Finding {
	var out []Finding
	z.index()
	for name, recs := range z.byName {
		if name == z.Origin {
			continue
		}
		nss := recordsOfType(recs, "NS")
		if len(nss) == 0 {
			continue
		}
		for _, ns := range nss {
			target := ns.Data
			if !IsBelow(target, z.Origin) {
				continue // served out of zone; glue assumed present at the parent
			}
			if len(z.byName[target]) == 0 {
				out = append(out, Finding{
					Code: "BROKEN_DELEGATION", Severity: "blocker",
					Name: name, Type: "NS",
					Message: fmt.Sprintf("delegation %s names %s, which has no records in zone", name, target),
				})
				continue
			}
			if !z.HasType(target, "A") && !z.HasType(target, "AAAA") {
				out = append(out, Finding{
					Code: "BROKEN_DELEGATION", Severity: "blocker",
					Name: name, Type: "NS",
					Message: fmt.Sprintf("nameserver %s for delegation %s has no A/AAAA glue in zone", target, name),
				})
			}
		}
	}
	sortFindings(out)
	return out
}

// serialRollback reports when the candidate SOA serial fails RFC 1982 ordering
// against the current serial.
func serialRollback(cur, cand *Zone) *Finding {
	cs, cok := cur.Serial()
	ns, nok := cand.Serial()
	if !cok || !nok {
		return nil
	}
	less, comparable := serialLess(cs, ns)
	if comparable && !less {
		return &Finding{
			Code: "SERIAL_ROLLBACK", Severity: "blocker",
			Name: cand.Origin, Type: "SOA",
			Message: fmt.Sprintf("candidate serial %d is not greater than current serial %d (RFC 1982)", ns, cs),
		}
	}
	if !comparable {
		return &Finding{
			Code: "SERIAL_AMBIGUOUS", Severity: "warning",
			Name: cand.Origin, Type: "SOA",
			Message: fmt.Sprintf("serial pair %d -> %d is unordered under RFC 1982", cs, ns),
		}
	}
	return nil
}

// signatureWindowProblem inspects RRsets that exist in both zones and carry
// RRSIGs. If both sides are signed but no old signature validity window
// overlaps any new one, resolvers in the field cannot validate through the
// transition and the change is blocked.
func signatureWindowProblem(cur, cand *Zone) []Finding {
	var out []Finding
	cset := collectRRSets(cur)
	nset := collectRRSets(cand)
	for k := range nset {
		name, rtype := splitKey(k)
		oldSigs := sigsFor(cur, name, rtype)
		newSigs := sigsFor(cand, name, rtype)
		if len(oldSigs) == 0 || len(newSigs) == 0 {
			continue
		}
		if _, ok := cset[k]; !ok {
			continue // brand new RRset: no rollover window required
		}
		if !windowsOverlap(oldSigs, newSigs) {
			out = append(out, Finding{
				Code: "SIGNATURE_WINDOW_DISJOINT", Severity: "blocker",
				Name: name, Type: rtype,
				Message: fmt.Sprintf("RRSIG windows for %s %s do not overlap between current and candidate zones", name, rtype),
			})
		}
	}
	sortFindings(out)
	return out
}

func windowsOverlap(a, b []Record) bool {
	for _, ra := range a {
		if ra.RRSIG == nil {
			continue
		}
		for _, rb := range b {
			if rb.RRSIG == nil {
				continue
			}
			if ra.RRSIG.Inception.Before(rb.RRSIG.Expiration) && rb.RRSIG.Inception.Before(ra.RRSIG.Expiration) {
				return true
			}
		}
	}
	return false
}

// SignatureValidAt reports whether at least one signature covering rtype at
// name is valid at instant t (inclusive bounds).
func SignatureValidAt(z *Zone, name, rtype string, t time.Time) bool {
	sigs := sigsFor(z, name, rtype)
	for _, s := range sigs {
		if s.RRSIG == nil {
			continue
		}
		lo := s.RRSIG.Inception
		hi := s.RRSIG.Expiration
		if (t.After(lo) || t.Equal(lo)) && (t.Before(hi) || t.Equal(hi)) {
			return true
		}
	}
	return false
}

// ValidateCandidate compares a candidate zone against the current zone and
// returns every finding. Structural candidate problems are checked even when
// there is no current zone.
func ValidateCandidate(cur, cand *Zone) []Finding {
	out := CNAMEChainProblems(cand)
	out = append(out, brokenDelegations(cand)...)
	if cur != nil {
		if f := serialRollback(cur, cand); f != nil {
			out = append(out, *f)
		}
		out = append(out, signatureWindowProblem(cur, cand)...)
	}
	sortFindings(out)
	return out
}

func sortFindings(f []Finding) {
	sort.Slice(f, func(i, j int) bool {
		if f[i].Code != f[j].Code {
			return f[i].Code < f[j].Code
		}
		if f[i].Name != f[j].Name {
			return f[i].Name < f[j].Name
		}
		return f[i].Type < f[j].Type
	})
}
