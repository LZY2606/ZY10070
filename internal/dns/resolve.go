package dns

import "sort"

// Answer statuses.
const (
	StatusOK       = "NOERROR"  // positive answer
	StatusNODATA   = "NODATA"   // name exists, requested type absent
	StatusNXDOMAIN = "NXDOMAIN" // name does not exist
	StatusReferral = "REFERRAL" // answer terminates at a delegation cut
	StatusFail     = "SERVFAIL" // loop or out-of-zone follow
)

// Answer is the result of resolving one (qname, qtype) against a View.
// Signatures attached to the answer RRset (and the negative/SOA RRset) are
// attached separately; validity against a clock is decided by the simulator.
type Answer struct {
	Status     string   `json:"status"`
	QName      string   `json:"qname"`
	QType      string   `json:"qtype"`
	Records    []Record `json:"records"`
	Signatures []Record `json:"signatures,omitempty"`
	TTL        uint32   `json:"ttl"`
	Wildcard   string   `json:"wildcard,omitempty"`
	Reason     string   `json:"reason,omitempty"`
}

func minTTL(rs []Record, fallback uint32) uint32 {
	if len(rs) == 0 {
		return fallback
	}
	m := rs[0].TTL
	for _, r := range rs[1:] {
		if r.TTL < m {
			m = r.TTL
		}
	}
	return m
}

func sigsFor(z *Zone, owner, covered string) []Record {
	var out []Record
	for _, s := range z.SignaturesAt(owner) {
		if s.RRSIG != nil && s.RRSIG.TypeCovered == covered {
			out = append(out, s)
		}
	}
	return out
}

// IsBelow reports whether name is the origin or strictly below it.
func IsBelow(name, origin string) bool {
	if name == origin {
		return true
	}
	return len(name) > len(origin) && name[len(name)-len(origin)-1:] == "."+origin
}

func parentName(name, origin string) string {
	if name == origin {
		return "."
	}
	idx := indexByte(name, '.')
	if idx < 0 {
		return origin
	}
	rest := name[idx+1:]
	if rest == "" {
		return "."
	}
	return rest
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// closestCut returns the deepest delegation point above qname (excluding the
// apex), or "". A cut is any non-apex name owning an NS RRset.
func closestCut(z *Zone, qname string) string {
	z.index()
	for name := parentName(qname, z.Origin); name != "." && name != z.Origin; name = parentName(name, z.Origin) {
		if z.HasType(name, "NS") {
			return name
		}
	}
	return ""
}

// wildcardOwner returns the closest enclosing wildcard node that can
// synthesise qname, or "".
func wildcardOwner(z *Zone, qname string) string {
	z.index()
	for anc := parentName(qname, z.Origin); anc != "."; anc = parentName(anc, z.Origin) {
		wc := "*." + anc
		if z.NodeExists(wc) {
			return wc
		}
		if anc == z.Origin {
			break
		}
	}
	return ""
}

// Resolve answers (qname, qtype) against the immutable view z.
func Resolve(z *Zone, qname, qtype string) *Answer {
	qname = CanonicalName(qname, z.Origin)
	qtype = canonicalType(qtype)
	if !IsBelow(qname, z.Origin) {
		return &Answer{Status: StatusFail, QName: qname, QType: qtype, TTL: 0, Reason: "qname outside zone"}
	}
	return resolveName(z, qname, qtype, qname, map[string]bool{}, true)
}

// resolveName performs one walk. The visited set is shared across CNAME
// follows so a loop terminates in a SERVFAIL answer instead of recursion.
func resolveName(z *Zone, node, qtype, synthName string, seen map[string]bool, allowWildcard bool) *Answer {
	// Delegation: anything strictly below a cut is referred. Querying the cut
	// itself for NS is answered authoritatively.
	if cut := closestCut(z, node); cut != "" && !(node == cut && qtype == "NS") {
		ns := recordsOfType(z.RecordsAt(cut), "NS")
		return &Answer{
			Status:     StatusReferral,
			QName:      synthName,
			QType:      qtype,
			Records:    ns,
			Signatures: sigsFor(z, cut, "NS"),
			TTL:        minTTL(ns, 0),
		}
	}

	recs := z.RecordsAt(node)
	if len(recs) == 0 {
		if allowWildcard {
			if wc := wildcardOwner(z, node); wc != "" {
				ans := resolveName(z, wc, qtype, node, seen, false)
				if ans != nil && ans.Status == StatusOK {
					ans.Wildcard = wc
					return ans
				}
			}
		}
		return negativeAnswer(z, synthName, qtype)
	}
	if seen[node] {
		return &Answer{Status: StatusFail, QName: synthName, QType: qtype, Reason: "CNAME loop detected at " + node}
	}
	seen[node] = true

	if qtype == "RRSIG" {
		all := z.SignaturesAt(node)
		return &Answer{Status: StatusOK, QName: synthName, QType: qtype, Records: all, TTL: minTTL(all, 0)}
	}

	if exact := recordsOfType(recs, qtype); len(exact) > 0 {
		ans := &Answer{
			Status:     StatusOK,
			QName:      synthName,
			QType:      qtype,
			Records:    withOwner(exact, synthName),
			Signatures: sigsFor(z, node, qtype),
			TTL:        minTTL(append(append([]Record{}, exact...), sigsFor(z, node, qtype)...), 0),
		}
		if qtype == "CNAME" {
			return ans
		}
		return ans
	}

	cnames := recordsOfType(recs, "CNAME")
	if len(cnames) > 0 {
		target := cnames[0].Data
		cnameAns := &Answer{
			Status:     StatusOK,
			QName:      synthName,
			QType:      qtype,
			Records:    withOwner(cnames, synthName),
			Signatures: sigsFor(z, node, "CNAME"),
			TTL:        minTTL(append(append([]Record{}, cnames...), sigsFor(z, node, "CNAME")...), 0),
		}
		if !IsBelow(target, z.Origin) {
			cnameAns.Reason = "CNAME target outside zone; chain ends here"
			return cnameAns
		}
		next := resolveName(z, target, qtype, target, seen, false)
		// Merge the chain head with the terminal answer while preserving the
		// loop/out-of-zone failure status.
		merged := *next
		merged.QName = synthName
		merged.Records = append(append([]Record{}, cnameAns.Records...), next.Records...)
		merged.Signatures = append(append([]Record{}, cnameAns.Signatures...), next.Signatures...)
		if next.TTL > 0 && cnameAns.TTL > 0 && next.TTL < cnameAns.TTL {
			merged.TTL = next.TTL
		} else {
			merged.TTL = cnameAns.TTL
		}
		if next.Status == StatusFail {
			merged.Status = StatusFail
			merged.Reason = next.Reason
		}
		return &merged
	}

	// Node exists but has neither qtype nor a CNAME: NODATA.
	return negativeAnswer(z, synthName, qtype)
}

func negativeAnswer(z *Zone, qname, qtype string) *Answer {
	soa, minTTL, ok := z.OriginSOA()
	if !ok {
		return &Answer{Status: StatusNXDOMAIN, QName: qname, QType: qtype, TTL: 0}
	}
	status := StatusNXDOMAIN
	parent := parentName(qname, z.Origin)
	if parent != "." && z.NodeExists(parent) {
		status = StatusNODATA
	}
	return &Answer{
		Status:     status,
		QName:      qname,
		QType:      qtype,
		Records:    []Record{{Name: z.Origin, Type: "SOA", TTL: minTTL, Data: soa.Data}},
		Signatures: sigsFor(z, z.Origin, "SOA"),
		TTL:        minTTL,
	}
}

func recordsOfType(recs []Record, rtype string) []Record {
	var out []Record
	for _, r := range recs {
		if r.Type == rtype {
			out = append(out, r)
		}
	}
	return out
}

func withOwner(recs []Record, owner string) []Record {
	out := make([]Record, len(recs))
	for i, r := range recs {
		r.Name = owner
		out[i] = r
	}
	return out
}

func canonicalType(t string) string {
	u := t
	if len(u) > 0 && u[0] >= 'a' && u[0] <= 'z' {
		b := []byte(u)
		for i := range b {
			if b[i] >= 'a' && b[i] <= 'z' {
				b[i] -= 'a' - 'A'
			}
		}
		u = string(b)
	}
	return u
}

// ChangeKind enumerates RRset diff results.
type ChangeKind string

const (
	ChangeAdded   ChangeKind = "added"
	ChangeRemoved ChangeKind = "removed"
	ChangeUpdated ChangeKind = "updated"
)

// Change is one RRset-level difference between two zones.
type Change struct {
	Name   string     `json:"name"`
	Type   string     `json:"type"`
	Kind   ChangeKind `json:"kind"`
	Before []Record   `json:"before,omitempty"`
	After  []Record   `json:"after,omitempty"`
}

// rrsetDatum identity ignores TTL: the wire RDATA set. TTL differences are
// reported separately as an update so phases can gate them.
type rrset struct {
	ttl    uint32
	datas  []string
	sigIDs []string
}

func collectRRSets(z *Zone) map[string]rrset {
	out := map[string]rrset{}
	z.index()
	for name, recs := range z.byName {
		byType := map[string][]Record{}
		for _, r := range recs {
			byType[r.Type] = append(byType[r.Type], r)
		}
		for rtype, rs := range byType {
			datas := make([]string, 0, len(rs))
			for _, r := range rs {
				datas = append(datas, r.Data)
			}
			sort.Strings(datas)
			var sigIDs []string
			for _, s := range sigsFor(z, name, rtype) {
				sigIDs = append(sigIDs, s.RRSIG.KeyTagString()+"@"+s.RRSIG.Inception.Format("20060102150405")+"-"+s.RRSIG.Expiration.Format("20060102150405"))
			}
			sort.Strings(sigIDs)
			out[name+" "+rtype] = rrset{ttl: rs[0].TTL, datas: datas, sigIDs: sigIDs}
		}
	}
	return out
}

// Diff returns the RRset-level changes required to turn before into after.
func Diff(before, after *Zone) []Change {
	b := collectRRSets(before)
	a := collectRRSets(after)
	keys := map[string]bool{}
	for k := range b {
		keys[k] = true
	}
	for k := range a {
		keys[k] = true
	}
	out := make([]Change, 0, len(keys))
	for k := range keys {
		name, rtype := splitKey(k)
		bb, bok := b[k]
		aa, aok := a[k]
		ch := Change{Name: name, Type: rtype}
		switch {
		case bok && !aok:
			ch.Kind = ChangeRemoved
			ch.Before = recordsOfType(before.RecordsAt(name), rtype)
		case !bok && aok:
			ch.Kind = ChangeAdded
			ch.After = recordsOfType(after.RecordsAt(name), rtype)
		case equalRData(bb, aa) && bb.ttl == aa.ttl:
			continue
		default:
			ch.Kind = ChangeUpdated
			ch.Before = recordsOfType(before.RecordsAt(name), rtype)
			ch.After = recordsOfType(after.RecordsAt(name), rtype)
		}
		out = append(out, ch)
	}
	sortChanges(out)
	return out
}

func equalRData(a, b rrset) bool {
	return equalStrings(a.datas, b.datas) && equalStrings(a.sigIDs, b.sigIDs)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func splitKey(k string) (string, string) {
	for i := len(k) - 1; i >= 0; i-- {
		if k[i] == ' ' {
			return k[:i], k[i+1:]
		}
	}
	return k, ""
}

func sortChanges(cs []Change) {
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].Name != cs[j].Name {
			return cs[i].Name < cs[j].Name
		}
		return cs[i].Type < cs[j].Type
	})
}
