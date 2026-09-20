package dns

import "strings"

// ChainStep records one link in CNAME resolution.
type ChainStep struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Target   string `json:"target,omitempty"`
	Wildcard bool   `json:"wildcard,omitempty"`
}

// Answer is one authoritative resolution outcome.
type Answer struct {
	QName     string      `json:"qname"`
	QType     string      `json:"qtype"`
	Status    string      `json:"status"` // NOERROR | NXDOMAIN | NODATA | SERVFAIL
	Records   []RR        `json:"records,omitempty"`
	Chain     []ChainStep `json:"chain,omitempty"`
	SigStatus string      `json:"sig_status"` // valid | expired | not_yet_valid | unsigned | insecure
	SigKeyTag int         `json:"sig_keytag,omitempty"`
	Wildcard  string      `json:"wildcard,omitempty"`
	NegTTL    int         `json:"neg_ttl,omitempty"`
	Authority string      `json:"authority"` // node id of the authoritative server that answered
}

// Canonical returns a deterministic identity used to compare answers across
// time and nodes (authority node and sig timing are intentionally excluded).
func (a Answer) Canonical() string {
	var b strings.Builder
	b.WriteString(a.Status)
	b.WriteString("|")
	b.WriteString(a.SigStatus)
	b.WriteString("|")
	if a.Wildcard != "" {
		b.WriteString(a.Wildcard)
		b.WriteString("|")
	}
	recs := make([]string, 0, len(a.Records))
	for _, r := range a.Records {
		recs = append(recs, r.Type+":"+r.Raw)
	}
	sortStrings(recs)
	b.WriteString(strings.Join(recs, ","))
	return b.String()
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// Resolver answers against a single effective zone snapshot.
type Resolver struct {
	Zone *Zone
	Now  int64
}

// Resolve performs authoritative resolution of name/type within the zone.
func (r *Resolver) Resolve(name, qtype string) Answer {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	qtype = strings.ToUpper(qtype)
	ans := Answer{QName: name, QType: qtype, Status: "SERVFAIL", SigStatus: "unsigned"}

	if !r.inZone(name) {
		ans.SigStatus = "insecure"
		return ans
	}

	// Non-apex delegation cut: authoritative data is only NS + glue.
	if r.Zone.IsDelegation(name) {
		return r.delegationAnswer(name, qtype)
	}

	target, wildcard := r.findName(name)
	if wildcard != "" {
		ans.Wildcard = wildcard
	}
	if target == "" {
		ans.Status = "NXDOMAIN"
		ans.SigStatus = "insecure"
		ans.NegTTL = r.negativeTTL()
		return ans
	}

	// Follow CNAME chain.
	visited := map[string]bool{}
	cur := target
	for {
		if visited[cur] {
			ans.Status = "SERVFAIL"
			ans.SigStatus = "insecure"
			return ans
		}
		visited[cur] = true
		cn := r.Zone.Lookup(cur, "CNAME")
		if len(cn) == 0 {
			break
		}
		step := ChainStep{Name: cur, Type: "CNAME", Target: cn[0].Data[0], Wildcard: wildcard != "" && cur == target}
		ans.Chain = append(ans.Chain, step)
		cur = strings.TrimSuffix(strings.ToLower(cn[0].Data[0]), ".")
		if !r.inZone(cur) {
			ans.Status = "NOERROR"
			ans.SigStatus = "insecure"
			return ans
		}
		t, w := r.findName(cur)
		if t == "" {
			ans.Status = "NXDOMAIN"
			ans.SigStatus = "insecure"
			ans.NegTTL = r.negativeTTL()
			return ans
		}
		cur = t
		if w != "" && ans.Wildcard == "" {
			ans.Wildcard = w
		}
		if r.Zone.IsDelegation(cur) {
			return r.delegationAnswer(cur, qtype)
		}
	}

	if qtype == "CNAME" {
		ans.Records = r.Zone.Lookup(cur, "CNAME")
	} else {
		ans.Records = r.Zone.Lookup(cur, qtype)
	}
	r.fillSig(&ans, cur, qtype)
	if len(ans.Records) == 0 {
		ans.Status = "NODATA"
		ans.NegTTL = r.negativeTTL()
	} else {
		ans.Status = "NOERROR"
	}
	return ans
}

func (r *Resolver) delegationAnswer(name, qtype string) Answer {
	ans := Answer{QName: name, QType: qtype, SigStatus: "insecure"}
	if qtype == "NS" {
		for _, rr := range r.Zone.RecordsAt(name) {
			if rr.Type == "NS" {
				ans.Records = append(ans.Records, rr)
			}
		}
		if len(ans.Records) > 0 {
			ans.Status = "NOERROR"
			return ans
		}
	}
	if qtype == "A" || qtype == "AAAA" {
		for _, rr := range r.Zone.RecordsAt(name) {
			if rr.Type == qtype {
				ans.Records = append(ans.Records, rr)
			}
		}
		if len(ans.Records) > 0 {
			ans.Status = "NOERROR"
			return ans
		}
	}
	ans.Status = "SERVFAIL"
	return ans
}

func (r *Resolver) fillSig(ans *Answer, name, qtype string) {
	sigs := r.Zone.RRSIGFor(name, qtype)
	if len(sigs) == 0 {
		ans.SigStatus = "unsigned"
		return
	}
	for _, s := range sigs {
		if r.Now >= s.Inception && r.Now <= s.Expiration {
			ans.SigStatus = "valid"
			ans.SigKeyTag = s.KeyTag
			return
		}
	}
	s := sigs[0]
	if r.Now < s.Inception {
		ans.SigStatus = "not_yet_valid"
	} else {
		ans.SigStatus = "expired"
	}
	ans.SigKeyTag = s.KeyTag
}

func (r *Resolver) trim(n string) string { return strings.TrimSuffix(strings.ToLower(n), ".") }

func (r *Resolver) inZone(name string) bool {
	o := r.trim(r.Zone.Origin)
	return name == o || strings.HasSuffix(name, "."+o)
}

// findName resolves the owner name applying RFC 4592 wildcard semantics.
func (r *Resolver) findName(qname string) (string, string) {
	if r.Zone.HasName(qname) {
		return qname, ""
	}
	labels := strings.Split(qname, ".")
	originLabels := strings.Split(r.trim(r.Zone.Origin), ".")
	for cut := 1; cut <= len(labels)-len(originLabels); cut++ {
		wild := append([]string{"*"}, labels[cut:]...)
		wname := strings.Join(wild, ".")
		if r.Zone.HasName(wname) {
			return wname, wname
		}
	}
	return "", ""
}

func (r *Resolver) negativeTTL() int {
	if r.Zone.SOA == nil {
		return 30
	}
	return maxInt(r.Zone.SOA.Minimum, 1)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
