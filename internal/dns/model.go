package dns

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// RR is a single normalized resource record.
type RR struct {
	Name string   `json:"name"`
	Type string   `json:"type"`
	TTL  int      `json:"ttl"`
	Data []string `json:"data"` // type-specific rdata fields
	Raw  string   `json:"raw"`  // normalized rdata string
}

// SOAInfo holds parsed SOA fields.
type SOAInfo struct {
	MName   string `json:"mname"`
	RName   string `json:"rname"`
	Serial  uint32 `json:"serial"`
	Refresh int    `json:"refresh"`
	Retry   int    `json:"retry"`
	Expire  int    `json:"expire"`
	Minimum int    `json:"minimum"`
}

// RRSigInfo holds parsed RRSIG metadata (RFC 4034).
type RRSigInfo struct {
	TypeCovered string `json:"type_covered"`
	Algorithm   int    `json:"algorithm"`
	Labels      int    `json:"labels"`
	OrigTTL     int    `json:"orig_ttl"`
	Expiration  int64  `json:"expiration"` // unix seconds
	Inception   int64  `json:"inception"`  // unix seconds
	KeyTag      int    `json:"keytag"`
}

// Zone is a parsed authoritative zone.
type Zone struct {
	Origin  string
	Records []RR
	SOA     *SOAInfo
	RRSIGs  map[string][]RRSigInfo // key: canonical owner/type "name|TYPE"
	byName  map[string][]RR
	deleg   map[string]bool
}

// Key returns the canonical storage key for an rrset owner/type.
func Key(name, rrtype string) string {
	return strings.ToLower(strings.TrimSuffix(name, ".")) + "|" + strings.ToUpper(rrtype)
}

func (z *Zone) index() {
	z.byName = map[string][]RR{}
	z.deleg = map[string]bool{}
	for _, rr := range z.Records {
		n := strings.ToLower(rr.Name)
		z.byName[n] = append(z.byName[n], rr)
		if rr.Type == "NS" && strings.TrimSuffix(strings.ToLower(rr.Name), ".") != strings.TrimSuffix(strings.ToLower(z.Origin), ".") {
			z.deleg[n] = true
		}
	}
}

// Lookup returns all records of the given type at name (after zone indexing).
func (z *Zone) Lookup(name, rrtype string) []RR {
	for _, rr := range z.byName[strings.ToLower(name)] {
		if strings.EqualFold(rr.Type, rrtype) {
			return []RR{rr}
		}
	}
	return nil
}

// RRSIGFor returns the parsed RRSIG records covering name/type.
func (z *Zone) RRSIGFor(name, rrtype string) []RRSigInfo {
	return z.RRSIGs[Key(name, rrtype)]
}

// HasName reports whether any record exists at name (below the apex in-zone).
func (z *Zone) HasName(name string) bool {
	_, ok := z.byName[strings.ToLower(name)]
	return ok
}

// IsDelegation reports whether name is a non-apex delegation point.
func (z *Zone) IsDelegation(name string) bool {
	return z.deleg[strings.ToLower(name)]
}

// RecordsAt returns every RR owned by name.
func (z *Zone) RecordsAt(name string) []RR {
	return z.byName[strings.ToLower(name)]
}

// ApexSerial returns the SOA serial or 0 when no SOA is present.
func (z *Zone) ApexSerial() uint32 {
	if z.SOA == nil {
		return 0
	}
	return z.SOA.Serial
}

// CanonicalLines renders records as deterministic normalized lines.
func (z *Zone) CanonicalLines() []string {
	lines := make([]string, 0, len(z.Records))
	for _, rr := range z.Records {
		lines = append(lines, strings.ToLower(rr.Name)+" "+itoa(rr.TTL)+" "+rr.Type+" "+rr.Raw)
	}
	sort.Strings(lines)
	return lines
}

// Fingerprint is a stable SHA-256 identity of the normalized record set.
func (z *Zone) Fingerprint() string {
	h := sha256.Sum256([]byte(strings.Join(z.CanonicalLines(), "\n")))
	return hex.EncodeToString(h[:])
}

func itoa(n int) string {
	return strconv.Itoa(n)
}
