// Package dns contains the zone data model, zone-file parser, resolver view,
// wildcard/CNAME/delegation handling and fingerprints. All names inside the
// model are canonical: lower case, root terminated and joined with dots.
package dns

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Origin is the canonical name of the single apex served by a zone view,
// for example "example.".
type Origin = string

// CanonicalName lower-cases and root-terminates a domain name. An empty or
// "@" name resolves to origin; relative names are appended to origin.
func CanonicalName(name string, origin string) string {
	name = strings.TrimSpace(name)
	if name == "" || name == "@" {
		return origin
	}
	name = strings.ToLower(name)
	if !strings.HasSuffix(name, ".") {
		name = name + "." + origin
	}
	return name
}

// CanonicalRData normalises RDATA text for a given record type. It does not
// fully parse every DNS type; it canonicalises the types the simulator cares
// about and falls back to trimmed, collapsed-space text otherwise.
func CanonicalRData(rtype, rdata, origin string) string {
	rtype = strings.ToUpper(strings.TrimSpace(rtype))
	fields := strings.Fields(rdata)
	switch rtype {
	case "CNAME", "NS", "DNAME", "PTR":
		if len(fields) != 1 {
			return strings.ToLower(strings.Join(fields, " "))
		}
		return CanonicalName(fields[0], origin)
	case "SOA":
		for i := range fields {
			switch i {
			case 0, 1:
				fields[i] = CanonicalName(fields[i], origin)
			}
		}
		return strings.Join(fields, " ")
	case "MX":
		if len(fields) >= 2 {
			fields[1] = CanonicalName(fields[1], origin)
		}
		return strings.Join(fields, " ")
	case "SRV":
		if len(fields) >= 4 {
			fields[3] = CanonicalName(fields[3], origin)
		}
		return strings.Join(fields, " ")
	case "TXT":
		return strings.Join(fields, " ")
	default:
		return strings.ToLower(strings.Join(fields, " "))
	}
}

// RRSIG is a parsed RRSIG RR. Key fields used by signature-window checks and
// answer-time validation are kept typed; the raw RDATA remains available.
type RRSIG struct {
	TypeCovered string    `json:"type_covered"`
	Algorithm   uint8     `json:"algorithm"`
	Labels      uint8     `json:"labels"`
	OrigTTL     uint32    `json:"orig_ttl"`
	Expiration  time.Time `json:"expiration"`
	Inception   time.Time `json:"inception"`
	KeyTag      uint16    `json:"key_tag"`
	SignerName  string    `json:"signer_name"`
	RData       string    `json:"rdata"`
	TTL         uint32    `json:"ttl"`
}

// Record is one resource record. CNAME owner names carry one data entry;
// RRsets are grouped by (Name, Type) inside Zone.
type Record struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Data  string `json:"data"`
	RRSIG *RRSIG `json:"rrsig,omitempty"`
}

// Key identifies an RRset.
func (r Record) Key() string { return r.Name + " " + r.Type }

// WireKey is the type-independent key used by phase change permissions.
func (r Record) WireKey() string { return r.Name }

// Zone is a parsed zone for one origin.
type Zone struct {
	Origin   string    `json:"origin"`
	Records  []Record  `json:"records"`
	ParsedAt time.Time `json:"parsed_at"`

	byName map[string][]Record
	sigs   map[string][]Record // owner name -> RRSIG records
}

// index builds lookup maps; safe to call repeatedly.
func (z *Zone) index() {
	if z.byName != nil {
		return
	}
	z.byName = map[string][]Record{}
	z.sigs = map[string][]Record{}
	for _, r := range z.Records {
		if r.Type == "RRSIG" {
			z.sigs[r.Name] = append(z.sigs[r.Name], r)
			continue
		}
		z.byName[r.Name] = append(z.byName[r.Name], r)
	}
}

// OriginSOA returns the apex SOA record and its minimum-TTL field, used for
// negative caching. ok is false for a zone without an SOA.
func (z *Zone) OriginSOA() (soa Record, minimum uint32, ok bool) {
	z.index()
	for _, r := range z.byName[z.Origin] {
		if r.Type != "SOA" {
			continue
		}
		fields := strings.Fields(r.Data)
		if len(fields) >= 5 {
			if v, err := strconv.ParseUint(fields[len(fields)-1], 10, 32); err == nil {
				return r, uint32(v), true
			}
		}
		return r, r.TTL, true
	}
	return Record{}, 0, false
}

// Serial returns the apex SOA serial (field 3 of RDATA) and whether it exists.
func (z *Zone) Serial() (uint32, bool) {
	soa, _, ok := z.OriginSOA()
	if !ok {
		return 0, false
	}
	fields := strings.Fields(soa.Data)
	// mname rname serial refresh retry expire minimum
	if len(fields) >= 3 {
		if v, err := strconv.ParseUint(fields[2], 10, 32); err == nil {
			return uint32(v), true
		}
	}
	return 0, false
}

// RecordsAt returns non-RRSIG records owned by name.
func (z *Zone) RecordsAt(name string) []Record {
	z.index()
	return z.byName[name]
}

// SignaturesAt returns RRSIG records owned by name.
func (z *Zone) SignaturesAt(name string) []Record {
	z.index()
	return z.sigs[name]
}

// NodeExists reports whether any record (including RRSIG) exists at name.
func (z *Zone) NodeExists(name string) bool {
	z.index()
	return len(z.byName[name]) > 0 || len(z.sigs[name]) > 0
}

// HasType reports whether name owns an RRset of rtype (RRSIG excluded).
func (z *Zone) HasType(name, rtype string) bool {
	for _, r := range z.RecordsAt(name) {
		if r.Type == rtype {
			return true
		}
	}
	return false
}

// Fingerprint is a stable hash over origin and the canonical, sorted record
// set. Identical candidate content always produces the same fingerprint.
func (z *Zone) Fingerprint() string {
	keys := make([]string, 0, len(z.Records))
	for _, r := range z.Records {
		keys = append(keys, r.Name+"|"+r.Type+"|"+strconv.FormatUint(uint64(r.TTL), 10)+"|"+r.Data)
	}
	sort.Strings(keys)
	h := sha256.New()
	h.Write([]byte(z.Origin))
	h.Write([]byte{0})
	h.Write([]byte(strings.Join(keys, "\n")))
	return hex.EncodeToString(h.Sum(nil))
}
