package dns

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseError describes a malformed zone line.
type ParseError struct {
	Line   int    `json:"line"`
	Reason string `json:"reason"`
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("zone parse error on line %d: %s", e.Line, e.Reason)
}

var sigTimeFormats = []string{
	"20060102150405",
	time.RFC3339,
}

func parseSigTime(s string) (time.Time, error) {
	for _, f := range sigTimeFormats {
		if t, err := time.Parse(f, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid RRSIG timestamp %q", s)
}

// ParseZone parses a small, deliberately strict subset of RFC 1035 zone text.
// Supported directives are $ORIGIN and $TTL; comments start with ';' and
// parenthesised line continuations are honoured. RRSIG signature inception and
// expiration are absolute wall-clock values (yyyymmddhhmmss or RFC3339).
func ParseZone(text string, defaultOrigin string) (*Zone, error) {
	defaultOrigin = CanonicalName(defaultOrigin, defaultOrigin)
	origin := defaultOrigin
	var defaultTTL uint32 = 3600

	// Join physical lines on parentheses, stripping comments and blank lines.
	type logical struct {
		no   int
		text string
	}
	var logicals []logical
	var buf strings.Builder
	startLine := 0
	depth := 0
	for i, raw := range strings.Split(text, "\n") {
		lineNo := i + 1
		if idx := strings.Index(raw, ";"); idx >= 0 {
			raw = raw[:idx]
		}
		raw = strings.TrimSpace(raw)
		if raw == "" && depth == 0 {
			continue
		}
		if depth == 0 {
			startLine = lineNo
		}
		for _, ch := range raw {
			switch ch {
			case '(':
				depth++
			case ')':
				depth--
				if depth < 0 {
					return nil, &ParseError{Line: lineNo, Reason: "unbalanced parentheses"}
				}
			}
		}
		raw = strings.ReplaceAll(raw, "(", " ")
		raw = strings.ReplaceAll(raw, ")", " ")
		buf.WriteString(" ")
		buf.WriteString(raw)
		if depth == 0 {
			logicals = append(logicals, logical{startLine, strings.TrimSpace(buf.String())})
			buf.Reset()
		}
	}
	if depth != 0 {
		return nil, &ParseError{Line: startLine, Reason: "unterminated parenthesised block"}
	}

	z := &Zone{Origin: origin, ParsedAt: time.Now().UTC()}
	var lastOwner string

	for _, lg := range logicals {
		fields := strings.Fields(lg.text)
		if len(fields) == 0 {
			continue
		}
		// Directives.
		if strings.HasPrefix(fields[0], "$") {
			switch strings.ToUpper(fields[0]) {
			case "$ORIGIN":
				if len(fields) != 2 {
					return nil, &ParseError{Line: lg.no, Reason: "$ORIGIN requires exactly one argument"}
				}
				origin = CanonicalName(fields[1], origin)
				z.Origin = origin
			case "$TTL":
				if len(fields) != 2 {
					return nil, &ParseError{Line: lg.no, Reason: "$TTL requires exactly one argument"}
				}
				ttl, err := parseTTL(fields[1])
				if err != nil {
					return nil, &ParseError{Line: lg.no, Reason: err.Error()}
				}
				defaultTTL = ttl
			default:
				return nil, &ParseError{Line: lg.no, Reason: "unsupported directive " + fields[0]}
			}
			continue
		}

		// Determine owner / TTL / type position. Fields may begin with the
		// owner, or (on continuation of an owner) with a TTL or type.
		idx := 0
		var owner string
		if isTTLField(fields[0]) || isKnownType(fields[0]) {
			owner = lastOwner
		} else {
			owner = CanonicalName(fields[0], origin)
			idx = 1
		}
		if owner == "" {
			return nil, &ParseError{Line: lg.no, Reason: "record without owner and no previous owner"}
		}
		lastOwner = owner

		var ttl uint32 = defaultTTL
		if idx < len(fields) && isTTLField(fields[idx]) {
			v, err := parseTTL(fields[idx])
			if err != nil {
				return nil, &ParseError{Line: lg.no, Reason: err.Error()}
			}
			ttl = v
			idx++
		}
		// Tolerate the optional "IN" class token.
		if idx < len(fields) && strings.EqualFold(fields[idx], "IN") {
			idx++
			if idx < len(fields) && isTTLField(fields[idx]) {
				v, err := parseTTL(fields[idx])
				if err != nil {
					return nil, &ParseError{Line: lg.no, Reason: err.Error()}
				}
				ttl = v
				idx++
			}
		}
		if idx >= len(fields) {
			return nil, &ParseError{Line: lg.no, Reason: "missing record type"}
		}
		rtype := strings.ToUpper(fields[idx])
		if !isKnownType(rtype) {
			return nil, &ParseError{Line: lg.no, Reason: "unknown or unsupported record type " + fields[idx]}
		}
		idx++
		if idx > len(fields) {
			return nil, &ParseError{Line: lg.no, Reason: "missing RDATA"}
		}
		rdata := strings.TrimSpace(strings.Join(fields[idx:], " "))

		rec := Record{Name: owner, Type: rtype, TTL: ttl}
		if rtype == "RRSIG" {
			sig, err := parseRRSIG(rdata, ttl, origin)
			if err != nil {
				return nil, &ParseError{Line: lg.no, Reason: err.Error()}
			}
			rec.RRSIG = sig
			rec.Data = sig.RData
		} else {
			if rdata == "" {
				return nil, &ParseError{Line: lg.no, Reason: "empty RDATA for " + rtype}
			}
			rec.Data = CanonicalRData(rtype, rdata, origin)
		}
		z.Records = append(z.Records, rec)
	}

	if _, _, ok := z.OriginSOA(); !ok {
		return nil, errors.New("zone has no SOA record at the apex")
	}
	z.index()
	return z, nil
}

func parseRRSIG(rdata string, ttl uint32, origin string) (*RRSIG, error) {
	f := strings.Fields(rdata)
	if len(f) < 9 {
		return nil, fmt.Errorf("RRSIG needs at least 9 fields, got %d", len(f))
	}
	algo, err := strconv.ParseUint(f[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid RRSIG algorithm %q", f[1])
	}
	labels, err := strconv.ParseUint(f[2], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid RRSIG labels %q", f[2])
	}
	origTTL, err := parseTTL(f[3])
	if err != nil {
		return nil, fmt.Errorf("invalid RRSIG original TTL %q", f[3])
	}
	exp, err := parseSigTime(f[4])
	if err != nil {
		return nil, err
	}
	inc, err := parseSigTime(f[5])
	if err != nil {
		return nil, err
	}
	if !inc.Before(exp) {
		return nil, fmt.Errorf("RRSIG inception %s must be before expiration %s", inc.Format(time.RFC3339), exp.Format(time.RFC3339))
	}
	keyTag, err := strconv.ParseUint(f[6], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid RRSIG key tag %q", f[6])
	}
	signer := CanonicalName(f[7], origin)
	rest := strings.TrimSpace(strings.Join(f[8:], " "))
	return &RRSIG{
		TypeCovered: strings.ToUpper(f[0]),
		Algorithm:   uint8(algo),
		Labels:      uint8(labels),
		OrigTTL:     origTTL,
		Expiration:  exp,
		Inception:   inc,
		KeyTag:      uint16(keyTag),
		SignerName:  signer,
		RData:       strings.ToUpper(f[0]) + " " + rest,
		TTL:         ttl,
	}, nil
}

// isTTLField reports whether token is a bare TTL (digits or a duration such as
// 1h30m). Known numeric record types are checked first by the caller to avoid
// ambiguity.
func isTTLField(s string) bool {
	if _, err := parseTTL(s); err == nil {
		return true
	}
	return false
}

func parseTTL(s string) (uint32, error) {
	if n, err := strconv.ParseUint(s, 10, 32); err == nil {
		return uint32(n), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid TTL %q", s)
	}
	if d < 0 {
		return 0, fmt.Errorf("negative TTL %q", s)
	}
	v := uint64(d.Seconds())
	if v > uint64(^uint32(0)) {
		return 0, fmt.Errorf("TTL %q too large", s)
	}
	return uint32(v), nil
}

var knownTypes = map[string]bool{
	"A": true, "AAAA": true, "NS": true, "SOA": true, "CNAME": true,
	"DNAME": true, "MX": true, "TXT": true, "SRV": true, "PTR": true,
	"RRSIG": true, "DNSKEY": true, "DS": true, "NSEC": true, "NSEC3": true,
	"CAA": true,
}

func isKnownType(s string) bool { return knownTypes[strings.ToUpper(s)] }
