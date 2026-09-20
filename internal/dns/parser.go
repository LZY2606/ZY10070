package dns

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseError locates a problem in the imported zone text.
type ParseError struct {
	Line    int
	Message string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("line %d: %s", e.Line, e.Message)
}

// ParseZone parses RFC-1035-ish zone text into a normalized Zone.
func ParseZone(name, text string) (*Zone, error) {
	origin := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if origin == "" {
		return nil, &ParseError{Line: 0, Message: "zone origin is required"}
	}
	z := &Zone{Origin: origin, RRSIGs: map[string][]RRSigInfo{}}
	defaultTTL := 3600
	var lastOwner string

	rawLines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	// Join parenthesized continuations, tracking the first physical line.
	type stmt struct {
		line int
		text string
	}
	var stmts []stmt
	var buf strings.Builder
	startLine := 0
	depth := 0
	for i, l := range rawLines {
		// Strip comments not inside quotes/parens (simple handling: quotes rare except TXT).
		l = stripComment(l)
		if depth == 0 && strings.Contains(l, "(") {
			startLine = i + 1
		}
		depth += strings.Count(l, "(") - strings.Count(l, ")")
		buf.WriteString(" ")
		buf.WriteString(l)
		if depth <= 0 {
			if buf.Len() > 0 {
				t := strings.ReplaceAll(buf.String(), "(", " ")
				t = strings.ReplaceAll(t, ")", " ")
				stmts = append(stmts, stmt{line: startLineSafe(startLine, i+1, buf.String()), text: t})
			}
			buf.Reset()
			depth = 0
		}
	}
	if depth != 0 {
		return nil, &ParseError{Line: startLine, Message: "unbalanced parentheses"}
	}

	for _, s := range stmts {
		fields := tokenize(s.text)
		if len(fields) == 0 {
			continue
		}
		first := fields[0]
		switch strings.ToUpper(first) {
		case "$ORIGIN":
			if len(fields) < 2 {
				return nil, &ParseError{Line: s.line, Message: "$ORIGIN requires a name"}
			}
			origin = fqdn(fields[1], origin)
			z.Origin = origin
			continue
		case "$TTL":
			if len(fields) < 2 {
				return nil, &ParseError{Line: s.line, Message: "$TTL requires a value"}
			}
			ttl, err := parseTTL(fields[1])
			if err != nil {
				return nil, &ParseError{Line: s.line, Message: err.Error()}
			}
			defaultTTL = ttl
			continue
		}

		// Determine owner.
		owner := lastOwner
		pos := 0
		lookOwner := first
		if lookOwner == "@" || isName(lookOwner) {
			owner = fqdn(lookOwner, origin)
			pos = 1
			lastOwner = owner
		}
		if owner == "" {
			owner = origin
		}

		ttl := defaultTTL
		for i := 0; i < 2 && pos < len(fields); i++ {
			if v, err := parseTTL(fields[pos]); err == nil {
				ttl = v
				pos++
				continue
			}
			if strings.EqualFold(fields[pos], "IN") {
				pos++
				continue
			}
			break
		}
		if pos < len(fields) && strings.EqualFold(fields[pos], "CH") {
			return nil, &ParseError{Line: s.line, Message: "only class IN is supported"}
		}
		if pos >= len(fields) {
			return nil, &ParseError{Line: s.line, Message: "missing record type"}
		}
		rrtype := strings.ToUpper(fields[pos])
		pos++
		if pos >= len(fields) && rrtype != "RRSIG" {
			return nil, &ParseError{Line: s.line, Message: "missing rdata"}
		}
		rdata := fields[pos:]

		rr := RR{Name: owner, Type: rrtype, TTL: ttl}
		switch rrtype {
		case "SOA":
			info, err := parseSOA(rdata)
			if err != nil {
				return nil, &ParseError{Line: s.line, Message: err.Error()}
			}
			z.SOA = info
			rr.Data = []string{info.MName, info.RName, strconv.FormatUint(uint64(info.Serial), 10),
				strconv.Itoa(info.Refresh), strconv.Itoa(info.Retry), strconv.Itoa(info.Expire), strconv.Itoa(info.Minimum)}
			rr.Raw = strings.Join(rr.Data, " ")
			if owner != z.Origin {
				return nil, &ParseError{Line: s.line, Message: "SOA must be at zone apex"}
			}
		case "RRSIG":
			info, raw, err := parseRRSIG(rdata)
			if err != nil {
				return nil, &ParseError{Line: s.line, Message: err.Error()}
			}
			rr.Data = []string{info.TypeCovered, strconv.Itoa(info.Algorithm), strconv.Itoa(info.Labels),
				strconv.Itoa(info.OrigTTL), strconv.FormatInt(info.Expiration, 10), strconv.FormatInt(info.Inception, 10),
				strconv.Itoa(info.KeyTag)}
			rr.Raw = raw
			z.RRSIGs[Key(owner, info.TypeCovered)] = append(z.RRSIGs[Key(owner, info.TypeCovered)], info)
		case "MX", "SRV":
			if len(rdata) < 2 {
				return nil, &ParseError{Line: s.line, Message: rrtype + " requires numeric preference and target"}
			}
			target := fqdn(rdata[len(rdata)-1], origin)
			rr.Data = append([]string{}, rdata[:len(rdata)-1]...)
			rr.Data = append(rr.Data, target)
			rr.Raw = strings.Join(rr.Data, " ")
		case "NS", "CNAME", "DNAME", "PTR":
			rr.Data = []string{fqdn(rdata[0], origin)}
			rr.Raw = rr.Data[0]
		case "CAA":
			if len(rdata) < 3 {
				return nil, &ParseError{Line: s.line, Message: "CAA requires flags tag value"}
			}
			rr.Data = rdata
			rr.Raw = strings.Join(rdata, " ")
		default:
			rr.Data = rdata
			rr.Raw = strings.Join(rdata, " ")
		}
		z.Records = append(z.Records, rr)
	}
	if z.SOA == nil {
		return nil, &ParseError{Line: 0, Message: "zone has no SOA record"}
	}
	z.index()
	return z, nil
}

func startLineSafe(a, b int, _ string) int {
	if a > 0 {
		return a
	}
	return b
}

func stripComment(l string) string {
	inQuote := false
	for i := 0; i < len(l); i++ {
		switch l[i] {
		case '"':
			inQuote = !inQuote
		case ';':
			if !inQuote {
				return l[:i]
			}
		}
	}
	return l
}

func tokenize(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuote = !inQuote
		case (c == ' ' || c == '\t' || c == '\n') && !inQuote:
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

func isName(tok string) bool {
	if tok == "@" {
		return true
	}
	if _, err := parseTTL(tok); err == nil {
		return false
	}
	if strings.EqualFold(tok, "IN") {
		return false
	}
	return true
}

func fqdn(name, origin string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "@" || name == "" {
		return origin
	}
	if strings.HasSuffix(name, ".") {
		return strings.TrimSuffix(name, ".")
	}
	if name == origin || strings.HasSuffix(name, "."+origin) {
		return name
	}
	return name + "." + origin
}

func parseTTL(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty ttl")
	}
	mult := 1
	last := s[len(s)-1]
	switch last {
	case 's', 'S':
		s, mult = s[:len(s)-1], 1
	case 'm', 'M':
		s, mult = s[:len(s)-1], 60
	case 'h', 'H':
		s, mult = s[:len(s)-1], 3600
	case 'd', 'D':
		s, mult = s[:len(s)-1], 86400
	case 'w', 'W':
		s, mult = s[:len(s)-1], 604800
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid ttl %q", s)
	}
	return n * mult, nil
}

func parseSOA(f []string) (*SOAInfo, error) {
	if len(f) != 7 {
		return nil, fmt.Errorf("SOA requires 7 fields, got %d", len(f))
	}
	serial, err := strconv.ParseUint(f[2], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid SOA serial: %v", err)
	}
	nums := make([]int, 4)
	for i, idx := range []int{3, 4, 5, 6} {
		v, err := strconv.Atoi(f[idx])
		if err != nil {
			return nil, fmt.Errorf("invalid SOA field: %v", err)
		}
		nums[i] = v
	}
	return &SOAInfo{MName: strings.ToLower(f[0]), RName: strings.ToLower(f[1]), Serial: uint32(serial),
		Refresh: nums[0], Retry: nums[1], Expire: nums[2], Minimum: nums[3]}, nil
}

func parseRRSIG(f []string) (RRSigInfo, string, error) {
	if len(f) < 9 {
		return RRSigInfo{}, "", fmt.Errorf("RRSIG requires at least 9 fields")
	}
	alg, err := strconv.Atoi(f[1])
	if err != nil {
		return RRSigInfo{}, "", fmt.Errorf("invalid RRSIG algorithm")
	}
	labels, err := strconv.Atoi(f[2])
	if err != nil {
		return RRSigInfo{}, "", fmt.Errorf("invalid RRSIG labels")
	}
	origTTL, err := strconv.Atoi(f[3])
	if err != nil {
		return RRSigInfo{}, "", fmt.Errorf("invalid RRSIG original TTL")
	}
	exp, err := parseSigTime(f[4])
	if err != nil {
		return RRSigInfo{}, "", fmt.Errorf("invalid RRSIG expiration: %v", err)
	}
	inc, err := parseSigTime(f[5])
	if err != nil {
		return RRSigInfo{}, "", fmt.Errorf("invalid RRSIG inception: %v", err)
	}
	tag, err := strconv.Atoi(f[6])
	if err != nil {
		return RRSigInfo{}, "", fmt.Errorf("invalid RRSIG key tag")
	}
	info := RRSigInfo{TypeCovered: strings.ToUpper(f[0]), Algorithm: alg, Labels: labels,
		OrigTTL: origTTL, Expiration: exp, Inception: inc, KeyTag: tag}
	return info, strings.Join(f, " "), nil
}

func parseSigTime(s string) (int64, error) {
	t, err := time.Parse("20060102150405", s)
	if err != nil {
		return 0, err
	}
	return t.Unix(), nil
}

// ParseTTL is exported for plan/parameter parsing convenience.
func ParseTTL(s string) (int, error) { return parseTTL(s) }
