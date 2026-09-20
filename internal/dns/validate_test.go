package dns

import "testing"

func baseZone(t *testing.T, serial uint32) *Zone {
	t.Helper()
	text := "$TTL 300\n@ IN SOA ns1 hostmaster " + uitoa(serial) + " 7200 3600 1209600 60\n@ NS ns1\nns1 A 10.0.0.1\n"
	z, err := ParseZone("example.test", text)
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func uitoa(u uint32) string {
	const digits = "0123456789"
	if u == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for u > 0 {
		i--
		b[i] = digits[u%10]
		u /= 10
	}
	return string(b[i:])
}

func TestSerialRollbackBlocked(t *testing.T) {
	base := baseZone(t, 100)
	plan := Plan{ZoneName: "example.test", Phases: []Phase{{
		Name: "rollback-serial", MinObserveSec: 10,
		Operations: []Operation{{Action: "upsert", Name: "example.test", Type: "SOA", TTL: 300,
			Data: []string{"ns1", "hostmaster", "50", "7200", "3600", "1209600", "60"},
			Raw:  "ns1 hostmaster 50 7200 3600 1209600 60"}},
	}}}
	blocks := ValidatePlan(base, plan)
	if !hasBlock(blocks, "serial_rollback") {
		t.Fatalf("expected serial_rollback, got %+v", blocks)
	}
}

func TestCNAMELoopBlocked(t *testing.T) {
	z, err := ParseZone("example.test", "$TTL 300\n@ SOA ns1 hostmaster 1 7200 3600 1209600 60\n@ NS ns1\nns1 A 10.0.0.1\n")
	if err != nil {
		t.Fatal(err)
	}
	plan := Plan{ZoneName: "example.test", Phases: []Phase{{Name: "loop", MinObserveSec: 10, Operations: []Operation{
		{Action: "upsert", Name: "a.example.test", Type: "CNAME", TTL: 300, Data: []string{"b.example.test"}, Raw: "b.example.test"},
		{Action: "upsert", Name: "b.example.test", Type: "CNAME", TTL: 300, Data: []string{"a.example.test"}, Raw: "a.example.test"},
	}}}}
	blocks := ValidatePlan(z, plan)
	if !hasBlock(blocks, "cname_loop") {
		t.Fatalf("expected cname_loop, got %+v", blocks)
	}
}

func TestBrokenDelegationBlocked(t *testing.T) {
	z, err := ParseZone("example.test", "$TTL 300\n@ SOA ns1 hostmaster 1 7200 3600 1209600 60\n@ NS ns1\nns1 A 10.0.0.1\n")
	if err != nil {
		t.Fatal(err)
	}
	plan := Plan{ZoneName: "example.test", Phases: []Phase{{Name: "deleg", MinObserveSec: 10, Operations: []Operation{
		{Action: "upsert", Name: "sub.example.test", Type: "NS", TTL: 300, Data: []string{"ns1.sub.example.test"}, Raw: "ns1.sub.example.test"},
	}}}}
	blocks := ValidatePlan(z, plan)
	if !hasBlock(blocks, "broken_delegation") {
		t.Fatalf("expected broken_delegation, got %+v", blocks)
	}
}

func TestGlueSatisfiesDelegation(t *testing.T) {
	z := baseZone(t, 1)
	plan := Plan{ZoneName: "example.test", Phases: []Phase{{Name: "deleg", MinObserveSec: 10, Operations: []Operation{
		{Action: "upsert", Name: "sub.example.test", Type: "NS", TTL: 300, Data: []string{"ns1.sub.example.test"}, Raw: "ns1.sub.example.test"},
		{Action: "upsert", Name: "ns1.sub.example.test", Type: "A", TTL: 300, Data: []string{"10.1.0.1"}, Raw: "10.1.0.1"},
	}}}}
	blocks := ValidatePlan(z, plan)
	if hasBlock(blocks, "broken_delegation") {
		t.Fatalf("glue should satisfy delegation: %+v", blocks)
	}
}

func TestRRSIGWindowDisjointBlocked(t *testing.T) {
	base := signedZone(t, 1000, 2000)
	next := signedZone(t, 3000, 4000)
	blocks := ValidateTransition(base, next)
	if !hasBlock(blocks, "signature_window_disjoint") {
		t.Fatalf("expected disjoint signature windows, got %+v", blocks)
	}
	overlap := signedZone(t, 1500, 2500)
	if hasBlock(ValidateTransition(base, overlap), "signature_window_disjoint") {
		t.Fatal("overlapping windows must pass")
	}
}

func hasBlock(bs []Block, code string) bool {
	for _, b := range bs {
		if b.Code == code {
			return true
		}
	}
	return false
}

func signedZone(t *testing.T, inception, expiration int64) *Zone {
	t.Helper()
	z := baseZone(t, 1)
	z.RRSIGs[Key("www.example.test", "A")] = []RRSigInfo{{
		TypeCovered: "A", Algorithm: 13, Labels: 3, OrigTTL: 300,
		Inception: inception, Expiration: expiration, KeyTag: 1234,
	}}
	z.Records = append(z.Records, RR{Name: "www.example.test", Type: "A", TTL: 300,
		Data: []string{"192.0.2.10"}, Raw: "192.0.2.10"})
	z.index()
	return z
}
