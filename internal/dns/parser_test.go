package dns

import "testing"

const sample = `$TTL 300
$ORIGIN example.test.
@ IN SOA ns1 hostmaster 2026090101 7200 3600 1209600 60
@ IN NS ns1
@ IN NS ns2
ns1 300 IN A 10.0.0.11
ns2 300 IN A 10.0.0.12
www 120 IN A 192.0.2.10
api IN CNAME www
mtxt 1m IN TXT "minute ttl"
`

func TestParseZone(t *testing.T) {
	z, err := ParseZone("example.test", sample)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if z.SOA == nil || z.SOA.Serial != 2026090101 {
		t.Fatalf("bad soa: %+v", z.SOA)
	}
	if got := z.Lookup("ns1.example.test", "A"); len(got) != 1 || got[0].Raw != "10.0.0.11" {
		t.Fatalf("ns1 lookup failed: %+v", got)
	}
	if got := z.Lookup("mtxt.example.test", "TXT"); len(got) != 1 || got[0].TTL != 60 {
		t.Fatalf("ttl suffix failed: %+v", got)
	}
	if z.Fingerprint() == "" {
		t.Fatal("fingerprint empty")
	}
}

func TestParseRelativeAndWildcard(t *testing.T) {
	text := `$TTL 300
@ IN SOA ns1 hostmaster 1 7200 3600 1209600 60
@ NS ns1
ns1 A 10.0.0.1
*.svc A 192.0.2.77
`
	z, err := ParseZone("example.test", sample[:0]+text)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !z.HasName("*.svc.example.test") {
		t.Fatal("wildcard owner missing")
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := ParseZone("example.test", "not a zone"); err == nil {
		t.Fatal("expected missing SOA error")
	}
	bad := `$TTL 300
@ SOA ns1 hostmaster notanumber 7200 3600 1209600 60
`
	if _, err := ParseZone("example.test", bad); err == nil {
		t.Fatal("expected serial parse error")
	}
}
