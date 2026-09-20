package dns

import "testing"

const zoneText = `$ORIGIN example.
$TTL 300
@   IN SOA ns1.example. admin.example. 2026010100 7200 3600 1209600 300
@   IN NS  ns1.example.
@   IN NS  ns2.example.
ns1 IN A   192.0.2.10
ns2 IN A   192.0.2.11
@   IN A   192.0.2.1
www IN A   192.0.2.20
api IN CNAME www.example.
*.svc IN A 192.0.2.50
sub IN NS  ns1.sub.example.
ns1.sub IN A 203.0.113.9
loop1 IN CNAME loop2.example.
loop2 IN CNAME loop1.example.
`

func mustZone(t *testing.T, text string) *Zone {
	t.Helper()
	z, err := ParseZone(text, "example.")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return z
}

func TestParseAndSerial(t *testing.T) {
	z := mustZone(t, zoneText)
	serial, ok := z.Serial()
	if !ok || serial != 2026010100 {
		t.Fatalf("serial = %d ok=%v", serial, ok)
	}
	_, minTTL, ok := z.OriginSOA()
	if !ok || minTTL != 300 {
		t.Fatalf("negative ttl = %d ok=%v", minTTL, ok)
	}
}

func TestResolveExact(t *testing.T) {
	z := mustZone(t, zoneText)
	ans := Resolve(z, "www.example.", "A")
	if ans.Status != StatusOK || len(ans.Records) != 1 || ans.Records[0].Data != "192.0.2.20" {
		t.Fatalf("unexpected answer: %+v", ans)
	}
	if ans.TTL != 300 {
		t.Fatalf("ttl = %d", ans.TTL)
	}
}

func TestResolveCNAMEChain(t *testing.T) {
	z := mustZone(t, zoneText)
	ans := Resolve(z, "api.example.", "A")
	if ans.Status != StatusOK {
		t.Fatalf("status = %s", ans.Status)
	}
	if len(ans.Records) != 2 || ans.Records[0].Type != "CNAME" || ans.Records[1].Type != "A" {
		t.Fatalf("chain = %+v", ans.Records)
	}
}

func TestResolveCNAMELoop(t *testing.T) {
	z := mustZone(t, zoneText)
	ans := Resolve(z, "loop1.example.", "A")
	if ans.Status != StatusFail || ans.Reason == "" {
		t.Fatalf("expected servfail, got %+v", ans)
	}
}

func TestResolveWildcard(t *testing.T) {
	z := mustZone(t, zoneText)
	ans := Resolve(z, "anything.svc.example.", "A")
	if ans.Status != StatusOK || ans.Wildcard != "*.svc.example." {
		t.Fatalf("wildcard answer = %+v", ans)
	}
	if ans.Records[0].Name != "anything.svc.example." {
		t.Fatalf("synthesised owner = %s", ans.Records[0].Name)
	}
}

func TestResolveDelegation(t *testing.T) {
	z := mustZone(t, zoneText)
	ans := Resolve(z, "host.sub.example.", "A")
	if ans.Status != StatusReferral {
		t.Fatalf("status = %s", ans.Status)
	}
	if len(ans.Records) != 1 || ans.Records[0].Data != "ns1.sub.example." {
		t.Fatalf("referral = %+v", ans.Records)
	}
	// Querying the cut for NS is authoritative.
	cut := Resolve(z, "sub.example.", "NS")
	if cut.Status != StatusOK || len(cut.Records) != 1 {
		t.Fatalf("cut NS = %+v", cut)
	}
}

func TestResolveNegative(t *testing.T) {
	z := mustZone(t, zoneText)
	noData := Resolve(z, "www.example.", "AAAA")
	if noData.Status != StatusNODATA || noData.TTL != 300 {
		t.Fatalf("nodata = %+v", noData)
	}
	nx := Resolve(z, "missing.deep.example.", "A")
	if nx.Status != StatusNXDOMAIN {
		t.Fatalf("nxdomain = %+v", nx)
	}
}

func TestFingerprintStable(t *testing.T) {
	a := mustZone(t, zoneText)
	b := mustZone(t, zoneText)
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatal("identical zones produced different fingerprints")
	}
}
