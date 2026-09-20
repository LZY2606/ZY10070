package dns

import "testing"

func TestDiffDetectsChanges(t *testing.T) {
	cur := mustZone(t, zoneText)
	next := mustZone(t, `$ORIGIN example.
$TTL 300
@ IN SOA ns1.example. admin.example. 2026011500 7200 3600 1209600 300
@ IN NS ns1.example.
@ IN NS ns2.example.
ns1 IN A 192.0.2.10
ns2 IN A 192.0.2.11
@ IN A 192.0.2.1
www IN A 192.0.2.21
api IN CNAME www.example.
*.svc IN A 192.0.2.50
sub IN NS ns1.sub.example.
ns1.sub IN A 203.0.113.9
loop1 IN CNAME loop2.example.
loop2 IN CNAME loop1.example.
`)
	changes := Diff(cur, next)
	found := map[ChangeKind]bool{}
	for _, c := range changes {
		found[c.Kind] = true
	}
	if !found[ChangeUpdated] {
		t.Fatalf("expected update, got %+v", changes)
	}
}

func TestSerialRollbackBlocker(t *testing.T) {
	cur := mustZone(t, zoneText)
	bad := mustZone(t, zoneText)
	// Replace SOA with an older serial by re-parsing different text.
	bad = mustZone(t, `$ORIGIN example.
$TTL 300
@ IN SOA ns1.example. admin.example. 100 7200 3600 1209600 300
@ IN NS ns1.example.
ns1 IN A 192.0.2.10
www IN A 192.0.2.20
`)
	findings := ValidateCandidate(cur, bad)
	if !hasBlocker(findings, "SERIAL_ROLLBACK") {
		t.Fatalf("expected SERIAL_ROLLBACK blocker: %+v", findings)
	}
}

func TestCNAMELoopBlocker(t *testing.T) {
	z := mustZone(t, zoneText)
	if !hasBlocker(ValidateCandidate(nil, z), "CNAME_LOOP") {
		t.Fatal("expected CNAME loop blocker")
	}
}

func TestBrokenDelegationBlocker(t *testing.T) {
	z := mustZone(t, `$ORIGIN example.
$TTL 300
@ IN SOA ns1.example. admin.example. 1 7200 3600 1209600 300
@ IN NS ns1.example.
ns1 IN A 192.0.2.10
sub IN NS nsx.sub.example.
`)
	if !hasBlocker(ValidateCandidate(nil, z), "BROKEN_DELEGATION") {
		t.Fatal("expected broken delegation blocker")
	}
}

func TestSignatureWindowDisjoint(t *testing.T) {
	cur := mustZone(t, `$ORIGIN example.
$TTL 300
@ IN SOA ns1.example. admin.example. 1 7200 3600 1209600 300
@ IN NS ns1.example.
ns1 IN A 192.0.2.10
www IN A 192.0.2.20
www IN RRSIG A 13 3 300 20260110000000 20260101000000 12345 example. FAKE
`)
	cand := mustZone(t, `$ORIGIN example.
$TTL 300
@ IN SOA ns1.example. admin.example. 2 7200 3600 1209600 300
@ IN NS ns1.example.
ns1 IN A 192.0.2.10
www IN A 192.0.2.21
www IN RRSIG A 13 3 300 20260220000000 20260210000000 12345 example. FAKE
`)
	if !hasBlocker(ValidateCandidate(cur, cand), "SIGNATURE_WINDOW_DISJOINT") {
		t.Fatal("expected disjoint signature window blocker")
	}
}

func TestSignatureWindowOverlapOK(t *testing.T) {
	cur := mustZone(t, `$ORIGIN example.
$TTL 300
@ IN SOA ns1.example. admin.example. 1 7200 3600 1209600 300
@ IN NS ns1.example.
ns1 IN A 192.0.2.10
www IN A 192.0.2.20
www IN RRSIG A 13 3 300 20260120000000 20260101000000 12345 example. FAKE
`)
	cand := mustZone(t, `$ORIGIN example.
$TTL 300
@ IN SOA ns1.example. admin.example. 2 7200 3600 1209600 300
@ IN NS ns1.example.
ns1 IN A 192.0.2.10
www IN A 192.0.2.21
www IN RRSIG A 13 3 300 20260210000000 20260115000000 12345 example. FAKE
`)
	for _, f := range ValidateCandidate(cur, cand) {
		if f.Code == "SIGNATURE_WINDOW_DISJOINT" {
			t.Fatalf("overlapping windows should pass: %+v", f)
		}
	}
}

func hasBlocker(fs []Finding, code string) bool {
	for _, f := range fs {
		if f.Code == code && f.Blocking() {
			return true
		}
	}
	return false
}
