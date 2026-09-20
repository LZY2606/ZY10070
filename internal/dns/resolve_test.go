package dns

import "testing"

func resolverZone(t *testing.T) *Zone {
	text := `$TTL 300
@ IN SOA ns1 hostmaster 10 7200 3600 1209600 60
@ NS ns1
ns1 A 10.0.0.1
www A 192.0.2.10
api CNAME www
*.svc A 192.0.2.77
`
	z, err := ParseZone("example.test", text)
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func TestResolveCNAMEAndWildcard(t *testing.T) {
	z := resolverZone(t)
	r := &Resolver{Zone: z, Now: 100}

	a := r.Resolve("api.example.test", "A")
	if a.Status != "NOERROR" || len(a.Records) != 1 || a.Records[0].Raw != "192.0.2.10" {
		t.Fatalf("cname resolve: %+v", a)
	}
	if len(a.Chain) != 1 || a.Chain[0].Target != "www.example.test" {
		t.Fatalf("cname chain: %+v", a.Chain)
	}

	w := r.Resolve("pod-1.svc.example.test", "A")
	if w.Status != "NOERROR" || w.Wildcard == "" || w.Records[0].Raw != "192.0.2.77" {
		t.Fatalf("wildcard: %+v", w)
	}

	nx := r.Resolve("nope.example.test", "A")
	if nx.Status != "NXDOMAIN" || nx.NegTTL != 60 {
		t.Fatalf("nxdomain: %+v", nx)
	}

	nd := r.Resolve("www.example.test", "AAAA")
	if nd.Status != "NODATA" {
		t.Fatalf("nodata: %+v", nd)
	}
}

func TestResolveRRSIGWindow(t *testing.T) {
	z := resolverZone(t)
	z.RRSIGs[Key("www.example.test", "A")] = []RRSigInfo{{
		TypeCovered: "A", Inception: 1000, Expiration: 2000, KeyTag: 7,
	}}
	r := &Resolver{Zone: z, Now: 1500}
	if got := r.Resolve("www.example.test", "A"); got.SigStatus != "valid" {
		t.Fatalf("expected valid sig, got %s", got.SigStatus)
	}
	r.Now = 2001
	if got := r.Resolve("www.example.test", "A"); got.SigStatus != "expired" {
		t.Fatalf("expected expired, got %s", got.SigStatus)
	}
	r.Now = 999
	if got := r.Resolve("www.example.test", "A"); got.SigStatus != "not_yet_valid" {
		t.Fatalf("expected not yet valid, got %s", got.SigStatus)
	}
}
