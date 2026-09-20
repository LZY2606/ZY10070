package sim

import (
	"testing"

	"zonesim/internal/dns"
)

func mustZone(t *testing.T, serial uint32, text string) *dns.Zone {
	t.Helper()
	z, err := dns.ParseZone("example.test", text)
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func cutoverInput(t *testing.T, seed int64) Input {
	cur := mustZone(t, 1, `$TTL 60
@ SOA ns1 hostmaster 1 7200 3600 1209600 30
@ NS ns1
ns1 A 10.0.0.1
www A 192.0.2.10
`)
	plan := dns.Plan{ZoneName: "example.test", Phases: []dns.Phase{{
		Name: "change-www", MinObserveSec: 60,
		Operations: []dns.Operation{
			{Action: "upsert", Name: "example.test", Type: "SOA", TTL: 60,
				Data: []string{"ns1", "hostmaster", "2", "7200", "3600", "1209600", "30"},
				Raw:  "ns1 hostmaster 2 7200 3600 1209600 30"},
			{Action: "upsert", Name: "www.example.test", Type: "A", TTL: 60,
				Data: []string{"198.51.100.20"}, Raw: "198.51.100.20"},
		},
	}}}
	return Input{Base: cur, Plan: plan, Params: Parameters{
		AuthoritativeNodes: 3, RecursiveNodes: 3, MaxAuthDelaySec: 60,
		MaxRecvDelaySec: 0, MaxClockSkewSec: 0, ProbeIntervalSec: 30, Seed: seed}}
}

func TestDeterministicSameSeed(t *testing.T) {
	r1, err := Run(cutoverInput(t, 42))
	if err != nil {
		t.Fatal(err)
	}
	r2, err := Run(cutoverInput(t, 42))
	if err != nil {
		t.Fatal(err)
	}
	if fingerprintResult(r1) != fingerprintResult(r2) {
		t.Fatal("same seed must produce identical results")
	}
	r3, err := Run(cutoverInput(t, 43))
	if err != nil {
		t.Fatal(err)
	}
	if fingerprintResult(r1) == fingerprintResult(r3) {
		t.Fatal("different seed must vary node delays")
	}
}

func TestAuthDesyncAndCacheResidueThenConvergence(t *testing.T) {
	res, err := Run(cutoverInput(t, 7))
	if err != nil {
		t.Fatal(err)
	}
	// Phase decided at 60; some auth node applies at 60, others up to 120 => desync window.
	var sawOld, sawNew, sawCache, sawAuth bool
	for _, tr := range res.Traces {
		for _, v := range tr.Views {
			for _, rec := range v.Answer.Records {
				if rec.Raw == "192.0.2.10" {
					sawOld = true
				}
				if rec.Raw == "198.51.100.20" {
					sawNew = true
				}
			}
			if v.Source == "cache" || v.Source == "negative_cache" {
				sawCache = true
			}
			if v.Source == "authoritative" {
				sawAuth = true
			}
		}
	}
	if !sawOld || !sawNew {
		t.Fatalf("expected both old and new answers during cutover old=%v new=%v", sawOld, sawNew)
	}
	if !sawCache {
		t.Fatal("expected cache hits demonstrating residual TTL")
	}
	if !sawAuth {
		t.Fatal("expected authoritative fetches")
	}
	if res.EarliestConverged <= res.StableFromSec {
		t.Fatalf("convergence must account for cached TTL after stability: conv=%d stable=%d",
			res.EarliestConverged, res.StableFromSec)
	}
}

func TestRollbackHonorsTTL(t *testing.T) {
	in := cutoverInput(t, 7)
	in.Decisions = []Decision{
		{PhaseIndex: 0, Action: "proceed", AtSec: 60},
		{PhaseIndex: 0, Action: "rollback", AtSec: 240},
	}
	res, err := Run(in)
	if err != nil {
		t.Fatal(err)
	}
	// After rollback the final answer must be the ORIGINAL value again.
	for _, tr := range res.Traces {
		last := tr.Views[len(tr.Views)-1]
		var raws []string
		for _, r := range last.Answer.Records {
			raws = append(raws, r.Raw)
		}
		found := false
		for _, x := range raws {
			if x == "192.0.2.10" {
				found = true
			}
		}
		if !found {
			t.Fatalf("after rollback final view must show old record, got %v", raws)
		}
	}
	if res.EarliestConverged < 240 {
		t.Fatalf("rollback convergence must wait for rollback + TTL, got %d", res.EarliestConverged)
	}
}

func TestNegativeCacheOnDeletion(t *testing.T) {
	cur := mustZone(t, 1, `$TTL 60
@ SOA ns1 hostmaster 1 7200 3600 1209600 30
@ NS ns1
ns1 A 10.0.0.1
gone A 192.0.2.5
`)
	plan := dns.Plan{ZoneName: "example.test", Phases: []dns.Phase{{
		Name: "delete", MinObserveSec: 30,
		Operations: []dns.Operation{
			{Action: "delete", Name: "gone.example.test", Type: "A"},
			{Action: "upsert", Name: "example.test", Type: "SOA", TTL: 60,
				Data: []string{"ns1", "hostmaster", "2", "7200", "3600", "1209600", "30"},
				Raw:  "ns1 hostmaster 2 7200 3600 1209600 30"},
		}}}}
	in := Input{Base: cur, Plan: plan, Params: Parameters{
		AuthoritativeNodes: 1, RecursiveNodes: 1, MaxAuthDelaySec: 0,
		ProbeIntervalSec: 10, Seed: 1,
	}}
	res, err := Run(in)
	if err != nil {
		t.Fatal(err)
	}
	sawNegative := false
	for _, tr := range res.Traces {
		for _, v := range tr.Views {
			if v.Source == "negative_cache" {
				sawNegative = true
			}
		}
	}
	if !sawNegative {
		t.Fatal("expected negative cache entries after record deletion")
	}
}

func fingerprintResult(r *Result) string {
	return ParamsFingerprint(r.Params) + "|" + r.PlanFingerprint + "|" + r.DecisionFingerprint
}
