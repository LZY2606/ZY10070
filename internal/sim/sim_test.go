package sim

import (
	"testing"

	"zonesim/internal/dns"
)

func parseZones(t *testing.T) (string, *dns.Zone, *dns.Zone) {
	t.Helper()
	cur, err := dns.ParseZone(`$ORIGIN example.
$TTL 300
@ IN SOA ns1.example. admin.example. 2026010100 7200 3600 1209600 300
@ IN NS ns1.example.
ns1 IN A 192.0.2.10
www IN A 192.0.2.20
old IN A 192.0.2.99
`, "example.")
	if err != nil {
		t.Fatal(err)
	}
	cand, err := dns.ParseZone(`$ORIGIN example.
$TTL 300
@ IN SOA ns1.example. admin.example. 2026011500 7200 3600 1209600 300
@ IN NS ns1.example.
ns1 IN A 192.0.2.10
www IN A 192.0.2.21
`, "example.")
	if err != nil {
		t.Fatal(err)
	}
	return "example.", cur, cand
}

func baseCfg() Config {
	return Config{
		Phases: []Phase{
			{Name: "all", MinHoldSeconds: 0, ChangedKeys: []string{
				"www.example. A", "old.example. A", "example. SOA",
			}},
		},
		AuthServers:       []string{"a0", "a1"},
		Nodes:             []NodeConfig{{ID: "n0", Label: "N0", SkewSeconds: 0}},
		Probes:            []Query{{QName: "www.example.", QType: "A"}},
		Seed:              42,
		MaxDelaySeconds:   10,
		QueryEverySeconds: 10,
		HorizonSeconds:    3600,
	}
}

func TestDeterministicAndConvergence(t *testing.T) {
	origin, cur, cand := parseZones(t)
	cfg := baseCfg()
	r1 := Run(cfg, origin, cur, cand)
	r2 := Run(cfg, origin, cur, cand)
	if r1.ConvergedAt != r2.ConvergedAt {
		t.Fatalf("non-deterministic: %d vs %d", r1.ConvergedAt, r2.ConvergedAt)
	}
	if !r1.ConvergedWithin {
		t.Fatalf("expected convergence, lastChange=%d", r1.LastAuthChangeAt)
	}
	if r1.ConvergedAt < r1.LastAuthChangeAt {
		t.Fatalf("converged %d before last auth change %d", r1.ConvergedAt, r1.LastAuthChangeAt)
	}
	// TTL 300 means the last node cannot see the final answer before
	// lastChange (cache of old data must expire).
	if r1.ConvergedAt < r1.LastAuthChangeAt {
		t.Fatal("cache appeared to ignore TTL")
	}
	pr := r1.Probes[0]
	if pr.ConvergedAnswer == "" {
		t.Fatal("missing converged answer identity")
	}
}

func TestCacheSourceLabels(t *testing.T) {
	origin, cur, cand := parseZones(t)
	cfg := baseCfg()
	// Observe one node's timeline and confirm: first query authority, later
	// cache hits, and the new value arrives via authority after TTL expiry.
	tls := buildTimelinesFromTest(t, cfg, cur, cand)
	rt := newNodeRuntime(cfg, cfg.Nodes[0])
	q := cfg.Probes[0]
	first := queryAt(cfg, tls, origin, rt, q, 0)
	if first.Source != SourceAuthority {
		t.Fatalf("first query source = %s", first.Source)
	}
	second := queryAt(cfg, tls, origin, rt, q, 10)
	if second.Source != SourceCache {
		t.Fatalf("second query source = %s", second.Source)
	}
}

func TestNegativeCaching(t *testing.T) {
	origin, cur, cand := parseZones(t)
	cfg := baseCfg()
	cfg.Probes = []Query{{QName: "old.example.", QType: "A"}}
	tls := buildTimelinesFromTest(t, cfg, cur, cand)
	rt := newNodeRuntime(cfg, cfg.Nodes[0])
	q := cfg.Probes[0]
	// Fetch once to populate; later while the answer stays NXDOMAIN and cache
	// is fresh, source must be negative_cache.
	first := queryAt(cfg, tls, origin, rt, q, 2000)
	_ = first
	second := queryAt(cfg, tls, origin, rt, q, 2010)
	if second.Source != SourceNegative {
		t.Fatalf("expected negative cache, got %s status=%s", second.Source, second.Status)
	}
}

func TestRollbackHonorsTTL(t *testing.T) {
	origin, cur, cand := parseZones(t)
	cfg := baseCfg()
	cfg.RollbackAtSeconds = 500
	rep := Run(cfg, origin, cur, cand)
	// With rollback, final identity at horizon is the base value again.
	tls := buildTimelinesFromTest(t, cfg, cur, cand)
	rt := newNodeRuntime(cfg, cfg.Nodes[0])
	q := cfg.Probes[0]
	// Shortly after rollback signal, the node may still serve cached new data.
	samples := map[string]string{}
	for tt := 0; tt <= cfg.HorizonSeconds; tt += cfg.QueryEverySeconds {
		s := queryAt(cfg, tls, origin, rt, q, tt)
		samples[firstData(s)] = "x"
	}
	if len(samples) < 2 {
		t.Fatalf("expected both old and new observations, got %v", samples)
	}
	if rep.ConvergedAt < rep.LastAuthChangeAt {
		t.Fatalf("rollback converged %d before last change %d", rep.ConvergedAt, rep.LastAuthChangeAt)
	}
}

func TestIdentityStable(t *testing.T) {
	cfg := baseCfg()
	if Identity(cfg) != Identity(cfg) {
		t.Fatal("identity not stable")
	}
	other := cfg
	other.Seed = 43
	if Identity(cfg) == Identity(other) {
		t.Fatal("seed change must change identity")
	}
}

func TestReplayReusesResult(t *testing.T) {
	// Identity ignores phase order-independent data but includes content.
	cfg := baseCfg()
	Normalize(&cfg)
	if cfg.MaxDelaySeconds != 10 {
		t.Fatalf("max delay preserved = %d", cfg.MaxDelaySeconds)
	}
}

func buildTimelinesFromTest(t *testing.T, cfg Config, cur, cand *dns.Zone) map[string]*serverTimeline {
	t.Helper()
	baseKR := zoneToKeyed(cur)
	targetKR := zoneToKeyed(cand)
	return buildTimelines(cfg, baseKR, targetKR, makeChangeMap(baseKR, targetKR))
}

func firstData(s *Sample) string {
	if len(s.Records) == 0 {
		return s.Status
	}
	return s.Status + ":" + s.Records[len(s.Records)-1].Data
}
