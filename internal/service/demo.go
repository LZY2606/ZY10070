package service

import "zonesim/internal/sim"

// DemoBundle is the seeded demonstration data.
type DemoBundle struct {
	Current   *ZoneDoc `json:"current"`
	Candidate *ZoneDoc `json:"candidate"`
	Plan      *Plan    `json:"plan"`
	BadPlan   *Plan    `json:"blocked_plan,omitempty"`
}

const demoCurrent = `$ORIGIN example.
$TTL 300
@   IN SOA ns1.example. admin.example. 2026010100 7200 3600 1209600 300
@   IN NS  ns1.example.
@   IN NS  ns2.example.
ns1 IN A   192.0.2.10
ns2 IN A   192.0.2.11
@   IN A   192.0.2.1
www IN A   192.0.2.20
api IN CNAME www.example.
old IN A   192.0.2.99
`

const demoCandidate = `$ORIGIN example.
$TTL 300
@   IN SOA ns1.example. admin.example. 2026011500 7200 3600 1209600 300
@   IN NS  ns1.example.
@   IN NS  ns2.example.
ns1 IN A   192.0.2.10
ns2 IN A   192.0.2.11
@   IN A   192.0.2.1
www IN A   192.0.2.21
www IN A   198.51.100.21
api IN CNAME www.example.
shop IN A 203.0.113.7
`

// A candidate that must be blocked: serial moved backwards and the www CNAME
// forms a loop with cname2.
const demoBadCandidate = `$ORIGIN example.
$TTL 300
@   IN SOA ns1.example. admin.example. 2026010000 7200 3600 1209600 300
@   IN NS  ns1.example.
@   IN NS  ns2.example.
ns1 IN A   192.0.2.10
ns2 IN A   192.0.2.11
@   IN A   192.0.2.1
www IN A   192.0.2.20
www IN AAAA 2001:db8::20
api IN CNAME www.example.
loop1 IN CNAME loop2.example.
loop2 IN CNAME loop1.example.
`

// SeedDemo imports the demo zones and builds a valid phased plan plus a plan
// that is blocked by pre-publish validation.
func (s *Service) SeedDemo() (*DemoBundle, error) {
	cur, err := s.ImportZone(ImportZoneInput{Label: "current (example.com)", Origin: "example.", Text: demoCurrent})
	if err != nil {
		return nil, err
	}
	cand, err := s.ImportZone(ImportZoneInput{Label: "candidate (example.com)", Origin: "example.", Text: demoCandidate})
	if err != nil {
		return nil, err
	}
	bad, err := s.ImportZone(ImportZoneInput{Label: "blocked candidate (example.com)", Origin: "example.", Text: demoBadCandidate})
	if err != nil {
		return nil, err
	}
	plan, err := s.CreatePlan(CreatePlanInput{
		CurrentZoneID: cur.ID, CandidateZoneID: cand.ID,
		Phases: []sim.Phase{
			{Name: "stage-1-www", MinHoldSeconds: 600, ChangedKeys: []string{
				"www.example. A", "old.example. A",
			}},
			{Name: "stage-2-rest", MinHoldSeconds: 900, ChangedKeys: []string{
				"example. SOA", "shop.example. A",
			}},
		},
	})
	if err != nil {
		return nil, err
	}
	badPlan, err := s.CreatePlan(CreatePlanInput{
		CurrentZoneID: cur.ID, CandidateZoneID: bad.ID,
		Phases: []sim.Phase{
			{Name: "everything", MinHoldSeconds: 300, ChangedKeys: []string{
				"www.example. AAAA", "loop1.example. CNAME", "loop2.example. CNAME",
				"example. SOA", "old.example. A",
			}},
		},
	})
	if err != nil {
		return nil, err
	}
	return &DemoBundle{Current: cur, Candidate: cand, Plan: plan, BadPlan: badPlan}, nil
}
