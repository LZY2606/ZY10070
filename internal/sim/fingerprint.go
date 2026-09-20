package sim

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"zonesim/internal/dns"
)

func canonicalHash(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// PlanFingerprint identifies the normalized staged plan.
func PlanFingerprint(p dns.Plan) string {
	type op struct {
		A   string `json:"a"`
		N   string `json:"n"`
		T   string `json:"t"`
		TTL int    `json:"ttl"`
		Raw string `json:"raw"`
	}
	type ph struct {
		Name string `json:"name"`
		Obs  int    `json:"obs"`
		Ops  []op   `json:"ops"`
	}
	out := struct {
		Zone   string `json:"zone"`
		Phases []ph   `json:"phases"`
	}{Zone: p.ZoneName}
	for _, p0 := range p.Phases {
		np := ph{Name: p0.Name, Obs: p0.MinObserveSec}
		for _, o := range p0.Operations {
			np.Ops = append(np.Ops, op{A: o.Action, N: o.Name, T: o.Type, TTL: o.TTL, Raw: o.Raw})
		}
		out.Phases = append(out.Phases, np)
	}
	return canonicalHash(out)
}

// ParamsFingerprint identifies the fleet/timeline parameters incl. seed.
func ParamsFingerprint(p Parameters) string {
	p.Defaults()
	return canonicalHash(struct {
		Auth  int     `json:"auth"`
		Recv  int     `json:"recv"`
		AD    int     `json:"a_delay"`
		RD    int     `json:"r_delay"`
		Skew  int     `json:"skew"`
		Grid  int     `json:"grid"`
		Seed  int64   `json:"seed"`
		Extra []Query `json:"extra"`
	}{p.AuthoritativeNodes, p.RecursiveNodes, p.MaxAuthDelaySec, p.MaxRecvDelaySec,
		p.MaxClockSkewSec, p.ProbeIntervalSec, p.Seed, p.sortedExtra()})
}

// DecisionFingerprint identifies the recorded operator decisions.
func DecisionFingerprint(ds []Decision) string {
	return canonicalHash(ds)
}
