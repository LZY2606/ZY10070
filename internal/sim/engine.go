package sim

import (
	"math/rand"
	"sort"
	"strings"

	"zonesim/internal/dns"
)

// Fixed clock origin keeps deterministic simulations independent of wall time.
const ReferenceEpoch int64 = 1700000000 // 2023-11-14T22:13:20Z

// Parameters controls the simulated fleet and timeline.
type Parameters struct {
	AuthoritativeNodes int     `json:"authoritative_nodes"`
	RecursiveNodes     int     `json:"recursive_nodes"`
	MaxAuthDelaySec    int     `json:"max_auth_delay_sec"`
	MaxRecvDelaySec    int     `json:"max_recv_delay_sec"`
	MaxClockSkewSec    int     `json:"max_clock_skew_sec"`
	ProbeIntervalSec   int     `json:"probe_interval_sec"`
	Seed               int64   `json:"seed"`
	ExtraQueries       []Query `json:"extra_queries,omitempty"`
}

// Query is a monitored lookup.
type Query struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Decision records an operator action at an absolute reference time.
type Decision struct {
	PhaseIndex int    `json:"phase_index"`
	Action     string `json:"action"` // proceed | rollback
	AtSec      int    `json:"at_sec"`
	Note       string `json:"note,omitempty"`
}

// NodeView is one recursive node's answer at one probe.
type NodeView struct {
	ProbeIndex int    `json:"probe_index"`
	AtSec      int    `json:"at_sec"`
	Source     string `json:"source"` // authoritative | cache | negative_cache
	Answer     `json:"answer"`
}

// QueryTrace holds all node views for one monitored query.
type QueryTrace struct {
	Query Query      `json:"query"`
	Views []NodeView `json:"views"`
}

// Convergence reports when a node and the fleet reach the final answer.
type Convergence struct {
	Query            Query          `json:"query"`
	FinalCanonical   string         `json:"final_canonical"`
	NodeConvergedSec map[string]int `json:"node_converged_sec"`
	AllConvergedSec  int            `json:"all_converged_sec"`
}

// Event is a scheduled authoritative zone-state transition.
type Event struct {
	AtSec      int    `json:"at_sec"`
	AuthNode   string `json:"auth_node"`
	FromZoneFp string `json:"from_zone_fp"`
	ToZoneFp   string `json:"to_zone_fp"`
	PhaseIndex int    `json:"phase_index"`
	Kind       string `json:"kind"` // phase | rollback
}

// Result is the full deterministic simulation output.
type Result struct {
	ID                  string        `json:"id"`
	PlanFingerprint     string        `json:"plan_fingerprint"`
	ParamsFingerprint   string        `json:"params_fingerprint"`
	DecisionFingerprint string        `json:"decision_fingerprint"`
	BaseZoneFp          string        `json:"base_zone_fp"`
	Params              Parameters    `json:"parameters"`
	Queries             []Query       `json:"queries"`
	PhaseSchedule       []PhaseTiming `json:"phase_schedule"`
	AuthNodes           []AuthNode    `json:"auth_nodes"`
	RecvNodes           []RecvNode    `json:"recv_nodes"`
	Events              []Event       `json:"events"`
	Traces              []QueryTrace  `json:"traces"`
	Convergence         []Convergence `json:"convergence"`
	EarliestConverged   int           `json:"earliest_all_converged_sec"`
	HorizonSec          int           `json:"horizon_sec"`
	StableFromSec       int           `json:"stable_from_sec"`
	Decisions           []Decision    `json:"decisions"`
}

// PhaseTiming records scheduled/actual timing for a phase.
type PhaseTiming struct {
	Index        int    `json:"index"`
	Name         string `json:"name"`
	EarliestSec  int    `json:"earliest_sec"`
	DecidedSec   int    `json:"decided_sec"`
	AppliedAtSec int    `json:"applied_at_sec"` // earliest auth node applied
	StableAtSec  int    `json:"stable_at_sec"`  // slowest auth node applied
}

// AuthNode is an authoritative server with propagation delay.
type AuthNode struct {
	ID           string `json:"id"`
	DelaySec     int    `json:"delay_sec"`
	ClockSkewSec int    `json:"clock_skew_sec"`
}

// RecvNode is a recursive resolver with delay, skew and an independent cache.
type RecvNode struct {
	ID           string `json:"id"`
	DelaySec     int    `json:"delay_sec"`
	ClockSkewSec int    `json:"clock_skew_sec"`
}

// Answer re-exports the DNS answer shape for JSON embedding convenience.
type Answer = dns.Answer

// Defaults fills missing parameters with deterministic fleet defaults.
func (p *Parameters) Defaults() {
	if p.AuthoritativeNodes <= 0 {
		p.AuthoritativeNodes = 3
	}
	if p.RecursiveNodes <= 0 {
		p.RecursiveNodes = 3
	}
	if p.MaxAuthDelaySec <= 0 {
		p.MaxAuthDelaySec = 60
	}
	if p.MaxRecvDelaySec <= 0 {
		p.MaxRecvDelaySec = 5
	}
	if p.MaxClockSkewSec <= 0 {
		p.MaxClockSkewSec = 30
	}
	if p.ProbeIntervalSec <= 0 {
		p.ProbeIntervalSec = 30
	}
}

func (p Parameters) sortedExtra() []Query {
	q := append([]Query(nil), p.ExtraQueries...)
	sort.Slice(q, func(i, j int) bool {
		if q[i].Name != q[j].Name {
			return q[i].Name < q[j].Name
		}
		return q[i].Type < q[j].Type
	})
	return q
}

func normQueries(qs []Query) {
	for i := range qs {
		qs[i].Name = strings.TrimSuffix(strings.ToLower(qs[i].Name), ".")
		qs[i].Type = strings.ToUpper(qs[i].Type)
	}
}

var _ = rand.New
