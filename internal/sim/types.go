// Package sim runs deterministic time-stepped resolution simulations over a
// staged zone release. Each recursive node has its own (seeded) clock skew,
// preferred authoritative server and cache; answers are labelled as coming
// from authority, a positive cache hit or a negative cache hit.
package sim

import (
	"time"

	"zonesim/internal/dns"
)

// Epoch anchors simulation second 0 as wall-clock time.
var Epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// Phase is one release stage. ChangedKeys is the subset of RRset keys
// ("name TYPE") that may flip in this phase. MinHoldSeconds is the minimum
// observation time before the next stage may apply.
type Phase struct {
	Name           string   `json:"name"`
	ChangedKeys    []string `json:"changed_keys"`
	MinHoldSeconds int      `json:"min_hold_seconds"`
}

// NodeConfig describes one recursive resolver.
type NodeConfig struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	SkewSeconds int    `json:"skew_seconds"`
}

// Config is a fully determined simulation request.
type Config struct {
	CurrentFingerprint   string       `json:"current_fingerprint"`
	CandidateFingerprint string       `json:"candidate_fingerprint"`
	Phases               []Phase      `json:"phases"`
	AuthServers          []string     `json:"auth_servers"`
	Nodes                []NodeConfig `json:"nodes"`
	Probes               []Query      `json:"probes"`
	Seed                 int64        `json:"seed"`
	MaxDelaySeconds      int          `json:"max_delay_seconds"`
	QueryEverySeconds    int          `json:"query_every_seconds"`
	HorizonSeconds       int          `json:"horizon_seconds"`
	RollbackAtSeconds    int          `json:"rollback_at_seconds,omitempty"`
}

// Query is one (name,type) probe.
type Query struct {
	QName string `json:"qname"`
	QType string `json:"qtype"`
}

func (q Query) key() string { return q.QName + " " + q.QType }

// Evidence sources.
const (
	SourceAuthority = "authority"
	SourceCache     = "cache"
	SourceNegative  = "negative_cache"
)

// Security states reported per answer.
const (
	Secure   = "secure"
	Insecure = "insecure"
	Bogus    = "bogus"
)

// Sample is one recursive node's view of a probe at one query instant.
type Sample struct {
	AtSeconds int          `json:"at_seconds"`
	Source    string       `json:"source"`
	Status    string       `json:"status"`
	Security  string       `json:"security"`
	Wildcard  string       `json:"wildcard,omitempty"`
	TTL       uint32       `json:"ttl"`
	Records   []dns.Record `json:"records"`
	Reason    string       `json:"reason,omitempty"`
	Server    string       `json:"server"`
}

// AnswerFingerprint is a compact, TTL-independent identity of the observable
// wire answer (status, records, wildcard, security).
func (s *Sample) AnswerFingerprint() string {
	return answerIdentity(s.Status, s.Security, s.Wildcard, s.Records)
}

// Interval describes a time range [From, To) during which a node's answer to
// a probe is constant. From==To marks a single fetch instant.
type Interval struct {
	From   int     `json:"from"`
	To     int     `json:"to"`
	Source string  `json:"source"`
	Sample *Sample `json:"sample"`
}

// NodeSeries holds one node's timeline for one probe.
type NodeSeries struct {
	NodeID    string     `json:"node_id"`
	Intervals []Interval `json:"intervals"`
}

// ProbeReport is the per-probe result across nodes, including convergence.
type ProbeReport struct {
	Query           Query        `json:"query"`
	Series          []NodeSeries `json:"series"`
	ConvergedAt     int          `json:"converged_at"`
	ConvergedAnswer string       `json:"converged_answer"`
	ConvergedWithin bool         `json:"converged_within"`
}

// Report is the whole deterministic output of a simulation run.
type Report struct {
	HorizonSeconds      int            `json:"horizon_seconds"`
	LastAuthChangeAt    int            `json:"last_auth_change_at"`
	FinalStableFrom     int            `json:"final_stable_from"`
	ConvergedAt         int            `json:"converged_at"`
	ConvergedWithin     bool           `json:"converged_within"`
	RollbackConvergedAt int            `json:"rollback_converged_at,omitempty"`
	Probes              []ProbeReport  `json:"probes"`
	AuthReadyAt         map[string]int `json:"auth_ready_at"`
}

// Simulation is the persisted simulation document.
type Simulation struct {
	ID                   string    `json:"id"`
	PlanID               string    `json:"plan_id"`
	Identity             string    `json:"identity"`
	Seed                 int64     `json:"seed"`
	CurrentFingerprint   string    `json:"current_fingerprint"`
	CandidateFingerprint string    `json:"candidate_fingerprint"`
	Config               Config    `json:"config"`
	Report               *Report   `json:"report"`
	RollbackReport       *Report   `json:"rollback_report,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
	CurrentAtSeconds     int       `json:"current_at_seconds,omitempty"`
}
