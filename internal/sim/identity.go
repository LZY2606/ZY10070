package sim

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// Defaults applied to a simulation configuration before running.
const (
	DefaultMaxDelay   = 60
	DefaultQueryEvery = 30
	DefaultHorizon    = 86400
)

// Normalize fills defaults, sorts key lists and validates basic invariants.
func Normalize(cfg *Config) error {
	if len(cfg.AuthServers) == 0 {
		cfg.AuthServers = []string{"a0", "a1", "a2", "a3"}
	}
	sort.Strings(cfg.AuthServers)
	if len(cfg.Nodes) == 0 {
		nodes := []NodeConfig{
			{ID: "tokyo", Label: "Tokyo", SkewSeconds: 0},
			{ID: "fra", Label: "Frankfurt", SkewSeconds: 45},
			{ID: "sjc", Label: "San Jose", SkewSeconds: -30},
		}
		cfg.Nodes = nodes
	}
	if cfg.MaxDelaySeconds <= 0 {
		cfg.MaxDelaySeconds = DefaultMaxDelay
	}
	if cfg.QueryEverySeconds <= 0 {
		cfg.QueryEverySeconds = DefaultQueryEvery
	}
	if cfg.HorizonSeconds <= 0 {
		cfg.HorizonSeconds = DefaultHorizon
	}
	if cfg.RollbackAtSeconds < 0 {
		cfg.RollbackAtSeconds = 0
	}
	if cfg.RollbackAtSeconds >= cfg.HorizonSeconds {
		cfg.RollbackAtSeconds = 0
	}
	for i := range cfg.Phases {
		if cfg.Phases[i].MinHoldSeconds < 0 {
			cfg.Phases[i].MinHoldSeconds = 0
		}
		sort.Strings(cfg.Phases[i].ChangedKeys)
	}
	seen := map[string]bool{}
	for _, n := range cfg.Nodes {
		if n.ID == "" {
			return errInvalid("node id must not be empty")
		}
		if seen[n.ID] {
			return errInvalid("duplicate node id " + n.ID)
		}
		seen[n.ID] = true
	}
	for _, p := range cfg.Probes {
		if p.QName == "" || p.QType == "" {
			return errInvalid("probe requires qname and qtype")
		}
	}
	return nil
}

type validationError struct{ msg string }

func (e *validationError) Error() string { return e.msg }
func errInvalid(msg string) error        { return &validationError{msg: msg} }

// IsValidationError reports whether err is a simulation configuration error.
func IsValidationError(err error) bool {
	_, ok := err.(*validationError)
	return ok
}

// Identity is the deterministic hash of everything that influences results:
// both zone fingerprints, seed, nodes, probes, delays, horizon, rollback and
// every phase. Repeating a simulation with the same identity reuses results.
func Identity(cfg Config) string {
	cp := cfg
	cp.Phases = append([]Phase(nil), cfg.Phases...)
	b, _ := json.Marshal(cp)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
