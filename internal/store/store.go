package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Store persists raw inputs, derived results and operation events separately.
// All writes are atomic: a crash mid-write never exposes a half-written
// document. Replays carrying the same request_id never create a second
// business result.
type Store struct {
	root string
	mu   sync.Mutex

	requests map[string]*RequestRecord // request_id -> record
	zones    map[string][]byte         // zone id -> raw json
	plans    map[string][]byte         // plan id -> raw json
	sims     map[string][]byte         // sim id -> derived json
	exports  map[string][]byte         // export id -> derived json
}

// RequestRecord captures idempotency state for one client request.
type RequestRecord struct {
	RequestID   string          `json:"request_id"`
	Endpoint    string          `json:"endpoint"`
	Fingerprint string          `json:"fingerprint"` // hash of normalized payload
	Status      string          `json:"status"`      // completed
	CreatedAt   string          `json:"created_at"`
	Response    json.RawMessage `json:"response"`
	Kind        string          `json:"kind"`
	ResourceID  string          `json:"resource_id"`
}

// New opens (and if necessary initializes) the on-disk layout.
func New(root string) (*Store, error) {
	for _, d := range []string{"raw/zones", "raw/plans", "derived/simulations", "derived/exports", "events", "tmp"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			return nil, err
		}
	}
	s := &Store{
		root:     root,
		requests: map[string]*RequestRecord{},
		zones:    map[string][]byte{},
		plans:    map[string][]byte{},
		sims:     map[string][]byte{},
		exports:  map[string][]byte{},
	}
	if err := s.cleanupTemp(); err != nil {
		return nil, err
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) cleanupTemp() error {
	tmp := filepath.Join(s.root, "tmp")
	entries, err := os.ReadDir(tmp)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(tmp, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) load() error {
	if err := s.loadRequests(); err != nil {
		return err
	}
	loadDir := func(dir string, into map[string][]byte) error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				return err
			}
			id := e.Name()[:len(e.Name())-len(".json")]
			into[id] = b
		}
		return nil
	}
	if err := loadDir(filepath.Join(s.root, "raw/zones"), s.zones); err != nil {
		return err
	}
	if err := loadDir(filepath.Join(s.root, "raw/plans"), s.plans); err != nil {
		return err
	}
	if err := loadDir(filepath.Join(s.root, "derived/simulations"), s.sims); err != nil {
		return err
	}
	return loadDir(filepath.Join(s.root, "derived/exports"), s.exports)
}

// sortedIDs is a small helper for listing endpoints.
func sortedIDs(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
