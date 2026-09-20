package store

import (
	"encoding/json"
	"errors"
	"path/filepath"
)

const (
	claimClaimed = "claimed"
	claimDone    = "done"
)

// claim records the lifecycle of one client-supplied request id.
type claim struct {
	RequestID string `json:"request_id"`
	Kind      Kind   `json:"kind"`
	State     string `json:"state"`
	ResultID  string `json:"result_id,omitempty"`
	CreatedAt string `json:"created_at"`
}

// ErrClaimExists means the same request id is already (or has already been)
// processed. The caller can fetch ResultID to replay the original response.
var ErrClaimExists = errors.New("request id already processed")

// ClaimResult is the outcome of BeginRequest.
type ClaimResult struct {
	Replay   bool
	ResultID string
}

func (s *Store) claimPath(reqID string) string {
	return filepath.Join(s.root, "requests", sanitize(reqID)+".json")
}

// BeginRequest implements at-most-once semantics for mutating requests.
// A brand-new request id is claimed; a repeat returns the original result id
// without running the business logic a second time.
func (s *Store) BeginRequest(reqID string, kind Kind) (*ClaimResult, error) {
	if reqID == "" {
		return &ClaimResult{}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if id, ok := s.pending[reqID]; ok {
		return &ClaimResult{Replay: true, ResultID: id}, nil
	}
	path := s.claimPath(reqID)
	data, err := readJSON(path)
	if err == nil {
		var c claim
		jerr := json.Unmarshal(data, &c)
		if jerr == nil && c.State == claimDone {
			return &ClaimResult{Replay: true, ResultID: c.ResultID}, nil
		}
		if jerr == nil && c.State == claimClaimed {
			// Same process holds it; treat concurrent duplicate as a replay
			// against whatever is registered in memory.
			if id, ok := s.pending[reqID]; ok {
				return &ClaimResult{Replay: true, ResultID: id}, nil
			}
		}
		return nil, ErrClaimExists
	}
	c := claim{RequestID: reqID, Kind: kind, State: claimClaimed}
	if err := s.atomicWrite(path, mustJSON(c)); err != nil {
		return nil, err
	}
	s.pending[reqID] = ""
	return &ClaimResult{}, nil
}

// CompleteRequest finalises a claim with the created result document id.
func (s *Store) CompleteRequest(reqID, resultID string) error {
	if reqID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := claim{RequestID: reqID, State: claimDone, ResultID: resultID}
	if err := s.atomicWrite(s.claimPath(reqID), mustJSON(c)); err != nil {
		return err
	}
	s.pending[reqID] = resultID
	return nil
}

// FailRequest releases an in-memory claim for a business-logic failure so the
// client can retry with the same request id. The on-disk "claimed" marker is
// removed too; if the process died instead, recovery would clean it on boot.
func (s *Store) FailRequest(reqID string) {
	if reqID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pending, reqID)
	_ = removeIfExists(s.claimPath(reqID))
}

func readJSON(path string) ([]byte, error) {
	return readFile(path)
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
