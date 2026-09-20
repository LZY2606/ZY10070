package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const requestLog = "events/requests.jsonl"

// Event is an append-only business operation record.
type Event struct {
	Seq        int64           `json:"seq"`
	At         string          `json:"at"`
	RequestID  string          `json:"request_id"`
	Kind       string          `json:"kind"`
	ResourceID string          `json:"resource_id,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`
}

func (s *Store) loadRequests() error {
	// Request records are committed as standalone documents; re-materialize
	// them directly so the index never depends on log embedding.
	dir := filepath.Join(s.root, "events", "requests")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
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
		var rec RequestRecord
		if err := json.Unmarshal(b, &rec); err != nil {
			continue // ignore partial/garbage file
		}
		s.requests[rec.RequestID] = &rec
	}
	return nil
}

// LookupRequest returns a copy of the stored result for a request id.
func (s *Store) LookupRequest(requestID string) *RequestRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.requests[requestID]; ok {
		cp := *r
		return &cp
	}
	return nil
}

// PayloadFingerprint hashes normalized request payload for replay mismatch.
func PayloadFingerprint(raw []byte) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		h := sha256.Sum256(raw)
		return hex.EncodeToString(h[:])
	}
	canon, _ := json.Marshal(v)
	h := sha256.Sum256(canon)
	return hex.EncodeToString(h[:])
}

// Commit is the materialized result of one mutating request.
type Commit struct {
	Record      *RequestRecord
	EventBody   []byte
	EntityBytes []byte
	ResourceID  string
	Kind        string
}

// CompleteRequest atomically persists entity document + append-only event +
// request record. The entity document lands first, the event log is the commit
// marker, and the request record enables idempotent replay.
func (s *Store) CompleteRequest(c Commit) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec := c.Record
	rec.Status = "completed"
	if rec.CreatedAt == "" {
		rec.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	rec.Kind = c.Kind
	rec.ResourceID = c.ResourceID

	seq, err := s.nextSeqLocked()
	if err != nil {
		return err
	}
	ev := Event{Seq: seq, At: rec.CreatedAt, RequestID: rec.RequestID,
		Kind: "request_completed", ResourceID: c.ResourceID, Payload: c.EventBody}
	line, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	recBytes, err := json.Marshal(rec)
	if err != nil {
		return err
	}

	entityRel := ""
	switch c.Kind {
	case "zone":
		entityRel = filepath.Join("raw/zones", c.ResourceID+".json")
	case "plan":
		entityRel = filepath.Join("raw/plans", c.ResourceID+".json")
	case "simulation":
		entityRel = filepath.Join("derived/simulations", c.ResourceID+".json")
	case "export":
		entityRel = filepath.Join("derived/exports", c.ResourceID+".json")
	}
	if entityRel != "" {
		if err := s.writeAtomic(entityRel, c.EntityBytes); err != nil {
			return err
		}
		switch c.Kind {
		case "zone":
			s.zones[c.ResourceID] = c.EntityBytes
		case "plan":
			s.plans[c.ResourceID] = c.EntityBytes
		case "simulation":
			s.sims[c.ResourceID] = c.EntityBytes
		case "export":
			s.exports[c.ResourceID] = c.EntityBytes
		}
	}
	if err := s.appendEventLocked(append(line, '\n')); err != nil {
		return err
	}
	if err := s.writeAtomic(filepath.Join("events/requests", rec.RequestID+".json"), recBytes); err != nil {
		return err
	}
	s.requests[rec.RequestID] = rec
	return nil
}

func (s *Store) appendEventLocked(line []byte) error {
	path := filepath.Join(s.root, requestLog)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(line); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (s *Store) nextSeqLocked() (int64, error) {
	var lastSeq int64
	f, err := os.Open(filepath.Join(s.root, requestLog))
	if os.IsNotExist(err) {
		return 1, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	err = replayLog(f, func(ev Event, _ *RequestRecord) error {
		if ev.Seq > lastSeq {
			lastSeq = ev.Seq
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return lastSeq + 1, nil
}

// ListEvents returns events in sequence order.
func (s *Store) ListEvents() ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Open(filepath.Join(s.root, requestLog))
	if os.IsNotExist(err) {
		return []Event{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Event
	err = replayLog(f, func(ev Event, _ *RequestRecord) error {
		out = append(out, ev)
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out, err
}
