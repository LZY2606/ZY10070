package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"
)

func (s *Store) eventsPath() string { return filepath.Join(s.root, "events", "journal.jsonl") }

// AppendEvent durably appends one operational event and returns it with a
// monotonic sequence number.
func (s *Store) AppendEvent(typ, reqID, refID string, detail any) (Event, error) {
	s.mu.Lock()
	s.seq++
	ev := Event{Seq: s.seq, At: time.Now().UTC(), Type: typ, RequestID: reqID, RefID: refID, Detail: detail}
	s.mu.Unlock()

	line, err := json.Marshal(ev)
	if err != nil {
		return Event{}, err
	}
	line = append(line, '\n')
	f, err := os.OpenFile(s.eventsPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return Event{}, err
	}
	defer f.Close()
	if _, err := f.Write(line); err != nil {
		return Event{}, err
	}
	if err := f.Sync(); err != nil {
		return Event{}, err
	}
	return ev, nil
}

func (s *Store) maxEventSeq() int {
	events, err := s.ListEvents()
	if err != nil || len(events) == 0 {
		return 0
	}
	return events[len(events)-1].Seq
}

// ListEvents reads the whole journal ordered by sequence.
func (s *Store) ListEvents() ([]Event, error) {
	data, err := os.ReadFile(s.eventsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Event
	start := 0
	for start < len(data) {
		end := start
		for end < len(data) && data[end] != '\n' {
			end++
		}
		if end > start {
			var ev Event
			if err := json.Unmarshal(data[start:end], &ev); err == nil {
				out = append(out, ev)
			}
		}
		start = end + 1
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out, nil
}
