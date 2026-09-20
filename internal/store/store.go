// Package store is the file-backed persistence layer. Raw inputs (imported
// zones), derived results (plans, simulations, exports) and operational events
// live in separate directories. Every document write is atomic (temp file,
// fsync, rename) so a crash mid-persist never exposes a half-written record.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	// ErrNotFound is returned for unknown document ids.
	ErrNotFound = errors.New("document not found")
	// ErrConflict is returned on optimistic state conflicts.
	ErrConflict = errors.New("state conflict")
)

// Kind enumerates document categories.
type Kind string

const (
	KindZone       Kind = "zones"
	KindPlan       Kind = "plans"
	KindSimulation Kind = "simulations"
	KindExport     Kind = "exports"
)

// Event is an append-only operational event.
type Event struct {
	Seq       int       `json:"seq"`
	At        time.Time `json:"at"`
	Type      string    `json:"type"`
	RequestID string    `json:"request_id,omitempty"`
	RefID     string    `json:"ref_id,omitempty"`
	Detail    any       `json:"detail,omitempty"`
}

// Store is safe for concurrent use.
type Store struct {
	root string
	mu   sync.Mutex
	seq  int
	lock *os.File

	pending map[string]string // request id -> result doc id (in-process claims)
}

// Open prepares the directory tree, takes an exclusive advisory lock (so a
// second process cannot corrupt the same data directory) and recovers any
// temp files or unfinished idempotency claims left by a crashed process.
func Open(root string) (*Store, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	for _, d := range []string{"raw/zones", "derived/plans", "derived/simulations", "derived/exports", "events", "tmp", "requests"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			return nil, err
		}
	}
	lock, err := os.OpenFile(filepath.Join(root, "lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := tryFileLock(lock); err != nil {
		lock.Close()
		return nil, fmt.Errorf("data directory locked by another process: %w", err)
	}
	s := &Store{root: root, pending: map[string]string{}}
	s.lock = lock
	if err := s.recover(); err != nil {
		return nil, err
	}
	s.seq = s.maxEventSeq()
	return s, nil
}

// Close releases the advisory data-directory lock.
func (s *Store) Close() error {
	if s.lock == nil {
		return nil
	}
	_ = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
	err := s.lock.Close()
	s.lock = nil
	return err
}

func tryFileLock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

// recover removes stale temp files and resolves crashed idempotency claims.
func (s *Store) recover() error {
	tmpDir := filepath.Join(s.root, "tmp")
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		_ = os.Remove(filepath.Join(tmpDir, e.Name()))
	}
	reqDir := filepath.Join(s.root, "requests")
	reqs, err := os.ReadDir(reqDir)
	if err != nil {
		return err
	}
	for _, e := range reqs {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(reqDir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var c claim
		if err := json.Unmarshal(data, &c); err != nil {
			_ = os.Remove(path)
			continue
		}
		if c.State == claimDone && c.ResultID != "" {
			if exists(s.kindDir(c.Kind), c.ResultID) {
				continue
			}
		}
		// Claimed but result never landed: the previous process crashed
		// mid-write, so remove the claim and allow one fresh execution.
		_ = os.Remove(path)
	}
	return nil
}

func exists(dir, id string) bool {
	_, err := os.Stat(filepath.Join(dir, sanitize(id)+".json"))
	return err == nil
}

func sanitize(id string) string {
	id = strings.ReplaceAll(id, "/", "_")
	id = strings.ReplaceAll(id, "..", "_")
	return id
}

func (s *Store) kindDir(k Kind) string {
	switch k {
	case KindZone:
		return filepath.Join(s.root, "raw", "zones")
	case KindPlan:
		return filepath.Join(s.root, "derived", "plans")
	case KindSimulation:
		return filepath.Join(s.root, "derived", "simulations")
	case KindExport:
		return filepath.Join(s.root, "derived", "exports")
	}
	return filepath.Join(s.root, "derived", string(k))
}

// Path is the on-disk location of one document.
func (s *Store) Path(k Kind, id string) string {
	return filepath.Join(s.kindDir(k), sanitize(id)+".json")
}

// Put atomically persists doc under (kind,id).
func (s *Store) Put(k Kind, id string, doc any) error {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return s.atomicWrite(s.Path(k, id), data)
}

func (s *Store) atomicWrite(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Join(s.root, "tmp"), "doc-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return syncDir(filepath.Dir(path))
}

// Get loads one document into out.
func (s *Store) Get(k Kind, id string, out any) error {
	data, err := os.ReadFile(s.Path(k, id))
	if err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return err
	}
	return json.Unmarshal(data, out)
}

// List returns document ids of a kind in lexical order.
func (s *Store) List(k Kind) ([]string, error) {
	entries, err := os.ReadDir(s.kindDir(k))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".json") {
			out = append(out, strings.TrimSuffix(name, ".json"))
		}
	}
	sort.Strings(out)
	return out, nil
}

// Delete removes one document.
func (s *Store) Delete(k Kind, id string) error {
	err := os.Remove(s.Path(k, id))
	if os.IsNotExist(err) {
		return ErrNotFound
	}
	return err
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return nil
	}
	defer d.Close()
	return d.Sync()
}
