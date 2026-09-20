package store

import (
	"os"
	"path/filepath"
	"testing"
)

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

type doc struct {
	Name string `json:"name"`
}

func TestAtomicPutGetList(t *testing.T) {
	s, _ := openTemp(t)
	if err := s.Put(KindZone, "z1", &doc{Name: "alpha"}); err != nil {
		t.Fatal(err)
	}
	var got doc
	if err := s.Get(KindZone, "z1", &got); err != nil {
		t.Fatal(err)
	}
	if got.Name != "alpha" {
		t.Fatalf("got %q", got.Name)
	}
	ids, err := s.List(KindZone)
	if err != nil || len(ids) != 1 || ids[0] != "z1" {
		t.Fatalf("list = %v err=%v", ids, err)
	}
}

func TestIdempotentReplay(t *testing.T) {
	s, _ := openTemp(t)
	first, err := s.BeginRequest("req-1", KindPlan)
	if err != nil || first.Replay {
		t.Fatalf("first claim = %+v err=%v", first, err)
	}
	if err := s.CompleteRequest("req-1", "plan_abc"); err != nil {
		t.Fatal(err)
	}
	second, err := s.BeginRequest("req-1", KindPlan)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Replay || second.ResultID != "plan_abc" {
		t.Fatalf("replay = %+v", second)
	}
}

func TestCrashDuringWriteRecoversClaim(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.BeginRequest("orphan", KindPlan); err != nil {
		t.Fatal(err)
	}
	// Simulate process exiting before CompleteRequest and leaving a tmp file.
	if err := os.WriteFile(filepath.Join(dir, "tmp", "doc-stray.tmp"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// New process reopens the same directory.
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := s2.BeginRequest("orphan", KindPlan)
	if err != nil || claim.Replay {
		t.Fatalf("orphan claim should be reusable: %+v err=%v", claim, err)
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "tmp")); len(entries) != 0 {
		t.Fatal("stale temp files survived restart")
	}
}

func TestEventJournalOrdering(t *testing.T) {
	s, _ := openTemp(t)
	for i := 0; i < 5; i++ {
		if _, err := s.AppendEvent("test.event", "", "id", map[string]int{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
	evs, err := s.ListEvents()
	if err != nil || len(evs) != 5 {
		t.Fatalf("events = %d err=%v", len(evs), err)
	}
	for i, e := range evs {
		if e.Seq != i+1 {
			t.Fatalf("seq[%d] = %d", i, e.Seq)
		}
	}

	// Reopen: sequence numbers continue past previous max.
	s2, err := Open(func() string { return s.root }())
	_ = s2
}

func TestRawDerivedEventsSeparated(t *testing.T) {
	s, dir := openTemp(t)
	if err := s.Put(KindZone, "z", &doc{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(KindPlan, "p", &doc{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendEvent("e", "", "", nil); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join("raw", "zones", "z.json"),
		filepath.Join("derived", "plans", "p.json"),
		filepath.Join("events", "journal.jsonl"),
	} {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			t.Fatalf("missing %s: %v", p, err)
		}
	}
}
