package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriteAndCrashCleanup(t *testing.T) {
	root := t.TempDir()
	st, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.writeAtomic("raw/zones/z1.json", []byte(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	// Simulate a half-written temp file left by a crashed process.
	if err := os.WriteFile(filepath.Join(root, "tmp", "doc-stale.json"), []byte(`{"partial":`), 0o644); err != nil {
		t.Fatal(err)
	}
	st2, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := st2.GetZone("z1")
	if !ok || string(b) != `{"v":1}` {
		t.Fatalf("committed doc missing after reopen: %s %v", b, ok)
	}
	entries, _ := os.ReadDir(filepath.Join(root, "tmp"))
	if len(entries) != 0 {
		t.Fatalf("stale temp files must be cleaned, got %d", len(entries))
	}
}

func TestIdempotentRequestReplay(t *testing.T) {
	root := t.TempDir()
	st, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	rec := &RequestRecord{RequestID: "req-1", Endpoint: "POST /api/zones",
		Fingerprint: "fp1", Response: json.RawMessage(`{"zone_id":"z1"}`)}
	body := json.RawMessage(`{}`)
	if err := st.CompleteRequest(Commit{Record: rec, EventBody: body,
		EntityBytes: []byte(`{"id":"z1"}`), ResourceID: "z1", Kind: "zone"}); err != nil {
		t.Fatal(err)
	}
	zonesBefore := len(st.ListZones())
	got := st.LookupRequest("req-1")
	if got == nil || string(got.Response) != `{"zone_id":"z1"}` {
		t.Fatalf("replay record mismatch: %+v", got)
	}
	// Reopening re-materializes the request index from the append-only log.
	st2, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	if st2.LookupRequest("req-1") == nil {
		t.Fatal("request must survive restart")
	}
	if len(st2.ListZones()) != zonesBefore {
		t.Fatal("replay must not create a second business result")
	}
	events, err := st2.ListEvents()
	if err != nil || len(events) != 1 {
		t.Fatalf("expected exactly one event, got %d err=%v", len(events), err)
	}
}

func TestRawDerivedEventsSeparation(t *testing.T) {
	root := t.TempDir()
	st, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	rec := &RequestRecord{RequestID: "r", Fingerprint: "f", Response: json.RawMessage(`{}`)}
	_ = st.CompleteRequest(Commit{Record: rec, EventBody: []byte(`{}`),
		EntityBytes: []byte(`{}`), ResourceID: "s1", Kind: "simulation"})
	for _, rel := range []string{"derived/simulations/s1.json", "events/requests/r.json", "events/requests.jsonl"} {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Fatalf("expected %s on disk: %v", rel, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "raw/zones/s1.json")); !os.IsNotExist(err) {
		t.Fatal("derived simulation must not be written under raw/")
	}
}
