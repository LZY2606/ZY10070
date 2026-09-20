package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"zonesim/internal/service"
)

func newServer(t *testing.T) (*httptest.Server, *service.Service) {
	t.Helper()
	svc, err := service.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(New(svc)), svc
}

func do(t *testing.T, method, url, reqID string, body any) (int, map[string]any, http.Header) {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, url, rdr)
	req.Header.Set("Content-Type", "application/json")
	if reqID != "" {
		req.Header.Set("X-Request-Id", reqID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, resp.Header
}

func TestErrorClassification(t *testing.T) {
	srv, _ := newServer(t)
	defer srv.Close()

	// Malformed JSON -> 400 invalid_request.
	status, body, _ := do(t, "POST", srv.URL+"/api/zones", "", map[string]any{"text": "x"})
	// Valid shape but bad content: missing SOA -> parse failure 400.
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v", status, body)
	}
	cls, _ := body["error"].(map[string]any)
	if cls["class"] != "invalid_request" {
		t.Fatalf("class = %v", cls)
	}

	// Not found -> 404.
	status, body, _ = do(t, "GET", srv.URL+"/api/zones/missing", "", nil)
	if status != http.StatusNotFound {
		t.Fatalf("status=%d", status)
	}
	if body["error"].(map[string]any)["class"] != "not_found" {
		t.Fatal("expected not_found class")
	}
}

func TestIdempotencyKey(t *testing.T) {
	srv, _ := newServer(t)
	defer srv.Close()

	zoneBody := map[string]any{"label": "z", "origin": "example.", "text": `$ORIGIN example.
$TTL 300
@ IN SOA ns1.example. admin.example. 1 7200 3600 1209600 300
@ IN NS ns1.example.
ns1 IN A 192.0.2.10
www IN A 192.0.2.20
`}
	status1, body1, _ := do(t, "POST", srv.URL+"/api/zones", "fixed-req-id", zoneBody)
	if status1 != http.StatusCreated {
		t.Fatalf("first = %d %v", status1, body1)
	}
	status2, body2, _ := do(t, "POST", srv.URL+"/api/zones", "fixed-req-id", zoneBody)
	if status2 != http.StatusOK {
		t.Fatalf("replay status = %d", status2)
	}
	if body2["replayed"] != true {
		t.Fatalf("replay flag missing: %v", body2)
	}
}

func TestFullWorkflowOverHTTP(t *testing.T) {
	srv, _ := newServer(t)
	defer srv.Close()

	mkZone := func(serial, www string) string {
		text := `$ORIGIN example.
$TTL 300
@ IN SOA ns1.example. admin.example. ` + serial + ` 7200 3600 1209600 300
@ IN NS ns1.example.
ns1 IN A 192.0.2.10
www IN A ` + www + `
`
		_, body, _ := do(t, "POST", srv.URL+"/api/zones", "", map[string]any{"origin": "example.", "text": text})
		return body["id"].(string)
	}
	cur := mkZone("2026010100", "192.0.2.20")
	cand := mkZone("2026011500", "192.0.2.21")

	_, planBody, _ := do(t, "POST", srv.URL+"/api/plans", "", map[string]any{
		"current_zone_id": cur, "candidate_zone_id": cand,
		"phases": []map[string]any{{"name": "p", "min_hold_seconds": 0,
			"changed_keys": []string{"www.example. A", "example. SOA"}}},
	})
	planID := planBody["id"].(string)

	if _, body, _ := do(t, "POST", srv.URL+"/api/plans/"+planID+"/commit", "", nil); body["error"] != nil {
		t.Fatalf("commit failed: %v", body)
	}

	status, simBody, hdr := do(t, "POST", srv.URL+"/api/simulations", "sim-1", map[string]any{
		"plan_id": planID, "seed": 11,
		"probes":            []map[string]any{{"qname": "www.example.", "qtype": "A"}},
		"max_delay_seconds": 10, "query_every_seconds": 10, "horizon_seconds": 3600,
	})
	if status != 201 {
		t.Fatalf("sim status = %d body=%v", status, simBody)
	}
	simID := simBody["simulation"].(map[string]any)["id"].(string)

	// Repeated simulation is reused.
	_, simBody2, hdr2 := do(t, "POST", srv.URL+"/api/simulations", "sim-2", map[string]any{
		"plan_id": planID, "seed": 11,
		"probes":            []map[string]any{{"qname": "www.example.", "qtype": "A"}},
		"max_delay_seconds": 10, "query_every_seconds": 10, "horizon_seconds": 3600,
	})
	if simBody2["reused"] != true || hdr2.Get("X-Simulation-Reused") != "true" {
		t.Fatalf("expected reuse: %v headers=%v", simBody2, hdr)
	}
	_ = hdr

	status, viewBody, _ := do(t, "POST", srv.URL+"/api/simulations/"+simID+"/view", "", map[string]any{
		"at_seconds": 100, "query": map[string]any{"qname": "www.example.", "qtype": "A"},
	})
	if status != 200 || viewBody["samples"] == nil {
		t.Fatalf("view failed: %d %v", status, viewBody)
	}

	status, exportBody, _ := do(t, "GET", srv.URL+"/api/simulations/"+simID+"/export", "", nil)
	if status != 200 || !strings.HasPrefix(exportBody["simulation"].(map[string]any)["id"].(string), "sim_") {
		t.Fatalf("export failed %d", status)
	}

	// Ad-hoc query with the same request id must not create a second side
	// record; both responses should carry identical content.
	adhocBody := map[string]any{"at_seconds": 50, "qname": "www.example.", "qtype": "A"}
	_, a1, _ := do(t, "POST", srv.URL+"/api/simulations/"+simID+"/adhoc", "adhoc-x", adhocBody)
	_, a2, _ := do(t, "POST", srv.URL+"/api/simulations/"+simID+"/adhoc", "adhoc-x", adhocBody)
	if a2["replayed"] != true || a2["id"] != "adhoc-adhoc-x" {
		t.Fatalf("ad-hoc replay must return idempotent replay marker: %v", a2)
	}
	// Only one side-log entry must exist.
	_, export2, _ := do(t, "GET", srv.URL+"/api/simulations/"+simID+"/export", "", nil)
	ah := export2["ad_hoc_queries"].([]any)
	if len(ah) != 1 {
		t.Fatalf("expected exactly 1 ad-hoc record, got %d", len(ah))
	}
	_ = a1
}
