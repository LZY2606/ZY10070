package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"zonesim/internal/service"
	"zonesim/internal/store"
)

func newSrv(t *testing.T) (http.Handler, *service.Service) {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := service.New(st)
	return New(svc, nil), svc
}

func do(t *testing.T, h http.Handler, method, path string, body map[string]any, reqID string) (int, map[string]any) {
	t.Helper()
	if body == nil {
		body = map[string]any{}
	}
	if reqID != "" {
		body["request_id"] = reqID
	}
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

const curZone = "$TTL 60\n@ SOA ns1 hostmaster 1 7200 3600 1209600 30\n@ NS ns1\nns1 A 10.0.0.1\nwww A 192.0.2.10\n"
const candZone = "$TTL 60\n@ SOA ns1 hostmaster 2 7200 3600 1209600 30\n@ NS ns1\nns1 A 10.0.0.1\nwww A 198.51.100.20\n"

func importZone(t *testing.T, h http.Handler, kind, text, id string) {
	t.Helper()
	code, out := do(t, h, "POST", "/api/zones", map[string]any{"kind": kind, "name": "example.test", "text": text}, id)
	if code != 200 {
		t.Fatalf("import %s: %d %v", kind, code, out)
	}
}

func listFirst(t *testing.T, h http.Handler, path string) map[string]any {
	r := httptest.NewRequest("GET", path, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	arr := out["zones"].([]any)
	if len(arr) == 0 {
		arr = out["plans"].([]any)
	}
	return arr[len(arr)-1].(map[string]any)
}

func TestImportInvalidJSONClass(t *testing.T) {
	h, _ := newSrv(t)
	r := httptest.NewRequest("POST", "/api/zones", strings.NewReader("{not json"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	var e map[string]any
	json.Unmarshal(w.Body.Bytes(), &e)
	if e["error"].(map[string]any)["code"] != "invalid_input" {
		t.Fatalf("expected invalid_input, got %v", e)
	}
}

func TestNotFoundAndReplayConflict(t *testing.T) {
	h, _ := newSrv(t)
	if code, _ := do(t, h, "GET", "/api/simulations/nope", nil, ""); code != 404 {
		t.Fatalf("expected 404, got %d", code)
	}
	importZone(t, h, "current", curZone, "req-z1")
	// Same request_id, different payload => 409 state conflict.
	code, out := do(t, h, "POST", "/api/zones", map[string]any{"kind": "candidate", "name": "example.test", "text": candZone}, "req-z1")
	if code != 409 || out["error"].(map[string]any)["code"] != "state_conflict" {
		t.Fatalf("expected 409 state_conflict, got %d %v", code, out)
	}
	// Identical replay returns the same response and no second result.
	code, out = do(t, h, "POST", "/api/zones", map[string]any{"kind": "current", "name": "example.test", "text": curZone}, "req-z1")
	if code != 200 || out["zone_id"] == "" {
		t.Fatalf("idempotent replay failed: %d %v", code, out)
	}
}

func TestBlockedPlanAndSafeCutover(t *testing.T) {
	h, _ := newSrv(t)
	importZone(t, h, "current", curZone, "rz")
	// Direct plan with serial regression must be blocked (400 publish_blocked).
	op := map[string]any{
		"action": "upsert", "name": "example.test", "type": "SOA", "ttl": 60,
		"data": []any{"ns1", "hostmaster", "0", "7200", "3600", "1209600", "30"},
		"raw":  "ns1 hostmaster 0 7200 3600 1209600 30",
	}
	phase := map[string]any{"name": "bad", "min_observe_sec": 10, "operations": []any{op}}
	plan := map[string]any{"zone_name": "example.test", "phases": []any{phase}}
	body := map[string]any{"current_zone_id": listFirst(t, h, "/api/zones")["id"], "plan": plan}
	code, out := do(t, h, "POST", "/api/plans", body, "rp-bad")
	if code != 400 || out["error"].(map[string]any)["code"] != "publish_blocked" {
		t.Fatalf("expected publish_blocked, got %d %v", code, out)
	}

	// Safe diff-based plan from current -> candidate must be accepted.
	importZone(t, h, "candidate", candZone, "rzc")
	r := httptest.NewRequest("GET", "/api/zones", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var zd map[string]any
	json.Unmarshal(w.Body.Bytes(), &zd)
	var curID, candID string
	for _, zi := range zd["zones"].([]any) {
		z := zi.(map[string]any)
		if z["kind"] == "current" {
			curID = z["id"].(string)
		}
		if z["kind"] == "candidate" {
			candID = z["id"].(string)
		}
	}
	code, out = do(t, h, "POST", "/api/plans",
		map[string]any{"current_zone_id": curID, "candidate_zone_id": candID}, "rp-ok")
	if code != 200 || out["status"] != "ready" {
		t.Fatalf("expected ready plan, got %d %v", code, out)
	}
}

func setupCutover(t *testing.T, h http.Handler) string {
	t.Helper()
	importZone(t, h, "current", curZone, "zc")
	importZone(t, h, "candidate", candZone, "zk")
	r := httptest.NewRequest("GET", "/api/zones", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var zd map[string]any
	json.Unmarshal(w.Body.Bytes(), &zd)
	var curID, candID string
	for _, zi := range zd["zones"].([]any) {
		z := zi.(map[string]any)
		switch z["kind"] {
		case "current":
			curID = z["id"].(string)
		case "candidate":
			candID = z["id"].(string)
		}
	}
	_, out := do(t, h, "POST", "/api/plans",
		map[string]any{"current_zone_id": curID, "candidate_zone_id": candID}, "rplan")
	return out["plan_id"].(string)
}

func TestSimulationReuseDeterministic(t *testing.T) {
	h, _ := newSrv(t)
	planID := setupCutover(t, h)
	params := map[string]any{"authoritative_nodes": 2, "recursive_nodes": 2,
		"max_auth_delay_sec": 30, "probe_interval_sec": 10, "seed": 99}
	code, out := do(t, h, "POST", "/api/plans/"+planID+"/simulations",
		map[string]any{"parameters": params}, "rsim1")
	if code != 200 {
		t.Fatalf("sim1: %d %v", code, out)
	}
	if out["reused"] == true {
		t.Fatal("first simulation must compute")
	}
	simID := out["simulation_id"].(string)
	_, out2 := do(t, h, "POST", "/api/plans/"+planID+"/simulations",
		map[string]any{"parameters": params}, "rsim2")
	if out2["reused"] != true || out2["simulation_id"] != simID {
		t.Fatalf("identical candidate must reuse deterministic result: %v", out2)
	}
}

func TestDecisionConflictAndRollback(t *testing.T) {
	h, _ := newSrv(t)
	planID := setupCutover(t, h)
	// Too-early decision conflicts with minimum observation time (candidate plan uses 300s).
	code, out := do(t, h, "POST", "/api/plans/"+planID+"/phases/0/decision",
		map[string]any{"action": "proceed", "at_sec": 5}, "rdec-early")
	if code != 409 || out["error"].(map[string]any)["code"] != "state_conflict" {
		t.Fatalf("expected 409 state_conflict, got %d %v", code, out)
	}
	code, out = do(t, h, "POST", "/api/plans/"+planID+"/phases/0/decision",
		map[string]any{"action": "proceed", "at_sec": 300}, "rdec-ok")
	if code != 200 || out["status"] != "completed" {
		t.Fatalf("proceed failed: %d %v", code, out)
	}
	// Second proceed on completed plan is a conflict.
	code, _ = do(t, h, "POST", "/api/plans/"+planID+"/phases/0/decision",
		map[string]any{"action": "proceed", "at_sec": 400}, "rdec-twice")
	if code != 409 {
		t.Fatalf("expected 409 on double proceed, got %d", code)
	}
	// Rollback must be allowed and produce an exported timeline honoring TTL.
	code, out = do(t, h, "POST", "/api/plans/"+planID+"/phases/0/decision",
		map[string]any{"action": "rollback", "at_sec": 400}, "rrb")
	if code != 200 || out["status"] != "rolled_back" {
		t.Fatalf("rollback failed: %d %v", code, out)
	}
	params := map[string]any{"authoritative_nodes": 1, "recursive_nodes": 1,
		"max_auth_delay_sec": 0, "probe_interval_sec": 10, "seed": 3}
	code, sim := do(t, h, "POST", "/api/plans/"+planID+"/simulations",
		map[string]any{"parameters": params}, "rsimrb")
	if code != 200 {
		t.Fatalf("rollback sim: %d %v", code, sim)
	}
	if conv, _ := sim["earliest_all_converged_sec"].(float64); conv < 400 {
		t.Fatalf("rollback convergence must honor emitted TTLs, got %v", conv)
	}
}

func TestCopyPlanBindsOldSimulationToOldFingerprint(t *testing.T) {
	h, _ := newSrv(t)
	planID := setupCutover(t, h)
	params := map[string]any{"seed": 5, "probe_interval_sec": 10, "authoritative_nodes": 1,
		"recursive_nodes": 1, "max_auth_delay_sec": 0}
	_, sim := do(t, h, "POST", "/api/plans/"+planID+"/simulations",
		map[string]any{"parameters": params}, "rc-sim")
	_ = sim
	// Unmodified copy echoes the source plan fingerprint while becoming a new document.
	code, cp := do(t, h, "POST", "/api/plans/"+planID+"/copy", map[string]any{}, "rc-copy")
	if code != 200 || cp["source_plan_id"] != planID || cp["source_plan_fingerprint"] == nil {
		t.Fatalf("copy must echo source fingerprint: %d %v", code, cp)
	}
	// A modified copy gets a distinct fingerprint, proving old simulations stay
	// bound to the old plan and are never reused against the new document.
	modified := map[string]any{"plan": map[string]any{"zone_name": "example.test", "phases": []any{
		map[string]any{"name": "only-phase", "min_observe_sec": 45, "operations": []any{
			map[string]any{"action": "upsert", "name": "x.example.test", "type": "A", "ttl": 60,
				"data": []any{"203.0.113.9"}, "raw": "203.0.113.9"},
			map[string]any{"action": "upsert", "name": "example.test", "type": "SOA", "ttl": 60,
				"data": []any{"ns1", "hostmaster", "2", "7200", "3600", "1209600", "30"},
				"raw":  "ns1 hostmaster 2 7200 3600 1209600 30"}}}}}}
	code, cp2 := do(t, h, "POST", "/api/plans/"+planID+"/copy", modified, "rc-copy2")
	if code != 200 || cp2["fingerprint"] == cp["source_plan_fingerprint"] {
		t.Fatalf("modified copy must have a new fingerprint: %d %v", code, cp2)
	}
}
