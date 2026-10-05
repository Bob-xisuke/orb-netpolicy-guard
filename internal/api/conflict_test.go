package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/Bob-xisuke/orb-netpolicy-guard/internal/store"
)

// policyWithRules builds a registration body with explicit rules and
// pluginParams JSON fragments.
func policyWithRules(ns, name, label, rulesJSON, paramsJSON string) string {
	return fmt.Sprintf(`{
		"namespace": %q,
		"name": %q,
		"label": %q,
		"rules": %s,
		"pluginParams": %s
	}`, ns, name, label, rulesJSON, paramsJSON)
}

// singleRuleBody builds a registration body holding exactly one rule.
func singleRuleBody(ns, name, label, direction, action string, lo, hi int, paramsJSON string) string {
	return policyWithRules(ns, name, label,
		fmt.Sprintf(`[{"direction": %q, "action": %q, "ports": [%d, %d]}]`, direction, action, lo, hi),
		paramsJSON)
}

// wantRecord derives the expected response object from the request body: every
// submitted field verbatim plus the registry metadata.
func wantRecord(t *testing.T, requestBody string, order int64, conflict bool) map[string]any {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal([]byte(requestBody), &record); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	record["order"] = float64(order)
	record["conflict"] = conflict
	return record
}

// registerCreated posts the body, demands 201, and verifies the response
// carries every submitted field plus the expected order and conflict flag.
// It returns the decoded record for later comparisons.
func registerCreated(t *testing.T, router *gin.Engine, body string, wantOrder int64, wantConflict bool) map[string]any {
	t.Helper()
	recorder := doRequest(router, http.MethodPost, "/v1/net-policies", body)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := wantRecord(t, body, wantOrder, wantConflict)
	if !reflect.DeepEqual(resp, want) {
		t.Fatalf("record = %v, want %v", resp, want)
	}
	return resp
}

// assertExactErrorShape verifies the body is exactly {"error":{"code","message"}}
// with both members being strings, and the code matching the contract.
func assertExactErrorShape(t *testing.T, recorder *httptest.ResponseRecorder, wantCode string) {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &top); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if len(top) != 1 {
		t.Fatalf("error body has %d top-level keys, want exactly one (error): %s", len(top), recorder.Body.String())
	}
	raw, ok := top["error"]
	if !ok {
		t.Fatalf("error body missing top-level error object: %s", recorder.Body.String())
	}
	var errObj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &errObj); err != nil {
		t.Fatalf("error member is not an object: %v", err)
	}
	if len(errObj) != 2 {
		t.Fatalf("error object has %d members, want exactly code and message: %s", len(errObj), recorder.Body.String())
	}
	var code, message string
	if err := json.Unmarshal(errObj["code"], &code); err != nil {
		t.Fatalf("error.code is not a string: %s", recorder.Body.String())
	}
	if err := json.Unmarshal(errObj["message"], &message); err != nil {
		t.Fatalf("error.message is not a string: %s", recorder.Body.String())
	}
	if code != wantCode {
		t.Fatalf("error.code = %q, want %q", code, wantCode)
	}
	if message == "" {
		t.Fatalf("error.message is empty: %s", recorder.Body.String())
	}
}

// The core lifecycle: a first policy in an empty history is conflict-free, a
// later opposite-action policy whose port interval touches the first at the
// endpoint is flagged, and the flag of the older record is not rewritten.
// Every query filter then returns the same records the registrations returned.
func TestConflictLifecycleAcrossRegisterAndQuery(t *testing.T) {
	router, _ := newTestRouter(t)

	seedBody := singleRuleBody("payments", "deny-web", "tier=backend", "ingress", "deny", 80, 100, `{"mode": "enforce"}`)
	seed := registerCreated(t, router, seedBody, 1, false)

	// Intervals [80,100] and [100,200] touch at endpoint 100: that counts as
	// overlapping, so the opposite-action record is flagged.
	clashBody := singleRuleBody("payments", "allow-web", "tier=backend", "ingress", "allow", 100, 200, `{"mode": "enforce"}`)
	clash := registerCreated(t, router, clashBody, 2, true)

	want := []map[string]any{seed, clash}
	for _, target := range []string{
		"/v1/net-policies?namespace=payments",
		"/v1/net-policies?label=tier%3Dbackend",
		"/v1/net-policies?namespace=payments&label=tier%3Dbackend",
	} {
		items := listItems(t, router, target)
		if !reflect.DeepEqual(items, want) {
			t.Fatalf("GET %s items = %v, want %v (older record keeps conflict=false, order ascending)", target, items, want)
		}
	}
}

// Port overlap is decided on closed intervals: a single shared port, the
// boundary ports 1 and 65535, and intervals merely touching at an endpoint all
// count as overlapping; fully separated intervals do not.
func TestConflictPortBoundaries(t *testing.T) {
	cases := []struct {
		name                           string
		seedLo, seedHi, candLo, candHi int
		conflict                       bool
	}{
		{"single shared port", 53, 53, 53, 53, true},
		{"touching at lower bound 1", 1, 1, 1, 65535, true},
		{"touching at upper bound 65535", 65535, 65535, 1, 65535, true},
		{"intervals touching at endpoint", 1, 100, 100, 65535, true},
		{"fully separated ports", 1, 99, 100, 200, false},
	}
	router, _ := newTestRouter(t)
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ns := fmt.Sprintf("ns-%d", i)
			seedBody := singleRuleBody(ns, "seed", "tier=backend", "ingress", "deny", tc.seedLo, tc.seedHi, `{}`)
			registerCreated(t, router, seedBody, int64(2*i+1), false)
			candBody := singleRuleBody(ns, "candidate", "tier=backend", "ingress", "allow", tc.candLo, tc.candHi, `{}`)
			registerCreated(t, router, candBody, int64(2*i+2), tc.conflict)
		})
	}
}

// A clashing rule is found even when it sits behind other rules: the seed
// carries three rules and only the last one clashes with the candidate's last
// rule.
func TestConflictFoundInLaterRulePositions(t *testing.T) {
	router, _ := newTestRouter(t)

	seedBody := policyWithRules("payments", "multi-rule", "tier=backend", `[
		{"direction": "egress", "action": "allow", "ports": [53, 53]},
		{"direction": "egress", "action": "deny", "ports": [8000, 9000]},
		{"direction": "ingress", "action": "deny", "ports": [80, 100]}
	]`, `{}`)
	seed := registerCreated(t, router, seedBody, 1, false)

	candBody := policyWithRules("payments", "late-clash", "tier=backend", `[
		{"direction": "egress", "action": "allow", "ports": [53, 53]},
		{"direction": "ingress", "action": "allow", "ports": [90, 90]}
	]`, `{}`)
	registerCreated(t, router, candBody, 2, true)

	items := listItems(t, router, "/v1/net-policies?namespace=payments")
	if !reflect.DeepEqual(items[0], seed) {
		t.Fatalf("seed record changed after clashing registration: %v, want %v", items[0], seed)
	}
}

// None of these dimensions alone produce a conflict: separated ports, a
// different direction, the same action, a different namespace or a different
// label all leave the new record's conflict flag false.
func TestConflictNegativeCases(t *testing.T) {
	router, _ := newTestRouter(t)

	seedBody := singleRuleBody("payments", "seed", "tier=backend", "ingress", "deny", 100, 200, `{}`)
	registerCreated(t, router, seedBody, 1, false)

	cases := []struct {
		name string
		body string
	}{
		{"disjoint ports", singleRuleBody("payments", "disjoint", "tier=backend", "ingress", "allow", 300, 400, `{}`)},
		{"different direction", singleRuleBody("payments", "other-dir", "tier=backend", "egress", "allow", 150, 150, `{}`)},
		{"same action", singleRuleBody("payments", "same-action", "tier=backend", "ingress", "deny", 150, 150, `{}`)},
		{"different namespace", singleRuleBody("staging", "other-ns", "tier=backend", "ingress", "allow", 150, 150, `{}`)},
		{"different label", singleRuleBody("payments", "other-label", "tier=frontend", "ingress", "allow", 150, 150, `{}`)},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			registerCreated(t, router, tc.body, int64(i+2), false)
		})
	}
}

// Records flagged true and false survive a close/reopen of the same database
// file with every field and the global order intact. Re-posting the original
// policy afterwards returns 200 with the stored record — the old conflict flag
// is not recomputed even though an opposite-action policy now exists — and a
// pluginParams object with reordered members still counts as the same content.
func TestConflictFlagsSurviveStoreReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "service.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	router := NewRouter(st)

	seedBody := singleRuleBody("payments", "deny-web", "tier=backend", "ingress", "deny", 80, 100,
		`{"mode": "enforce", "zone": "east"}`)
	seed := registerCreated(t, router, seedBody, 1, false)
	clashBody := singleRuleBody("payments", "allow-web", "tier=backend", "ingress", "allow", 100, 200,
		`{"mode": "enforce"}`)
	clash := registerCreated(t, router, clashBody, 2, true)

	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	reopened, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { reopened.Close() })
	router = NewRouter(reopened)

	items := listItems(t, router, "/v1/net-policies?namespace=payments")
	if want := []map[string]any{seed, clash}; !reflect.DeepEqual(items, want) {
		t.Fatalf("items after reopen = %v, want %v", items, want)
	}

	// Same content, pluginParams members in a different order: still a retry.
	retryBody := singleRuleBody("payments", "deny-web", "tier=backend", "ingress", "deny", 80, 100,
		`{"zone": "east", "mode": "enforce"}`)
	recorder := doRequest(router, http.MethodPost, "/v1/net-policies", retryBody)
	if recorder.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode retry: %v", err)
	}
	if !reflect.DeepEqual(resp, seed) {
		t.Fatalf("retry record = %v, want the original %v (conflict flag must not be recomputed)", resp, seed)
	}

	// The retry consumed no order: the next brand-new policy takes max+1.
	nextBody := singleRuleBody("payments", "after-reopen", "tier=frontend", "egress", "allow", 53, 53, `{}`)
	registerCreated(t, router, nextBody, 3, false)
}

// Rejected requests (409 content conflict, 400 invalid input) and same-content
// retries neither add records nor change any committed field — including the
// conflict flags — and the next legal policy continues at max order + 1.
func TestRejectedAndRetriedRequestsLeaveRegistryUntouched(t *testing.T) {
	router, _ := newTestRouter(t)

	seedBody := singleRuleBody("payments", "deny-web", "tier=backend", "ingress", "deny", 80, 100, `{"mode": "enforce"}`)
	seed := registerCreated(t, router, seedBody, 1, false)
	clashBody := singleRuleBody("payments", "allow-web", "tier=backend", "ingress", "allow", 100, 200,
		`{"mode": "enforce", "zone": "east"}`)
	clash := registerCreated(t, router, clashBody, 2, true)

	// Legal change of a plugin string value on an existing identity: 409.
	changed := singleRuleBody("payments", "deny-web", "tier=backend", "ingress", "deny", 80, 100, `{"mode": "audit"}`)
	recorder := doRequest(router, http.MethodPost, "/v1/net-policies", changed)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("changed status = %d, want %d: %s", recorder.Code, http.StatusConflict, recorder.Body.String())
	}
	assertExactErrorShape(t, recorder, "NetPolicyConflictError")
	assertSafeErrorMessage(t, recorder)

	// Invalid direction and out-of-range port on fresh identities: 400.
	for name, body := range map[string]string{
		"bad direction":    singleRuleBody("payments", "bad-dir", "tier=backend", "sideways", "allow", 80, 80, `{}`),
		"port below range": singleRuleBody("payments", "bad-port", "tier=backend", "ingress", "allow", 0, 80, `{}`),
		"port above range": singleRuleBody("payments", "bad-port2", "tier=backend", "ingress", "allow", 1, 65536, `{}`),
	} {
		recorder := doRequest(router, http.MethodPost, "/v1/net-policies", body)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want %d: %s", name, recorder.Code, http.StatusBadRequest, recorder.Body.String())
		}
		assertExactErrorShape(t, recorder, "InvalidNetPolicyInputError")
		assertSafeErrorMessage(t, recorder)
	}

	// Same-content retry with reordered pluginParams members: 200, original record.
	retryBody := singleRuleBody("payments", "allow-web", "tier=backend", "ingress", "allow", 100, 200,
		`{"zone": "east", "mode": "enforce"}`)
	recorder = doRequest(router, http.MethodPost, "/v1/net-policies", retryBody)
	if recorder.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode retry: %v", err)
	}
	if !reflect.DeepEqual(resp, clash) {
		t.Fatalf("retry record = %v, want the original %v", resp, clash)
	}

	// A filter matching nothing still reports 404 with the published shape.
	miss := doRequest(router, http.MethodGet, "/v1/net-policies?label=tier%3Dmissing", "")
	if miss.Code != http.StatusNotFound {
		t.Fatalf("miss status = %d, want %d", miss.Code, http.StatusNotFound)
	}
	assertExactErrorShape(t, miss, "NetPolicyNotFoundError")
	assertSafeErrorMessage(t, miss)

	// Nothing was added and nothing committed changed.
	items := listItems(t, router, "/v1/net-policies?namespace=payments")
	if want := []map[string]any{seed, clash}; !reflect.DeepEqual(items, want) {
		t.Fatalf("items after rejections/retries = %v, want unchanged %v", items, want)
	}

	// The next legal new policy takes the current maximum order plus one.
	nextBody := singleRuleBody("payments", "next", "tier=backend", "egress", "allow", 53, 53, `{}`)
	registerCreated(t, router, nextBody, 3, false)
}
