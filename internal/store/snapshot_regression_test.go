package store_test

// Deterministic snapshot regressions for the public GET /v1/net-policies
// surface. Unlike the concurrent tests, which fire reads and writes together
// and only ever treat a sampled state as incidental, these tests create a
// registration whose candidate row is fully written inside an open (uncommitted)
// transaction — via the test-only store.HoldUncommittedRegistration seam — and
// drive the published HTTP entry points while that transaction is held open.
// Every pre-commit query therefore provably happens in the window "candidate
// written, transaction not committed": CountInTransaction proves the row exists
// inside the transaction, while GET over real HTTP proves other connections
// read only committed rows. The tests then fix the results after commit and
// after rollback, and re-exercise POST to show later registration still works.
//
// No production code or route is involved beyond the published GET/POST entries;
// the seam itself lives in export_test.go and is absent from release builds.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Bob-xisuke/orb-netpolicy-guard/internal/api"
	"github.com/Bob-xisuke/orb-netpolicy-guard/internal/store"
)

var snapHTTPClient = &http.Client{Timeout: 10 * time.Second}

// Independent data for the two scenarios: each test also gets its own database
// file, so nothing here relies on rows left by other tests or vice versa.
const (
	snapNamespace = "payments"
	snapLabel     = "tier=backend"

	snapDenyBody = `{
		"namespace": "payments",
		"name": "ledger-deny",
		"label": "tier=backend",
		"rules": [{"direction": "ingress", "action": "deny", "ports": [80, 100]}],
		"pluginParams": {"mode": "enforce", "zone": "east"}
	}`

	snapAllowBody = `{
		"namespace": "payments",
		"name": "ledger-allow",
		"label": "tier=backend",
		"rules": [{"direction": "ingress", "action": "allow", "ports": [100, 200]}],
		"pluginParams": {"mode": "enforce", "zone": "west"}
	}`

	// A brand-new identity registered through POST after the pending
	// transaction commits: egress, so its rule cannot clash.
	snapNextBody = `{
		"namespace": "payments",
		"name": "ledger-egress",
		"label": "tier=backend",
		"rules": [{"direction": "egress", "action": "allow", "ports": [53, 53]}],
		"pluginParams": {}
	}`

	// Rollback scenario data (empty store at the start).
	rollbackBody = `{
		"namespace": "payments",
		"name": "settle-allow",
		"label": "tier=backend",
		"rules": [{"direction": "ingress", "action": "allow", "ports": [100, 200]}],
		"pluginParams": {"mode": "enforce"}
	}`
	rollbackChangedBody = `{
		"namespace": "payments",
		"name": "settle-allow",
		"label": "tier=backend",
		"rules": [{"direction": "ingress", "action": "allow", "ports": [100, 200]}],
		"pluginParams": {"mode": "audit"}
	}`
)

func snapQueryTargets(base string) []string {
	return []string{
		base + "/v1/net-policies?namespace=payments",
		base + "/v1/net-policies?label=tier%3Dbackend",
		base + "/v1/net-policies?namespace=payments&label=tier%3Dbackend",
	}
}

func newSnapServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	server := httptest.NewServer(api.NewRouter(st))
	t.Cleanup(func() {
		server.Close()
		st.Close()
	})
	return server, st
}

func httpDo(t *testing.T, method, target, body string) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, target, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := snapHTTPClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp.StatusCode, raw
}

func recordFromBody(t *testing.T, body string) store.Record {
	t.Helper()
	var rec store.Record
	if err := json.Unmarshal([]byte(body), &rec); err != nil {
		t.Fatalf("decode record body: %v", err)
	}
	return rec
}

// wantRecordMap is the expected externally visible JSON object for a body:
// every submitted field verbatim plus order and conflict metadata.
func wantRecordMap(t *testing.T, body string, order int64, conflict bool) map[string]any {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal([]byte(body), &record); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	record["order"] = float64(order)
	record["conflict"] = conflict
	return record
}

func decodeItems(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	var body struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode items: %v", err)
	}
	return body.Items
}

// assertErrorResponse fixes the published error contract: exactly one top-level
// "error" object with two string members (code, message), the expected code, a
// non-empty message that leaks no SQL, stack frame or path detail.
func assertErrorResponse(t *testing.T, status int, raw []byte, wantStatus int, wantCode string) {
	t.Helper()
	if status != wantStatus {
		t.Fatalf("status = %d, want %d: %s", status, wantStatus, string(raw))
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if len(top) != 1 {
		t.Fatalf("error body has %d top-level keys, want exactly one (error): %s", len(top), string(raw))
	}
	errRaw, ok := top["error"]
	if !ok {
		t.Fatalf("error body missing top-level error object: %s", string(raw))
	}
	var errObj map[string]json.RawMessage
	if err := json.Unmarshal(errRaw, &errObj); err != nil {
		t.Fatalf("error member is not an object: %v", err)
	}
	if len(errObj) != 2 {
		t.Fatalf("error object has %d members, want exactly code and message: %s", len(errObj), string(raw))
	}
	var code, message string
	if err := json.Unmarshal(errObj["code"], &code); err != nil {
		t.Fatalf("error.code is not a string: %s", string(raw))
	}
	if err := json.Unmarshal(errObj["message"], &message); err != nil {
		t.Fatalf("error.message is not a string: %s", string(raw))
	}
	if code != wantCode {
		t.Fatalf("error.code = %q, want %q (body %s)", code, wantCode, string(raw))
	}
	if message == "" {
		t.Fatalf("error.message is empty: %s", string(raw))
	}
	for _, leak := range []string{"sql", "sqlite", "goroutine", ".go:", "panic", "/", "\\"} {
		if strings.Contains(strings.ToLower(message), leak) {
			t.Fatalf("error.message leaks %q: %s", leak, message)
		}
	}
}

// assertUniqueIdentities fails if two items share a namespace/name identity.
func assertUniqueIdentities(t *testing.T, items []map[string]any) {
	t.Helper()
	seen := map[string]bool{}
	for _, item := range items {
		ns, _ := item["namespace"].(string)
		name, _ := item["name"].(string)
		id := ns + "\x00" + name
		if seen[id] {
			t.Fatalf("duplicate identity %q in items: %v", id, items)
		}
		seen[id] = true
	}
}

func assertHealthy(t *testing.T, base string) {
	t.Helper()
	status, raw := httpDo(t, http.MethodGet, base+"/healthz", "")
	if status != http.StatusOK {
		t.Fatalf("healthz status = %d: %s", status, string(raw))
	}
	if string(raw) != `{"database":"ok","status":"ok"}` {
		t.Fatalf("healthz body = %s", string(raw))
	}
}

// holdPending performs the candidate write and leaves it uncommitted. The
// cleanup rolls back defensively if a test exits without finalizing; an
// explicit Commit/Rollback turns that into a harmless no-op.
func holdPending(t *testing.T, st *store.Store, rec store.Record) *store.PendingRegistration {
	t.Helper()
	pending, order, conflict, err := store.HoldUncommittedRegistration(st, rec)
	if err != nil {
		t.Fatalf("hold uncommitted registration: %v", err)
	}
	if pending.Order() != order {
		t.Fatalf("pending order mismatch: %d vs %d", pending.Order(), order)
	}
	t.Cleanup(func() { _ = pending.Rollback() })
	if order != 2 || !conflict {
		t.Fatalf("holdPending helper expected order 2 conflict true, got order %d conflict %v", order, conflict)
	}
	return pending
}

// TestSnapshotQueryBeforeAndAfterCommit fixes GET results at the three points
// around a commit: candidate fully written but uncommitted, after commit, and
// (via the next POST) after later registration keeps working.
func TestSnapshotQueryBeforeAndAfterCommit(t *testing.T) {
	server, st := newSnapServer(t)
	targets := snapQueryTargets(server.URL)

	// The original committed record: ingress deny [80,100], order 1, no conflict.
	status, raw := httpDo(t, http.MethodPost, server.URL+"/v1/net-policies", snapDenyBody)
	if status != http.StatusCreated {
		t.Fatalf("seed POST status = %d, want 201: %s", status, string(raw))
	}
	var seed map[string]any
	if err := json.Unmarshal(raw, &seed); err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	wantSeed := wantRecordMap(t, snapDenyBody, 1, false)
	if !reflect.DeepEqual(seed, wantSeed) {
		t.Fatalf("seed record = %v, want %v", seed, wantSeed)
	}

	// Second policy, same namespace and label, different name: ingress allow
	// [100,200]. The whole row is written; the transaction stays open.
	candidate := recordFromBody(t, snapAllowBody)
	pending := holdPending(t, st, candidate)
	if pending.Order() != 2 {
		t.Fatalf("pending order = %d, want 2", pending.Order())
	}

	// Proof that the window is real: the pending transaction itself can count
	// both rows under every filter that matches the candidate.
	for _, filter := range []struct{ namespace, label string }{
		{snapNamespace, ""},
		{"", snapLabel},
		{snapNamespace, snapLabel},
	} {
		count, err := pending.CountInTransaction(filter.namespace, filter.label)
		if err != nil {
			t.Fatalf("count in transaction: %v", err)
		}
		if count != 2 {
			t.Fatalf("inside-tx count (%q,%q) = %d, want 2 (candidate row is fully written)",
				filter.namespace, filter.label, count)
		}
	}

	// Health and query validation behave exactly as on a quiet store.
	assertHealthy(t, server.URL)

	// Pre-commit snapshot, through the public GET entry on real HTTP: every
	// matching filter returns 200 and items contains ONLY the original record.
	// The candidate cannot appear, leak a partial field mix, or duplicate the
	// original identity.
	for _, target := range targets {
		status, raw := httpDo(t, http.MethodGet, target, "")
		if status != http.StatusOK {
			t.Fatalf("pre-commit GET %s status = %d, want 200: %s", target, status, string(raw))
		}
		items := decodeItems(t, raw)
		assertUniqueIdentities(t, items)
		if len(items) != 1 {
			t.Fatalf("pre-commit GET %s returned %d items, want exactly the original row: %s",
				target, len(items), string(raw))
		}
		if !reflect.DeepEqual(items[0], wantSeed) {
			t.Fatalf("pre-commit GET %s item = %v, want unchanged original %v", target, items[0], wantSeed)
		}
	}

	// Commit: the held registration finalizes exactly like a committed Register.
	if err := pending.Commit(); err != nil {
		t.Fatalf("commit pending registration: %v", err)
	}

	// Post-commit snapshot: all three filters return two COMPLETE records,
	// ascending by order. The new record is order 2 with conflict=true (closed
	// intervals [80,100] and [100,200] touch at port 100); the original record
	// is unchanged in every field.
	wantCandidate := wantRecordMap(t, snapAllowBody, 2, true)
	wantBoth := []map[string]any{wantSeed, wantCandidate}
	for _, target := range targets {
		status, raw := httpDo(t, http.MethodGet, target, "")
		if status != http.StatusOK {
			t.Fatalf("post-commit GET %s status = %d, want 200: %s", target, status, string(raw))
		}
		items := decodeItems(t, raw)
		assertUniqueIdentities(t, items)
		if !reflect.DeepEqual(items, wantBoth) {
			t.Fatalf("post-commit GET %s items = %v, want both complete records ascending %v",
				target, items, wantBoth)
		}
		// Explicit field-level checks per record: identity, rule order, ports
		// and plugin params must match each submission with no mixing.
		if !reflect.DeepEqual(items[0], seed) {
			t.Fatalf("original record changed after commit:\n got %v\nwant %v", items[0], seed)
		}
		rules, _ := items[1]["rules"].([]any)
		if len(rules) != 1 {
			t.Fatalf("candidate rules = %v, want exactly one rule", rules)
		}
		rule, _ := rules[0].(map[string]any)
		if rule["direction"] != "ingress" || rule["action"] != "allow" {
			t.Fatalf("candidate rule = %v, want ingress allow", rule)
		}
		ports, _ := rule["ports"].([]any)
		if len(ports) != 2 || ports[0] != float64(100) || ports[1] != float64(200) {
			t.Fatalf("candidate ports = %v, want [100 200]", ports)
		}
		if !reflect.DeepEqual(items[1]["pluginParams"], map[string]any{"mode": "enforce", "zone": "west"}) {
			t.Fatalf("candidate pluginParams = %v, want mode=enforce zone=west (no field mixing)",
				items[1]["pluginParams"])
		}
		if items[1]["order"] != float64(2) || items[1]["conflict"] != true {
			t.Fatalf("candidate order/conflict = %v/%v, want 2/true",
				items[1]["order"], items[1]["conflict"])
		}
	}

	// The existing POST entry still works afterwards: a brand-new identity
	// takes order 3 (the committed candidate really persisted at order 2) and
	// is conflict-free (egress cannot clash with either ingress rule).
	status, raw = httpDo(t, http.MethodPost, server.URL+"/v1/net-policies", snapNextBody)
	if status != http.StatusCreated {
		t.Fatalf("next POST status = %d, want 201: %s", status, string(raw))
	}
	wantNext := wantRecordMap(t, snapNextBody, 3, false)
	var next map[string]any
	if err := json.Unmarshal(raw, &next); err != nil {
		t.Fatalf("decode next: %v", err)
	}
	if !reflect.DeepEqual(next, wantNext) {
		t.Fatalf("next record = %v, want %v", next, wantNext)
	}

	// Same-content retry of the original via POST: 200 with the untouched
	// original record; queries then list all three in ascending order.
	status, raw = httpDo(t, http.MethodPost, server.URL+"/v1/net-policies", snapDenyBody)
	if status != http.StatusOK {
		t.Fatalf("retry POST status = %d, want 200: %s", status, string(raw))
	}
	var retried map[string]any
	if err := json.Unmarshal(raw, &retried); err != nil {
		t.Fatalf("decode retry: %v", err)
	}
	if !reflect.DeepEqual(retried, seed) {
		t.Fatalf("retry record = %v, want original %v", retried, seed)
	}

	status, raw = httpDo(t, http.MethodGet, server.URL+"/v1/net-policies?namespace=payments", "")
	if status != http.StatusOK {
		t.Fatalf("final GET status = %d: %s", status, string(raw))
	}
	items := decodeItems(t, raw)
	wantAll := []map[string]any{wantSeed, wantCandidate, wantNext}
	if !reflect.DeepEqual(items, wantAll) {
		t.Fatalf("final items = %v, want three records ascending by order %v", items, wantAll)
	}
	assertUniqueIdentities(t, items)
}

// TestSnapshotQueryBeforeAndAfterRollback fixes GET results around a rollback:
// while the candidate is written-but-uncommitted and after it is rolled back,
// every matching query is 404; input validation is unchanged in that window;
// and POSTing the same content afterwards yields a brand-new order-1 record
// (rollback left neither a row nor a consumed order), with retry/conflict
// semantics intact and queries still showing only that record.
func TestSnapshotQueryBeforeAndAfterRollback(t *testing.T) {
	server, st := newSnapServer(t)
	targets := snapQueryTargets(server.URL)

	candidate := recordFromBody(t, rollbackBody)
	pending, order, conflict, err := store.HoldUncommittedRegistration(st, candidate)
	if err != nil {
		t.Fatalf("hold uncommitted registration: %v", err)
	}
	t.Cleanup(func() { _ = pending.Rollback() })
	if order != 1 || conflict {
		t.Fatalf("pending order/conflict = %d/%v, want 1/false on the empty store", order, conflict)
	}

	// The window is real: inside the transaction each matching filter counts
	// the fully written candidate once.
	for _, filter := range []struct{ namespace, label string }{
		{snapNamespace, ""},
		{"", snapLabel},
		{snapNamespace, snapLabel},
	} {
		count, err := pending.CountInTransaction(filter.namespace, filter.label)
		if err != nil {
			t.Fatalf("count in transaction: %v", err)
		}
		if count != 1 {
			t.Fatalf("inside-tx count (%q,%q) = %d, want 1 (candidate row is fully written)",
				filter.namespace, filter.label, count)
		}
	}

	// Uncommitted: every filter that WOULD match the candidate returns 404
	// through the public GET entry.
	for _, target := range targets {
		status, raw := httpDo(t, http.MethodGet, target, "")
		assertErrorResponse(t, status, raw, http.StatusNotFound, "NetPolicyNotFoundError")
	}

	// Missing filter during the same window: validation is independent of
	// transaction state — 400 InvalidNetPolicyInputError before any storage
	// read, with the same safe error envelope.
	status, raw := httpDo(t, http.MethodGet, server.URL+"/v1/net-policies", "")
	assertErrorResponse(t, status, raw, http.StatusBadRequest, "InvalidNetPolicyInputError")

	// Health stays green while the transaction is open.
	assertHealthy(t, server.URL)

	// Rollback: the candidate row and its seq=1 assignment disappear.
	if err := pending.Rollback(); err != nil {
		t.Fatalf("rollback pending registration: %v", err)
	}
	for _, target := range targets {
		status, raw := httpDo(t, http.MethodGet, target, "")
		assertErrorResponse(t, status, raw, http.StatusNotFound, "NetPolicyNotFoundError")
	}

	// The same legal content now goes through the existing POST entry: 201 and
	// order 1 prove the rollback left neither a record nor a consumed order.
	status, raw = httpDo(t, http.MethodPost, server.URL+"/v1/net-policies", rollbackBody)
	if status != http.StatusCreated {
		t.Fatalf("POST after rollback status = %d, want 201: %s", status, string(raw))
	}
	wantFirst := wantRecordMap(t, rollbackBody, 1, false)
	var first map[string]any
	if err := json.Unmarshal(raw, &first); err != nil {
		t.Fatalf("decode first: %v", err)
	}
	if !reflect.DeepEqual(first, wantFirst) {
		t.Fatalf("first record after rollback = %v, want %v", first, wantFirst)
	}

	// Every matching filter now returns exactly that one complete record.
	for _, target := range targets {
		status, raw := httpDo(t, http.MethodGet, target, "")
		if status != http.StatusOK {
			t.Fatalf("GET %s after POST status = %d, want 200: %s", target, status, string(raw))
		}
		items := decodeItems(t, raw)
		assertUniqueIdentities(t, items)
		if !reflect.DeepEqual(items, []map[string]any{wantFirst}) {
			t.Fatalf("GET %s items = %v, want only the registered record %v", target, items, wantFirst)
		}
	}

	// Identical retry: 200 with the original record, no order consumed.
	status, raw = httpDo(t, http.MethodPost, server.URL+"/v1/net-policies", rollbackBody)
	if status != http.StatusOK {
		t.Fatalf("retry POST status = %d, want 200: %s", status, string(raw))
	}
	var retried map[string]any
	if err := json.Unmarshal(raw, &retried); err != nil {
		t.Fatalf("decode retry: %v", err)
	}
	if !reflect.DeepEqual(retried, wantFirst) {
		t.Fatalf("retry record = %v, want original %v", retried, wantFirst)
	}

	// Changed plugin params on the same identity: 409, not an overwrite.
	status, raw = httpDo(t, http.MethodPost, server.URL+"/v1/net-policies", rollbackChangedBody)
	assertErrorResponse(t, status, raw, http.StatusConflict, "NetPolicyConflictError")

	// Queries still return just the original record, untouched.
	for _, target := range targets {
		status, raw := httpDo(t, http.MethodGet, target, "")
		if status != http.StatusOK {
			t.Fatalf("GET %s after conflict status = %d, want 200: %s", target, status, string(raw))
		}
		items := decodeItems(t, raw)
		assertUniqueIdentities(t, items)
		if !reflect.DeepEqual(items, []map[string]any{wantFirst}) {
			t.Fatalf("GET %s items = %v after 409, want only unchanged original %v",
				target, items, wantFirst)
		}
	}
}
