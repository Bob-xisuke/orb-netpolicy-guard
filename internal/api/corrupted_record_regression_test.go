package api

// Regression tests for committed records whose stored rules or pluginParams
// can no longer be decoded: one row's JSON column is truncated mid-syntax
// through a second connection to the same database file, while every other
// stored field keeps its original bytes and the connection stays readable and
// writable. No production code or public behaviour is stubbed; restoring the
// original column value models the storage recovering.

import (
	"database/sql"
	"net/http"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
)

// corruptStoredField rewrites one JSON column of a committed record to
// syntactically incomplete JSON and returns the original value so the test
// can restore it later. The column name is a fixed identifier from the test,
// never request input.
func corruptStoredField(t *testing.T, admin *sql.DB, column, namespace, name, broken string) string {
	t.Helper()
	var original string
	if err := admin.QueryRow(
		`SELECT `+column+` FROM net_policies WHERE namespace = ? AND name = ?`,
		namespace, name).Scan(&original); err != nil {
		t.Fatalf("read original %s: %v", column, err)
	}
	if _, err := admin.Exec(
		`UPDATE net_policies SET `+column+` = ? WHERE namespace = ? AND name = ?`,
		broken, namespace, name); err != nil {
		t.Fatalf("corrupt %s: %v", column, err)
	}
	return original
}

func restoreStoredField(t *testing.T, admin *sql.DB, column, namespace, name, original string) {
	t.Helper()
	if _, err := admin.Exec(
		`UPDATE net_policies SET `+column+` = ? WHERE namespace = ? AND name = ?`,
		original, namespace, name); err != nil {
		t.Fatalf("restore %s: %v", column, err)
	}
}

// getExpectError demands a GET failing with exactly the published error shape:
// a single top-level error object holding string code and message, no items.
func getExpectError(t *testing.T, router *gin.Engine, target string, wantStatus int, wantCode string) {
	t.Helper()
	recorder := doRequest(router, http.MethodGet, target, "")
	if recorder.Code != wantStatus {
		t.Fatalf("GET %s status = %d, want %d: %s", target, recorder.Code, wantStatus, recorder.Body.String())
	}
	assertExactErrorShape(t, recorder, wantCode)
	assertSafeErrorMessage(t, recorder)
}

// seedThreePolicies commits two clashing ingress policies in
// payments/tier=backend (orders 1 and 2) and one unrelated egress policy in
// staging/tier=frontend (order 3), returning the registered records exactly
// as the service reported them.
func seedThreePolicies(t *testing.T, router *gin.Engine) (denyBody, allowBody string, deny, allow, other map[string]any) {
	t.Helper()
	denyBody = singleRuleBody("payments", "deny-web", "tier=backend",
		"ingress", "deny", 80, 100, `{"mode": "enforce"}`)
	deny = registerCreated(t, router, denyBody, 1, false)
	allowBody = singleRuleBody("payments", "allow-web", "tier=backend",
		"ingress", "allow", 100, 200, `{"mode": "enforce"}`)
	allow = registerCreated(t, router, allowBody, 2, true)
	otherBody := singleRuleBody("staging", "other-egress", "tier=frontend",
		"egress", "allow", 53, 53, `{}`)
	other = registerCreated(t, router, otherBody, 3, false)
	return denyBody, allowBody, deny, allow, other
}

// expectCorruptionBehaviour asserts every response the service must give while
// one committed record in payments/tier=backend holds an undecodable field:
// queries matching the corrupted record fail wholesale with 503 (never a
// partial list), the corrupted identity rejects same-content retries with 503
// but still answers 409 to different content, queries excluding the record
// stay accurate, invalid input is rejected before storage is read, and the
// health check keeps reporting ok on the healthy connection.
func expectCorruptionBehaviour(t *testing.T, router *gin.Engine, allowBody string, other map[string]any) {
	t.Helper()

	// Namespace, label and intersection queries all match the corrupted row:
	// each fails completely instead of returning the intact records around it.
	for _, target := range []string{
		"/v1/net-policies?namespace=payments",
		"/v1/net-policies?label=tier%3Dbackend",
		"/v1/net-policies?namespace=payments&label=tier%3Dbackend",
	} {
		getExpectError(t, router, target, http.StatusServiceUnavailable, "storage_unavailable")
	}

	// Same identity, original legal content: the idempotent retry must decode
	// the stored record and fails the same way.
	postExpect(t, router, allowBody, http.StatusServiceUnavailable, "storage_unavailable")

	// Same identity, different legal content: the content fingerprint mismatches
	// before any stored JSON is decoded, so this stays a plain 409.
	changedBody := singleRuleBody("payments", "allow-web", "tier=backend",
		"ingress", "allow", 100, 200, `{"mode": "audit"}`)
	postExpect(t, router, changedBody, http.StatusConflict, "NetPolicyConflictError")

	// Queries that exclude the corrupted record keep working with complete
	// results, and a query matching nothing stays 404.
	if items := listItems(t, router, "/v1/net-policies?namespace=staging"); !reflect.DeepEqual(items, []map[string]any{other}) {
		t.Fatalf("staging items = %v, want %v", items, []map[string]any{other})
	}
	getExpectError(t, router, "/v1/net-policies?namespace=missing",
		http.StatusNotFound, "NetPolicyNotFoundError")

	// Invalid input is rejected before storage is touched, corruption or not:
	// illegal direction, out-of-range port and a broken percent escape.
	badDirection := singleRuleBody("payments", "bad-direction", "tier=backend",
		"sideways", "allow", 80, 80, `{}`)
	postExpect(t, router, badDirection, http.StatusBadRequest, "InvalidNetPolicyInputError")
	portTooHigh := singleRuleBody("payments", "port-too-high", "tier=backend",
		"ingress", "allow", 1, 65536, `{}`)
	postExpect(t, router, portTooHigh, http.StatusBadRequest, "InvalidNetPolicyInputError")
	getExpectError(t, router, "/v1/net-policies?namespace=payments%2",
		http.StatusBadRequest, "InvalidNetPolicyInputError")

	// The connection itself is healthy, so the health check stays ok.
	health := doRequest(router, http.MethodGet, "/healthz", "")
	if health.Code != http.StatusOK || health.Body.String() != `{"database":"ok","status":"ok"}` {
		t.Fatalf("healthz during corruption = %d %s, want 200 ok", health.Code, health.Body.String())
	}
}

// A committed record whose stored rules are truncated JSON breaks every query
// that would return it and every new registration in its namespace/label
// (conflict detection must decode the historical rules), while the rest of
// the service keeps its published behaviour. Restoring the original column
// value brings back the exact pre-corruption state, and the registration that
// failed during the outage commits with the next order and a conflict flag
// computed from the restored rules.
func TestCorruptedStoredRulesFailReadsAndWritesUntilRestored(t *testing.T) {
	router, _, _, admin := newFaultRouter(t)
	_, allowBody, deny, allow, other := seedThreePolicies(t, router)

	// The rules column of the second record becomes syntactically incomplete
	// JSON; every other stored byte stays as committed.
	originalRules := corruptStoredField(t, admin, "rules", "payments", "allow-web",
		`[{"direction":"ingress","action":"allow","ports":[100,200`)

	expectCorruptionBehaviour(t, router, allowBody, other)

	// A new identity in the corrupted namespace/label cannot be registered:
	// conflict detection has to decode the stored rules and fails with 503.
	// The failed attempt leaves no record and consumes no order, so repeating
	// it fails identically instead of becoming an idempotent retry.
	lateBody := singleRuleBody("payments", "late-allow", "tier=backend",
		"ingress", "allow", 90, 90, `{"mode": "audit"}`)
	postExpect(t, router, lateBody, http.StatusServiceUnavailable, "storage_unavailable")
	postExpect(t, router, lateBody, http.StatusServiceUnavailable, "storage_unavailable")

	// Restore the original rules value: the corruption is lifted.
	restoreStoredField(t, admin, "rules", "payments", "allow-web", originalRules)

	// All three filter queries return the complete pre-corruption records in
	// ascending order, identical in submitted fields, rule order, plugin
	// strings, order and conflict flags.
	wantOriginals := []map[string]any{deny, allow}
	for _, target := range []string{
		"/v1/net-policies?namespace=payments",
		"/v1/net-policies?label=tier%3Dbackend",
		"/v1/net-policies?namespace=payments&label=tier%3Dbackend",
	} {
		if items := listItems(t, router, target); !reflect.DeepEqual(items, wantOriginals) {
			t.Fatalf("GET %s after restore items = %v, want %v", target, items, wantOriginals)
		}
	}

	// The original content retried on its own identity is a read-only 200
	// returning the original record.
	retry := doRequest(router, http.MethodPost, "/v1/net-policies", allowBody)
	if retry.Code != http.StatusOK {
		t.Fatalf("retry after restore status = %d, want %d: %s",
			retry.Code, http.StatusOK, retry.Body.String())
	}
	if got := decodeRecord(t, retry.Body.Bytes()); !reflect.DeepEqual(got, allow) {
		t.Fatalf("retry record = %v, want original %v", got, allow)
	}

	// The registration that failed with 503 now commits with the next order
	// (proving the outage consumed neither a row nor a sequence value), and
	// its conflict flag is computed from the restored historical rules:
	// ingress allow [90,90] overlaps the ingress deny [80,100].
	late := registerCreated(t, router, lateBody, 4, true)

	wantRecovered := []map[string]any{deny, allow, late}
	if items := listItems(t, router, "/v1/net-policies?namespace=payments&label=tier%3Dbackend"); !reflect.DeepEqual(items, wantRecovered) {
		t.Fatalf("items after recovery = %v, want %v", items, wantRecovered)
	}
}

// A committed record whose stored pluginParams are truncated JSON breaks the
// same queries and same-identity retries, but registrations of new identities
// keep working because conflict detection never reads pluginParams. Restoring
// the column value recovers the exact pre-corruption records.
func TestCorruptedStoredPluginParamsFailReadsAndRetryUntilRestored(t *testing.T) {
	router, _, _, admin := newFaultRouter(t)
	_, allowBody, deny, allow, other := seedThreePolicies(t, router)

	// The plugin_params column of the second record becomes syntactically
	// incomplete JSON; every other stored byte stays as committed.
	originalParams := corruptStoredField(t, admin, "plugin_params", "payments", "allow-web",
		`{"mode":"enf`)

	expectCorruptionBehaviour(t, router, allowBody, other)

	// The storage stays writable for identities whose handling never decodes
	// the corrupted column: a new identity in the same namespace/label commits
	// with the next order and a conflict flag from the intact rules.
	lateBody := singleRuleBody("payments", "late-allow", "tier=backend",
		"ingress", "allow", 90, 90, `{"mode": "audit"}`)
	late := registerCreated(t, router, lateBody, 4, true)

	// Restore the original plugin_params value: the corruption is lifted.
	restoreStoredField(t, admin, "plugin_params", "payments", "allow-web", originalParams)

	// All three filter queries return every committed record in ascending
	// order, the recovered record identical to its pre-corruption state.
	wantRecovered := []map[string]any{deny, allow, late}
	for _, target := range []string{
		"/v1/net-policies?namespace=payments",
		"/v1/net-policies?label=tier%3Dbackend",
		"/v1/net-policies?namespace=payments&label=tier%3Dbackend",
	} {
		if items := listItems(t, router, target); !reflect.DeepEqual(items, wantRecovered) {
			t.Fatalf("GET %s after restore items = %v, want %v", target, items, wantRecovered)
		}
	}

	// The original content retried on its own identity is a read-only 200
	// returning the original record.
	retry := doRequest(router, http.MethodPost, "/v1/net-policies", allowBody)
	if retry.Code != http.StatusOK {
		t.Fatalf("retry after restore status = %d, want %d: %s",
			retry.Code, http.StatusOK, retry.Body.String())
	}
	if got := decodeRecord(t, retry.Body.Bytes()); !reflect.DeepEqual(got, allow) {
		t.Fatalf("retry record = %v, want original %v", got, allow)
	}
}
