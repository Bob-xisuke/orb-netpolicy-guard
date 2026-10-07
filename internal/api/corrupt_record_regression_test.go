package api

// Regression tests for committed records whose stored rules or pluginParams
// can no longer be decoded: a record committed earlier has its rules or
// plugin_params column rewritten to syntactically incomplete JSON through an
// independent connection to the same database file, while every other stored
// byte and the connection itself stay intact and readable/writable. The
// service must then fail closed: every read that would have to decode the
// broken record answers 503 storage_unavailable with only the published error
// object (never a partial item list), same-identity writes keep their
// read-only semantics (identical content cannot be decoded for the response
// either, different content still conflicts on the intact fingerprint), and
// input validation still runs before storage is touched. Restoring the column
// verbatim returns the registry to its exact pre-corruption state. No
// production code or public behaviour is stubbed.

import (
	"database/sql"
	"net/http"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
)

// corruptStoredColumn rewrites one JSON column of the named committed record
// to the given syntactically incomplete JSON through the independent admin
// connection, leaving every other stored byte untouched. It returns the
// original column value so the test can restore it later.
func corruptStoredColumn(t *testing.T, admin *sql.DB, namespace, name, column, broken string) string {
	t.Helper()
	var original string
	if err := admin.QueryRow(
		`SELECT `+column+` FROM net_policies WHERE namespace = ? AND name = ?`,
		namespace, name).Scan(&original); err != nil {
		t.Fatalf("read stored %s: %v", column, err)
	}
	restoreStoredColumn(t, admin, namespace, name, column, broken)
	return original
}

// restoreStoredColumn writes a column value back into the named record and
// demands that exactly that one row changed.
func restoreStoredColumn(t *testing.T, admin *sql.DB, namespace, name, column, value string) {
	t.Helper()
	result, err := admin.Exec(
		`UPDATE net_policies SET `+column+` = ? WHERE namespace = ? AND name = ?`,
		value, namespace, name)
	if err != nil {
		t.Fatalf("update stored %s: %v", column, err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		t.Fatalf("update stored %s affected %d rows (err %v), want exactly 1", column, affected, err)
	}
}

// getExpectError demands a GET error response carrying exactly the published
// error shape and a leak-free message.
func getExpectError(t *testing.T, router *gin.Engine, target string, wantStatus int, wantCode string) {
	t.Helper()
	recorder := doRequest(router, http.MethodGet, target, "")
	if recorder.Code != wantStatus {
		t.Fatalf("GET %s status = %d, want %d: %s", target, recorder.Code, wantStatus, recorder.Body.String())
	}
	assertExactErrorShape(t, recorder, wantCode)
	assertSafeErrorMessage(t, recorder)
}

// seedCorruptionFixture commits the three records the corruption scenarios
// share: two in payments/tier=backend (the second is the one the tests break,
// and the first stands before it so a partial query result would be visible)
// and one in staging/tier=frontend that exclusion filters can still reach.
func seedCorruptionFixture(t *testing.T, router *gin.Engine) (allowBody string, deny, allow, staging map[string]any) {
	t.Helper()
	denyBody := singleRuleBody("payments", "deny-web", "tier=backend", "ingress", "deny", 80, 100, `{"mode": "enforce"}`)
	deny = registerCreated(t, router, denyBody, 1, false)
	allowBody = singleRuleBody("payments", "allow-web", "tier=backend", "ingress", "allow", 100, 200, `{"mode": "enforce"}`)
	allow = registerCreated(t, router, allowBody, 2, true)
	stagingBody := singleRuleBody("staging", "batch", "tier=frontend", "egress", "allow", 53, 53, `{}`)
	staging = registerCreated(t, router, stagingBody, 3, false)
	return allowBody, deny, allow, staging
}

// assertCorruptionFailsClosed holds the behaviour both corruption scenarios
// share while the broken column is in place.
func assertCorruptionFailsClosed(t *testing.T, router *gin.Engine, allowBody string, staging map[string]any) {
	t.Helper()

	// Every filter that would have to decode the broken record — namespace,
	// label and their intersection — fails closed with 503 and only the
	// published error object: no items member, no policy fields, and no
	// partial result built from the intact record standing before the broken
	// one.
	for _, target := range []string{
		"/v1/net-policies?namespace=payments",
		"/v1/net-policies?label=tier%3Dbackend",
		"/v1/net-policies?namespace=payments&label=tier%3Dbackend",
	} {
		getExpectError(t, router, target, http.StatusServiceUnavailable, "storage_unavailable")
	}

	// Same identity, identical legal content: the retry is read-only, but the
	// stored record can no longer be decoded for the response -> same 503.
	postExpect(t, router, allowBody, http.StatusServiceUnavailable, "storage_unavailable")

	// Same identity, different legal content: the intact content fingerprint
	// still decides the conflict before any decode is needed -> 409.
	changedBody := singleRuleBody("payments", "allow-web", "tier=backend", "ingress", "allow", 100, 200, `{"mode": "audit"}`)
	postExpect(t, router, changedBody, http.StatusConflict, "NetPolicyConflictError")

	// Filters that exclude the broken record still return the complete,
	// untouched result set.
	for _, target := range []string{
		"/v1/net-policies?namespace=staging",
		"/v1/net-policies?label=tier%3Dfrontend",
	} {
		if items := listItems(t, router, target); !reflect.DeepEqual(items, []map[string]any{staging}) {
			t.Fatalf("GET %s items = %v, want only %v", target, items, staging)
		}
	}

	// A filter matching nothing stays 404.
	getExpectError(t, router, "/v1/net-policies?namespace=missing", http.StatusNotFound, "NetPolicyNotFoundError")

	// Input validation still runs before storage is read: an illegal
	// direction, an out-of-range port and an illegal percent escape all stay
	// 400 even though the storage layer holds an undecodable record.
	postExpect(t, router,
		singleRuleBody("payments", "bad-direction", "tier=backend", "sideways", "allow", 80, 80, `{}`),
		http.StatusBadRequest, "InvalidNetPolicyInputError")
	postExpect(t, router,
		singleRuleBody("payments", "port-too-high", "tier=backend", "ingress", "allow", 1, 65536, `{}`),
		http.StatusBadRequest, "InvalidNetPolicyInputError")
	getExpectError(t, router, "/v1/net-policies?namespace=payments&junk=%ZZ",
		http.StatusBadRequest, "InvalidNetPolicyInputError")

	// The connection itself is healthy: the health check keeps reporting ok.
	health := doRequest(router, http.MethodGet, "/healthz", "")
	if health.Code != http.StatusOK || health.Body.String() != `{"database":"ok","status":"ok"}` {
		t.Fatalf("healthz with corrupted record = %d %s, want 200 ok", health.Code, health.Body.String())
	}
}

// assertRegistryRestored holds the behaviour both corruption scenarios share
// after the broken column has been restored verbatim.
func assertRegistryRestored(t *testing.T, router *gin.Engine, allowBody string, deny, allow, staging map[string]any) {
	t.Helper()

	// All three filters return the complete committed set again, sorted by
	// order ascending and identical to the pre-corruption state in every
	// submitted field, rule order, plugin string, order value and conflict
	// flag.
	wantPayments := []map[string]any{deny, allow}
	for _, target := range []string{
		"/v1/net-policies?namespace=payments",
		"/v1/net-policies?label=tier%3Dbackend",
		"/v1/net-policies?namespace=payments&label=tier%3Dbackend",
	} {
		if items := listItems(t, router, target); !reflect.DeepEqual(items, wantPayments) {
			t.Fatalf("GET %s after restore items = %v, want %v", target, items, wantPayments)
		}
	}
	if items := listItems(t, router, "/v1/net-policies?namespace=staging"); !reflect.DeepEqual(items, []map[string]any{staging}) {
		t.Fatalf("staging items after restore = %v, want %v", items, staging)
	}

	// The original content is once again an idempotent retry: 200 with the
	// original record.
	retry := doRequest(router, http.MethodPost, "/v1/net-policies", allowBody)
	if retry.Code != http.StatusOK {
		t.Fatalf("retry after restore status = %d, want %d: %s", retry.Code, http.StatusOK, retry.Body.String())
	}
	if got := decodeRecord(t, retry.Body.Bytes()); !reflect.DeepEqual(got, allow) {
		t.Fatalf("retry after restore record = %v, want original %v", got, allow)
	}
}

// A committed record whose stored rules no longer decode takes down every
// query and same-identity write that would have to read it, including the
// conflict scan for a brand-new identity in the same namespace and label.
// Restoring the rules verbatim brings the registry back exactly, and the
// request that failed while the rules were broken commits with the next
// order and a conflict flag computed from the restored history.
func TestCorruptedStoredRulesFailClosedUntilRestored(t *testing.T) {
	router, _, _, admin := newFaultRouter(t)
	allowBody, deny, allow, staging := seedCorruptionFixture(t, router)

	// Break only the rules column of the second record: syntactically
	// incomplete JSON, everything else stored stays as committed.
	originalRules := corruptStoredColumn(t, admin, "payments", "allow-web", "rules",
		`[{"direction": "ingress", "action": "allow", "ports": [100,`)

	assertCorruptionFailsClosed(t, router, allowBody, staging)

	// With rules undecodable the conflict scan cannot run either: a brand-new
	// identity in the same namespace and label fails with 503, writes no
	// record and consumes no order. Repeating it fails the same way.
	quarantineBody := singleRuleBody("payments", "quarantine-web", "tier=backend",
		"ingress", "deny", 150, 150, `{"mode": "enforce"}`)
	postExpect(t, router, quarantineBody, http.StatusServiceUnavailable, "storage_unavailable")
	postExpect(t, router, quarantineBody, http.StatusServiceUnavailable, "storage_unavailable")

	// Restore the stored rules verbatim: the registry returns to its exact
	// pre-corruption state.
	restoreStoredColumn(t, admin, "payments", "allow-web", "rules", originalRules)
	assertRegistryRestored(t, router, allowBody, deny, allow, staging)

	// The request that failed while the rules were broken now commits: it
	// takes the maximum committed order plus one — the failed attempts
	// consumed nothing — and its conflict flag is computed from the restored
	// historical rules (ingress deny [150,150] clashes with allow [100,200]).
	quarantine := registerCreated(t, router, quarantineBody, 4, true)

	wantAll := []map[string]any{deny, allow, quarantine}
	if items := listItems(t, router, "/v1/net-policies?namespace=payments"); !reflect.DeepEqual(items, wantAll) {
		t.Fatalf("items after recovery = %v, want %v", items, wantAll)
	}
}

// The conflict scan for a brand-new identity must read every committed record
// in the candidate's namespace and label before deciding: when one record in
// that scope holds undecodable rules, the registration fails with 503
// storage_unavailable even though another intact record in the same scope
// already determines the conflict flag by itself. The answer must not depend
// on the order the historical records were registered in or on how their
// names sort, and the failed attempts must leave no row, consume no order and
// not touch the intact records. Restoring the broken rules verbatim lets the
// same request commit with the next order and the conflict flag computed from
// the restored history. The scenario runs under every combination of
// registration order and name ordering of the two historical records.
func TestConflictScanFailsClosedOnCorruptScopeRegardlessOfHistoryOrder(t *testing.T) {
	cases := []struct {
		name         string
		corruptName  string // policy name of the record whose rules get broken
		corruptFirst bool   // register the to-be-corrupted record before the intact one
	}{
		{"corrupt registered first, name sorts first", "aaa-dns", true},
		{"corrupt registered first, name sorts last", "zzz-dns", true},
		{"corrupt registered second, name sorts first", "aaa-dns", false},
		{"corrupt registered second, name sorts last", "zzz-dns", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, _, _, admin := newFaultRouter(t)

			// Same namespace and label: an intact ingress deny [80,100] and an
			// egress allow [53,53] whose stored rules are about to be broken.
			denyBody := singleRuleBody("payments", "deny-web", "tier=backend",
				"ingress", "deny", 80, 100, `{"mode": "enforce"}`)
			egressBody := singleRuleBody("payments", tc.corruptName, "tier=backend",
				"egress", "allow", 53, 53, `{}`)
			var seeds []map[string]any
			var deny map[string]any
			if tc.corruptFirst {
				seeds = append(seeds, registerCreated(t, router, egressBody, 1, false))
				deny = registerCreated(t, router, denyBody, 2, false)
				seeds = append(seeds, deny)
			} else {
				deny = registerCreated(t, router, denyBody, 1, false)
				seeds = append(seeds, deny)
				seeds = append(seeds, registerCreated(t, router, egressBody, 2, false))
			}
			stagingBody := singleRuleBody("staging", "batch", "tier=frontend", "egress", "allow", 53, 53, `{}`)
			staging := registerCreated(t, router, stagingBody, 3, false)

			// Break only the rules column of the egress record: syntactically
			// incomplete JSON, connection and every other stored byte intact.
			originalRules := corruptStoredColumn(t, admin, "payments", tc.corruptName, "rules",
				`[{"direction": "egress", "action": "allow", "ports": [53,`)

			// A brand-new identity in the same scope. The intact deny record
			// alone already decides the rules conflict (ingress allow [100,200]
			// meets ingress deny [80,100] at port 100), yet the undecodable
			// record in the same scope must still fail the request closed:
			// 503 storage_unavailable, and the repeat fails the same way.
			candidateBody := singleRuleBody("payments", "allow-web", "tier=backend",
				"ingress", "allow", 100, 200, `{"mode": "enforce"}`)
			postExpect(t, router, candidateBody, http.StatusServiceUnavailable, "storage_unavailable")
			postExpect(t, router, candidateBody, http.StatusServiceUnavailable, "storage_unavailable")

			// The established error priorities hold while the scope is corrupt:
			// input validation still runs before storage is touched.
			postExpect(t, router,
				singleRuleBody("payments", "bad-direction", "tier=backend", "sideways", "allow", 80, 80, `{}`),
				http.StatusBadRequest, "InvalidNetPolicyInputError")
			postExpect(t, router,
				singleRuleBody("payments", "port-too-high", "tier=backend", "ingress", "allow", 1, 65536, `{}`),
				http.StatusBadRequest, "InvalidNetPolicyInputError")

			// Same identity as the corrupt record, different legal content: the
			// intact content fingerprint still decides -> 409.
			changedBody := singleRuleBody("payments", tc.corruptName, "tier=backend",
				"egress", "allow", 53, 53, `{"mode": "audit"}`)
			postExpect(t, router, changedBody, http.StatusConflict, "NetPolicyConflictError")

			// Same-content retry of the intact record is read-only and stays
			// 200 with the original record, unaffected by the corrupt record
			// sharing its scope.
			intactRetry := doRequest(router, http.MethodPost, "/v1/net-policies", denyBody)
			if intactRetry.Code != http.StatusOK {
				t.Fatalf("intact retry status = %d, want %d: %s", intactRetry.Code, http.StatusOK, intactRetry.Body.String())
			}
			if got := decodeRecord(t, intactRetry.Body.Bytes()); !reflect.DeepEqual(got, deny) {
				t.Fatalf("intact retry record = %v, want the committed deny record %v", got, deny)
			}

			// Same-content retry of the corrupt identity itself cannot decode
			// the stored record for the response -> 503.
			postExpect(t, router, egressBody, http.StatusServiceUnavailable, "storage_unavailable")

			// Queries that would have to decode the broken record fail closed
			// with no partial items; filters excluding it still hit, a query
			// matching nothing stays 404, and the healthy connection keeps the
			// health check at 200.
			for _, target := range []string{
				"/v1/net-policies?namespace=payments",
				"/v1/net-policies?label=tier%3Dbackend",
				"/v1/net-policies?namespace=payments&label=tier%3Dbackend",
			} {
				getExpectError(t, router, target, http.StatusServiceUnavailable, "storage_unavailable")
			}
			if items := listItems(t, router, "/v1/net-policies?namespace=staging"); !reflect.DeepEqual(items, []map[string]any{staging}) {
				t.Fatalf("staging items = %v, want only %v", items, staging)
			}
			getExpectError(t, router, "/v1/net-policies?namespace=missing", http.StatusNotFound, "NetPolicyNotFoundError")
			health := doRequest(router, http.MethodGet, "/healthz", "")
			if health.Code != http.StatusOK || health.Body.String() != `{"database":"ok","status":"ok"}` {
				t.Fatalf("healthz with corrupted record = %d %s, want 200 ok", health.Code, health.Body.String())
			}

			// Restore the stored rules verbatim: the historical records come
			// back exactly as committed, proving the failed registrations
			// changed none of their fields or conflict flags.
			restoreStoredColumn(t, admin, "payments", tc.corruptName, "rules", originalRules)

			// The request that failed while the scope was corrupt now commits:
			// order is the maximum committed order plus one — the failed
			// attempts consumed nothing — and conflict is true because the
			// restored history holds ingress deny [80,100].
			candidate := registerCreated(t, router, candidateBody, 4, true)

			// The identical retry is now an idempotent 200 with that record.
			retry := doRequest(router, http.MethodPost, "/v1/net-policies", candidateBody)
			if retry.Code != http.StatusOK {
				t.Fatalf("retry after restore status = %d, want %d: %s", retry.Code, http.StatusOK, retry.Body.String())
			}
			if got := decodeRecord(t, retry.Body.Bytes()); !reflect.DeepEqual(got, candidate) {
				t.Fatalf("retry after restore record = %v, want %v", got, candidate)
			}

			// A further legal new identity continues the order sequence.
			nextBody := singleRuleBody("payments", "after-recovery", "tier=backend",
				"egress", "allow", 8053, 8053, `{}`)
			next := registerCreated(t, router, nextBody, 5, false)

			// The restored registry returns the complete record set sorted by
			// order ascending, every historical field and conflict flag intact.
			wantAll := append(append([]map[string]any{}, seeds...), candidate, next)
			if items := listItems(t, router, "/v1/net-policies?namespace=payments"); !reflect.DeepEqual(items, wantAll) {
				t.Fatalf("items after recovery = %v, want %v", items, wantAll)
			}
		})
	}
}

// A committed record whose stored pluginParams no longer decode takes down
// every query and same-identity identical-content write that would have to
// read it, while the intact content fingerprint still answers 409 for
// different content. Restoring the params verbatim brings the registry back
// exactly, and later registrations continue the order sequence.
func TestCorruptedStoredPluginParamsFailClosedUntilRestored(t *testing.T) {
	router, _, _, admin := newFaultRouter(t)
	allowBody, deny, allow, staging := seedCorruptionFixture(t, router)

	// Break only the plugin_params column of the second record: syntactically
	// incomplete JSON, everything else stored stays as committed.
	originalParams := corruptStoredColumn(t, admin, "payments", "allow-web", "plugin_params",
		`{"mode": "enforce", "zone":`)

	assertCorruptionFailsClosed(t, router, allowBody, staging)

	// Restore the stored pluginParams verbatim: the registry returns to its
	// exact pre-corruption state.
	restoreStoredColumn(t, admin, "payments", "allow-web", "plugin_params", originalParams)
	assertRegistryRestored(t, router, allowBody, deny, allow, staging)

	// A brand-new identity now commits with the next order, proving the
	// requests rejected above consumed nothing (egress allow clashes with
	// nothing in the restored history).
	nextBody := singleRuleBody("payments", "after-restore", "tier=backend", "egress", "allow", 53, 53, `{}`)
	registerCreated(t, router, nextBody, 4, false)
}
