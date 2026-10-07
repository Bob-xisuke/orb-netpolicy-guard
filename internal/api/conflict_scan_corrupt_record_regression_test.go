package api

// Regression tests for the conflict scan skipping corrupt history records:
// the scan used to stop at the first committed record that already decided the
// clash, so a record in the same namespace and label whose stored rules no
// longer parse was reported (503) or silently skipped (201) depending on the
// order the history rows happened to be read in — insertion order and name
// sort order both changed the outcome. The scan must decode every record in
// scope before answering: any undecodable record sharing the candidate's
// namespace and label fails the registration with 503 storage_unavailable,
// even when an intact record already suffices to decide the conflict, and
// regardless of how the history records are named or were committed. Records
// in a different namespace or label never block registration, and matching
// keeps using the stored values verbatim — no trimming, no case folding. No
// production code or public behaviour is stubbed.

import (
	"database/sql"
	"net/http"
	"reflect"
	"testing"
)

// assertRegistryUntouched demands that rejected registrations left the registry
// exactly as seeded: the row count and the maximum committed order are
// unchanged (no row written, no order consumed) and no row exists under the
// candidate identity.
func assertRegistryUntouched(t *testing.T, admin *sql.DB, wantRows int, wantMaxSeq int64, namespace, candidateName string) {
	t.Helper()
	var rows int
	if err := admin.QueryRow(`SELECT COUNT(*) FROM net_policies`).Scan(&rows); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rows != wantRows {
		t.Fatalf("row count = %d, want %d: rejected registration must leave no row", rows, wantRows)
	}
	var maxSeq int64
	if err := admin.QueryRow(`SELECT COALESCE(MAX(seq), 0) FROM net_policies`).Scan(&maxSeq); err != nil {
		t.Fatalf("max committed order: %v", err)
	}
	if maxSeq != wantMaxSeq {
		t.Fatalf("max committed order = %d, want %d: rejected registration must consume no order", maxSeq, wantMaxSeq)
	}
	var candidateRows int
	if err := admin.QueryRow(
		`SELECT COUNT(*) FROM net_policies WHERE namespace = ? AND name = ?`,
		namespace, candidateName).Scan(&candidateRows); err != nil {
		t.Fatalf("count candidate rows: %v", err)
	}
	if candidateRows != 0 {
		t.Fatalf("candidate identity %s/%s has %d rows, want none", namespace, candidateName, candidateRows)
	}
}

// storedConflictFlag reads one committed record's conflict flag through the
// independent admin connection.
func storedConflictFlag(t *testing.T, admin *sql.DB, namespace, name string) int {
	t.Helper()
	var flag int
	if err := admin.QueryRow(
		`SELECT conflict FROM net_policies WHERE namespace = ? AND name = ?`,
		namespace, name).Scan(&flag); err != nil {
		t.Fatalf("read stored conflict flag for %s/%s: %v", namespace, name, err)
	}
	return flag
}

// The same corrupt-history scenario must behave identically however the two
// history records are ordered: the corrupt record committed first or last, and
// its name sorting before or after the intact record's name. SQLite is free to
// read the history rows in insertion (rowid) order or in primary-key (name)
// order, so all four combinations are exercised.
func TestConflictScanDecodesWholeScopeRegardlessOfHistoryOrder(t *testing.T) {
	cases := []struct {
		name        string
		denyName    string
		egressName  string
		egressFirst bool
	}{
		{"corrupt committed first and name sorts first", "z-deny", "a-egress", true},
		{"corrupt committed last and name sorts last", "a-deny", "z-egress", false},
		{"corrupt committed first but name sorts last", "a-deny", "z-egress", true},
		{"corrupt committed last but name sorts first", "z-deny", "a-egress", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runCorruptHistoryConflictScenario(t, tc.denyName, tc.egressName, tc.egressFirst)
		})
	}
}

// runCorruptHistoryConflictScenario seeds an intact ingress deny [80,100] and
// an egress allow [53,53] in one namespace/label, breaks the egress record's
// stored rules into syntactically incomplete JSON, and demands that a new
// identity whose ingress allow [100,200] already clashes with the intact deny
// still fails closed with 503 — deterministically, atomically, and with every
// other error priority and read path preserved — until the column is restored
// verbatim, after which the same request commits with the next order and
// conflict=true.
func runCorruptHistoryConflictScenario(t *testing.T, denyName, egressName string, egressFirst bool) {
	router, _, _, admin := newFaultRouter(t)

	denyBody := singleRuleBody("payments", denyName, "tier=backend",
		"ingress", "deny", 80, 100, `{"mode": "enforce"}`)
	egressBody := singleRuleBody("payments", egressName, "tier=backend",
		"egress", "allow", 53, 53, `{"mode": "enforce"}`)

	// Commit the two history records in the requested order. Different
	// directions never clash, so both carry conflict=false.
	var deny, egress map[string]any
	if egressFirst {
		egress = registerCreated(t, router, egressBody, 1, false)
		deny = registerCreated(t, router, denyBody, 2, false)
	} else {
		deny = registerCreated(t, router, denyBody, 1, false)
		egress = registerCreated(t, router, egressBody, 2, false)
	}
	stagingBody := singleRuleBody("staging", "batch", "tier=frontend",
		"egress", "allow", 53, 53, `{}`)
	staging := registerCreated(t, router, stagingBody, 3, false)

	// Break only the rules column of the egress record: syntactically
	// incomplete JSON, every other stored byte and the connection itself
	// intact and readable/writable.
	originalRules := corruptStoredColumn(t, admin, "payments", egressName, "rules",
		`[{"direction": "egress", "action": "allow", "ports": [53,`)

	// The candidate's ingress allow [100,200] overlaps the intact deny [80,100]
	// at port 100, so the intact record alone already decides conflict=true —
	// yet the corrupt record in the same namespace and label must still fail
	// the registration with 503, on the first submit and on every repeat.
	candidateBody := singleRuleBody("payments", "fresh-allow", "tier=backend",
		"ingress", "allow", 100, 200, `{"mode": "enforce"}`)
	postExpect(t, router, candidateBody, http.StatusServiceUnavailable, "storage_unavailable")
	postExpect(t, router, candidateBody, http.StatusServiceUnavailable, "storage_unavailable")

	// The rejected submits were atomic: no row, no order consumed, and the
	// intact history record's stored conflict flag untouched.
	assertRegistryUntouched(t, admin, 3, 3, "payments", "fresh-allow")
	if flag := storedConflictFlag(t, admin, "payments", denyName); flag != 0 {
		t.Fatalf("intact history record conflict flag = %d, want unchanged 0", flag)
	}

	// Input validation still runs before storage is read: illegal direction
	// and out-of-range port stay 400.
	postExpect(t, router,
		singleRuleBody("payments", "bad-direction", "tier=backend", "sideways", "allow", 80, 80, `{}`),
		http.StatusBadRequest, "InvalidNetPolicyInputError")
	postExpect(t, router,
		singleRuleBody("payments", "port-too-high", "tier=backend", "ingress", "allow", 1, 65536, `{}`),
		http.StatusBadRequest, "InvalidNetPolicyInputError")

	// Same identity on the intact record: different legal content still
	// conflicts on the intact fingerprint -> 409; identical content is a
	// read-only retry -> 200 with the original record, unaffected by the
	// corrupt record standing next to it in the same scope.
	changedDeny := singleRuleBody("payments", denyName, "tier=backend",
		"ingress", "deny", 80, 100, `{"mode": "audit"}`)
	postExpect(t, router, changedDeny, http.StatusConflict, "NetPolicyConflictError")
	retryDeny := doRequest(router, http.MethodPost, "/v1/net-policies", denyBody)
	if retryDeny.Code != http.StatusOK {
		t.Fatalf("intact identity retry status = %d, want %d: %s",
			retryDeny.Code, http.StatusOK, retryDeny.Body.String())
	}
	if got := decodeRecord(t, retryDeny.Body.Bytes()); !reflect.DeepEqual(got, deny) {
		t.Fatalf("intact identity retry record = %v, want original %v", got, deny)
	}

	// Same identity on the corrupt record with identical content: the stored
	// record itself cannot be decoded for the response -> same 503.
	postExpect(t, router, egressBody, http.StatusServiceUnavailable, "storage_unavailable")

	// Reads that would have to decode the broken record fail closed with 503
	// and no partial items; filters excluding it still hit 200, and a filter
	// matching nothing stays 404.
	getExpectError(t, router, "/v1/net-policies?namespace=payments",
		http.StatusServiceUnavailable, "storage_unavailable")
	getExpectError(t, router, "/v1/net-policies?label=tier%3Dbackend",
		http.StatusServiceUnavailable, "storage_unavailable")
	if items := listItems(t, router, "/v1/net-policies?namespace=staging"); !reflect.DeepEqual(items, []map[string]any{staging}) {
		t.Fatalf("staging items = %v, want only %v", items, staging)
	}
	getExpectError(t, router, "/v1/net-policies?namespace=missing",
		http.StatusNotFound, "NetPolicyNotFoundError")

	// The connection itself is healthy: the health check keeps reporting ok.
	health := doRequest(router, http.MethodGet, "/healthz", "")
	if health.Code != http.StatusOK || health.Body.String() != `{"database":"ok","status":"ok"}` {
		t.Fatalf("healthz with corrupted record = %d %s, want 200 ok", health.Code, health.Body.String())
	}

	// The corrupt record blocks only its own namespace+label scope: new
	// identities under a different label in the same namespace and under a
	// different namespace still commit, consuming the next orders.
	cacheBody := singleRuleBody("payments", "cache-writer", "tier=cache",
		"egress", "allow", 53, 53, `{}`)
	cache := registerCreated(t, router, cacheBody, 4, false)
	extraStagingBody := singleRuleBody("staging", "extra", "tier=frontend",
		"egress", "allow", 9000, 9000, `{}`)
	extraStaging := registerCreated(t, router, extraStagingBody, 5, false)

	// Restore the stored rules verbatim.
	restoreStoredColumn(t, admin, "payments", egressName, "rules", originalRules)

	// The request that failed while the rules were broken now commits: order
	// is the maximum committed order plus one — the 503 attempts consumed
	// nothing — and conflict=true is computed from the restored history
	// (ingress allow [100,200] clashes with deny [80,100]).
	candidate := registerCreated(t, router, candidateBody, 6, true)

	// The identical retry is now a read-only 200 returning the same record.
	retry := doRequest(router, http.MethodPost, "/v1/net-policies", candidateBody)
	if retry.Code != http.StatusOK {
		t.Fatalf("retry after restore status = %d, want %d: %s",
			retry.Code, http.StatusOK, retry.Body.String())
	}
	if got := decodeRecord(t, retry.Body.Bytes()); !reflect.DeepEqual(got, candidate) {
		t.Fatalf("retry after restore record = %v, want %v", got, candidate)
	}

	// Another legal new policy continues the sequence (egress allow matches
	// the restored egress record in direction and action, so no conflict).
	secondBody := singleRuleBody("payments", "second-fresh", "tier=backend",
		"egress", "allow", 53, 53, `{}`)
	second := registerCreated(t, router, secondBody, 7, false)

	// The restored registry returns the complete record set, sorted by order
	// ascending and identical to what was committed in every field.
	var wantPayments []map[string]any
	if egressFirst {
		wantPayments = []map[string]any{egress, deny, cache, candidate, second}
	} else {
		wantPayments = []map[string]any{deny, egress, cache, candidate, second}
	}
	for _, target := range []string{
		"/v1/net-policies?namespace=payments",
		"/v1/net-policies?namespace=payments&label=tier%3Dbackend",
	} {
		want := wantPayments
		if target == "/v1/net-policies?namespace=payments&label=tier%3Dbackend" {
			// The tier=cache record is excluded by the label filter.
			want = append(want[:2:2], want[3:]...)
		}
		if items := listItems(t, router, target); !reflect.DeepEqual(items, want) {
			t.Fatalf("GET %s after restore items = %v, want %v", target, items, want)
		}
	}
	if items := listItems(t, router, "/v1/net-policies?namespace=staging"); !reflect.DeepEqual(items, []map[string]any{staging, extraStaging}) {
		t.Fatalf("staging items after restore = %v, want %v", items, []map[string]any{staging, extraStaging})
	}

	// Matching uses the stored values verbatim: a namespace differing only by
	// case or by surrounding whitespace matches nothing.
	getExpectError(t, router, "/v1/net-policies?namespace=Payments",
		http.StatusNotFound, "NetPolicyNotFoundError")
	getExpectError(t, router, "/v1/net-policies?namespace=%20payments",
		http.StatusNotFound, "NetPolicyNotFoundError")
}
