package api

// Deterministic regression tests for transaction visibility: a complete
// candidate row is written through a second connection to the same database
// file and held inside an open, uncommitted transaction while the public
// GET /v1/net-policies entry is queried. The query results are pinned down
// in three snapshots — before commit, after commit, and after rollback — so
// the proof never relies on racing reads against writes and observing the
// final state. No production code or public entry point is added.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/Bob-xisuke/orb-netpolicy-guard/internal/store"

	_ "modernc.org/sqlite"
)

// candidateRecord describes a complete net_policies row held inside an open,
// uncommitted transaction: the same column values store.Register would persist
// for the equivalent registration.
type candidateRecord struct {
	namespace string
	name      string
	label     string
	rules     []store.Rule
	params    map[string]string
	seq       int64
	conflict  bool
}

// newSnapshotRouter opens a service store plus an independent connection to
// the same database file, used to hold a candidate row inside an open
// transaction while the public HTTP surface is queried.
func newSnapshotRouter(t *testing.T) (*gin.Engine, *sql.DB) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "service.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	admin, err := sql.Open("sqlite", dbPath)
	if err != nil {
		st.Close()
		t.Fatalf("open snapshot connection: %v", err)
	}
	t.Cleanup(func() {
		admin.Close()
		st.Close()
	})
	return NewRouter(st), admin
}

// insertUncommittedCandidate writes a complete candidate row exactly the way
// store.Register persists it (same columns, same content fingerprint) but
// holds the surrounding transaction open, and proves from inside the
// transaction that the row genuinely exists before returning. The caller
// decides whether the candidate ever becomes visible by committing or rolling
// back the returned transaction.
func insertUncommittedCandidate(t *testing.T, admin *sql.DB, row candidateRecord) *sql.Tx {
	t.Helper()
	rulesJSON, err := json.Marshal(row.rules)
	if err != nil {
		t.Fatalf("marshal candidate rules: %v", err)
	}
	paramsJSON, err := json.Marshal(row.params)
	if err != nil {
		t.Fatalf("marshal candidate plugin params: %v", err)
	}
	// The same fingerprint store.Register stores in the content column.
	content := row.label + "\x00" + string(rulesJSON) + "\x00" + string(paramsJSON)
	conflictFlag := 0
	if row.conflict {
		conflictFlag = 1
	}

	tx, err := admin.Begin()
	if err != nil {
		t.Fatalf("begin candidate transaction: %v", err)
	}
	if _, err := tx.Exec(
		`INSERT INTO net_policies (namespace, name, label, rules, plugin_params, content, seq, conflict)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		row.namespace, row.name, row.label, string(rulesJSON), string(paramsJSON),
		content, row.seq, conflictFlag); err != nil {
		tx.Rollback()
		t.Fatalf("insert candidate: %v", err)
	}
	// The candidate row is genuinely written at this point: it is visible from
	// inside the still-open transaction, so every query below runs in the
	// "written but uncommitted" phase by construction, not by timing.
	var count int
	if err := tx.QueryRow(
		`SELECT COUNT(*) FROM net_policies WHERE namespace = ? AND name = ?`,
		row.namespace, row.name).Scan(&count); err != nil {
		tx.Rollback()
		t.Fatalf("count candidate inside transaction: %v", err)
	}
	if count != 1 {
		tx.Rollback()
		t.Fatalf("candidate row count inside transaction = %d, want 1", count)
	}
	return tx
}

// assertGetNotFound demands 404 with the published NetPolicyNotFoundError
// shape and a leak-free message.
func assertGetNotFound(t *testing.T, router *gin.Engine, target string) {
	t.Helper()
	recorder := doRequest(router, http.MethodGet, target, "")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("GET %s status = %d, want %d: %s",
			target, recorder.Code, http.StatusNotFound, recorder.Body.String())
	}
	assertExactErrorShape(t, recorder, "NetPolicyNotFoundError")
	assertSafeErrorMessage(t, recorder)
}

// Commit scenario: a committed ingress deny [80,100] (order 1, conflict=false)
// is followed by a same-group ingress allow [100,200] candidate held
// uncommitted. While the candidate transaction is open, every filter — by
// namespace, by label and by their intersection — returns 200 with only the
// original record. After the candidate commits, all three filters return both
// complete records ascending by order: the new one with order 2 and
// conflict=true (the closed intervals touch at port 100), the original
// unchanged in every field. A later registration through the public POST
// entry continues the sequence at order 3.
func TestUncommittedCandidateInvisibleUntilCommit(t *testing.T) {
	router, admin := newSnapshotRouter(t)

	denyBody := singleRuleBody("payments", "deny-web", "tier=backend",
		"ingress", "deny", 80, 100, `{"mode": "enforce"}`)
	deny := registerCreated(t, router, denyBody, 1, false)

	allowBody := singleRuleBody("payments", "allow-web", "tier=backend",
		"ingress", "allow", 100, 200, `{"mode": "enforce"}`)
	wantAllow := wantRecord(t, allowBody, 2, true)

	tx := insertUncommittedCandidate(t, admin, candidateRecord{
		namespace: "payments",
		name:      "allow-web",
		label:     "tier=backend",
		rules:     []store.Rule{{Direction: "ingress", Action: "allow", Ports: [2]int{100, 200}}},
		params:    map[string]string{"mode": "enforce"},
		seq:       2,
		conflict:  true,
	})

	targets := []string{
		"/v1/net-policies?namespace=payments",
		"/v1/net-policies?label=tier%3Dbackend",
		"/v1/net-policies?namespace=payments&label=tier%3Dbackend",
	}

	// Snapshot before commit: the candidate row exists but is uncommitted, so
	// every filter returns exactly the original record and nothing else.
	for _, target := range targets {
		if items := listItems(t, router, target); !reflect.DeepEqual(items, []map[string]any{deny}) {
			t.Fatalf("GET %s before commit items = %v, want only the original record %v",
				target, items, deny)
		}
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("commit candidate: %v", err)
	}

	// Snapshot after commit: both complete records, ascending by order, the
	// original record untouched in every field — no field mixing, no
	// duplicated identity.
	wantBoth := []map[string]any{deny, wantAllow}
	for _, target := range targets {
		if items := listItems(t, router, target); !reflect.DeepEqual(items, wantBoth) {
			t.Fatalf("GET %s after commit items = %v, want %v", target, items, wantBoth)
		}
	}

	// Registration through the public POST entry still works afterwards and
	// continues the sequence (egress, so no rule clash with the ingress pair).
	nextBody := singleRuleBody("payments", "after-commit", "tier=backend",
		"egress", "allow", 53, 53, `{}`)
	registerCreated(t, router, nextBody, 3, false)
}

// Rollback scenario on an empty store with independent data: while the
// candidate row is uncommitted and again after the rollback, every filter
// that would match it returns 404 NetPolicyNotFoundError, and a query missing
// filter conditions still returns 400 InvalidNetPolicyInputError — input
// validation does not depend on transaction state. The same legal content
// then commits through POST with 201 and order 1, proving the rollback left
// no record and consumed no order; an identical retry returns 200 with the
// original record, changed plugin params return 409 NetPolicyConflictError,
// and queries still show only the original record.
func TestRolledBackCandidateLeavesNoRecordOrOrder(t *testing.T) {
	router, admin := newSnapshotRouter(t)

	candidateBody := singleRuleBody("inventory", "deny-web", "tier=frontend",
		"ingress", "deny", 80, 100, `{"mode": "enforce"}`)
	tx := insertUncommittedCandidate(t, admin, candidateRecord{
		namespace: "inventory",
		name:      "deny-web",
		label:     "tier=frontend",
		rules:     []store.Rule{{Direction: "ingress", Action: "deny", Ports: [2]int{80, 100}}},
		params:    map[string]string{"mode": "enforce"},
		seq:       1,
		conflict:  false,
	})

	targets := []string{
		"/v1/net-policies?namespace=inventory",
		"/v1/net-policies?label=tier%3Dfrontend",
		"/v1/net-policies?namespace=inventory&label=tier%3Dfrontend",
	}

	// Snapshot while uncommitted: every filter matching the candidate is 404.
	for _, target := range targets {
		assertGetNotFound(t, router, target)
	}

	// A query without filter conditions is invalid input regardless of the
	// open transaction.
	noFilter := doRequest(router, http.MethodGet, "/v1/net-policies", "")
	if noFilter.Code != http.StatusBadRequest {
		t.Fatalf("GET without filters status = %d, want %d: %s",
			noFilter.Code, http.StatusBadRequest, noFilter.Body.String())
	}
	assertExactErrorShape(t, noFilter, "InvalidNetPolicyInputError")
	assertSafeErrorMessage(t, noFilter)

	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback candidate: %v", err)
	}

	// Snapshot after rollback: still 404 on every matching filter.
	for _, target := range targets {
		assertGetNotFound(t, router, target)
	}

	// The same legal content now commits as the very first record: the
	// rollback left no row behind and consumed no order.
	created := registerCreated(t, router, candidateBody, 1, false)

	// Identical retry: 200 with the original record.
	retry := doRequest(router, http.MethodPost, "/v1/net-policies", candidateBody)
	if retry.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want %d: %s", retry.Code, http.StatusOK, retry.Body.String())
	}
	if got := decodeRecord(t, retry.Body.Bytes()); !reflect.DeepEqual(got, created) {
		t.Fatalf("retry record = %v, want original %v", got, created)
	}

	// Same identity with changed plugin params: 409 NetPolicyConflictError.
	changedBody := singleRuleBody("inventory", "deny-web", "tier=frontend",
		"ingress", "deny", 80, 100, `{"mode": "audit"}`)
	changed := doRequest(router, http.MethodPost, "/v1/net-policies", changedBody)
	if changed.Code != http.StatusConflict {
		t.Fatalf("changed status = %d, want %d: %s",
			changed.Code, http.StatusConflict, changed.Body.String())
	}
	assertExactErrorShape(t, changed, "NetPolicyConflictError")
	assertSafeErrorMessage(t, changed)

	// Queries still return only the original record, unchanged in every field.
	for _, target := range targets {
		if items := listItems(t, router, target); !reflect.DeepEqual(items, []map[string]any{created}) {
			t.Fatalf("GET %s items = %v, want only the original record %v", target, items, created)
		}
	}
}
