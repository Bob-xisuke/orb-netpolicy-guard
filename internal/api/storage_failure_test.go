package api

// Regression tests for storage write failures: a storage that can still be read
// but refuses new records, and a fully unavailable storage. The write failure is
// injected at the real SQLite layer through a second connection to the same
// database file (a BEFORE INSERT trigger that raises ABORT), so the service
// issues genuine INSERTs that the database genuinely rejects and rolls back;
// dropping the trigger restores writes on the same file. No production code or
// public behaviour is stubbed.

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/Bob-xisuke/orb-netpolicy-guard/internal/store"

	_ "modernc.org/sqlite"
)

// blockInsertTrigger aborts every INSERT on net_policies while leaving SELECTs
// untouched, modelling "storage readable but refusing new records".
const blockInsertTrigger = `CREATE TRIGGER fail_new_policy
BEFORE INSERT ON net_policies
BEGIN
	SELECT RAISE(ABORT, 'simulated storage outage');
END`

// newFaultRouter opens a service database and an independent connection to the
// same file used only to install/remove the failure trigger.
func newFaultRouter(t *testing.T) (*gin.Engine, *store.Store, string, *sql.DB) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "service.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	admin, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open fault connection: %v", err)
	}
	t.Cleanup(func() {
		admin.Close()
		st.Close()
	})
	return NewRouter(st), st, dbPath, admin
}

func blockStorageInserts(t *testing.T, admin *sql.DB) {
	t.Helper()
	if _, err := admin.Exec(blockInsertTrigger); err != nil {
		t.Fatalf("install insert-blocking trigger: %v", err)
	}
}

func restoreStorageInserts(t *testing.T, admin *sql.DB) {
	t.Helper()
	if _, err := admin.Exec(`DROP TRIGGER fail_new_policy`); err != nil {
		t.Fatalf("drop insert-blocking trigger: %v", err)
	}
}

func postExpect(t *testing.T, router *gin.Engine, body string, wantStatus int, wantCode string) {
	t.Helper()
	recorder := doRequest(router, http.MethodPost, "/v1/net-policies", body)
	if recorder.Code != wantStatus {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, wantStatus, recorder.Body.String())
	}
	if wantStatus >= 400 {
		assertExactErrorShape(t, recorder, wantCode)
		assertSafeErrorMessage(t, recorder)
	}
}

// A registration whose INSERT is rejected by storage returns 503
// storage_unavailable and is atomic: no row, no order consumed, existing
// records untouched in every field, ordering and conflict flag. Read-only paths
// (queries, same-content retry, different-content 409) keep working while the
// failure condition holds. Once writes are allowed again the original request
// succeeds with the next order, the state survives a close/reopen, and the
// following registration continues the sequence.
func TestRegisterStorageWriteFailureIsAtomicAndRecoverable(t *testing.T) {
	router, st, dbPath, admin := newFaultRouter(t)

	// Two ingress policies in one namespace/label: [80,100] deny then
	// [100,200] allow; the closed intervals touch at 100, so the second is
	// flagged while the first keeps conflict=false.
	denyBody := singleRuleBody("payments", "deny-web", "tier=backend",
		"ingress", "deny", 80, 100, `{"mode": "enforce"}`)
	deny := registerCreated(t, router, denyBody, 1, false)
	allowBody := singleRuleBody("payments", "allow-web", "tier=backend",
		"ingress", "allow", 100, 200, `{"mode": "enforce"}`)
	allow := registerCreated(t, router, allowBody, 2, true)

	// Storage stays readable but refuses new records.
	blockStorageInserts(t, admin)

	// A brand-new identity (egress, so it would not clash by rules) with legal
	// string plugin params: the write is genuinely rejected -> 503.
	blockedBody := singleRuleBody("payments", "allow-dns", "tier=backend",
		"egress", "allow", 53, 53, `{"mode": "enforce"}`)
	postExpect(t, router, blockedBody, http.StatusServiceUnavailable, "storage_unavailable")

	// Repeating the failed request still fails the same way: it never created a
	// row, so there is nothing to idempotently return.
	postExpect(t, router, blockedBody, http.StatusServiceUnavailable, "storage_unavailable")

	// Every read path still returns exactly the two original records, identical
	// in all submitted fields, order and conflict flags, sorted by order.
	wantOnlyOriginals := []map[string]any{deny, allow}
	for _, target := range []string{
		"/v1/net-policies?namespace=payments",
		"/v1/net-policies?label=tier%3Dbackend",
		"/v1/net-policies?namespace=payments&label=tier%3Dbackend",
	} {
		if items := listItems(t, router, target); !reflect.DeepEqual(items, wantOnlyOriginals) {
			t.Fatalf("GET %s items = %v, want unchanged originals %v", target, items, wantOnlyOriginals)
		}
	}

	// Same identity with identical content on a committed record is a read-only
	// retry: 200 with the original record despite the write outage.
	retryExisting := doRequest(router, http.MethodPost, "/v1/net-policies", denyBody)
	if retryExisting.Code != http.StatusOK {
		t.Fatalf("existing identity retry status = %d, want %d: %s",
			retryExisting.Code, http.StatusOK, retryExisting.Body.String())
	}
	if got := decodeRecord(t, retryExisting.Body.Bytes()); !reflect.DeepEqual(got, deny) {
		t.Fatalf("retry record = %v, want original %v", got, deny)
	}

	// Same identity with different content stays a 409: the lookup and content
	// comparison happen before any write attempt.
	changedBody := singleRuleBody("payments", "deny-web", "tier=backend",
		"ingress", "deny", 80, 100, `{"mode": "audit"}`)
	postExpect(t, router, changedBody, http.StatusConflict, "NetPolicyConflictError")

	// Lift the failure condition and resubmit the request that had failed:
	// it now commits with order 3 and conflict=false (egress never clashes with
	// the ingress records).
	restoreStorageInserts(t, admin)
	recovered := registerCreated(t, router, blockedBody, 3, false)

	// Submitting it again is now an idempotent retry returning the same record.
	again := doRequest(router, http.MethodPost, "/v1/net-policies", blockedBody)
	if again.Code != http.StatusOK {
		t.Fatalf("recovered retry status = %d, want %d: %s",
			again.Code, http.StatusOK, again.Body.String())
	}
	if got := decodeRecord(t, again.Body.Bytes()); !reflect.DeepEqual(got, recovered) {
		t.Fatalf("recovered retry record = %v, want %v", got, recovered)
	}

	// Close and reopen the same database file: all three records survive with
	// every field, order and conflict flag intact.
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	reopened, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { reopened.Close() })
	router = NewRouter(reopened)

	wantPersisted := []map[string]any{deny, allow, recovered}
	if items := listItems(t, router, "/v1/net-policies?namespace=payments&label=tier%3Dbackend"); !reflect.DeepEqual(items, wantPersisted) {
		t.Fatalf("items after reopen = %v, want %v", items, wantPersisted)
	}

	// The failed registration consumed no order: the next legal new identity
	// takes order 4 (egress allow matches the existing egress in action, so no
	// conflict).
	nextBody := singleRuleBody("payments", "after-recovery", "tier=backend",
		"egress", "allow", 53, 53, `{}`)
	registerCreated(t, router, nextBody, 4, false)
}

// With storage completely unavailable a legal registration returns 503
// storage_unavailable, while invalid input is still rejected with 400
// InvalidNetPolicyInputError before storage is touched, and the health check
// reports 503. After storage comes back the invalid requests left no records
// and consumed no order, and the request that failed with 503 commits with the
// next sequence value.
func TestStorageFullyUnavailableFailuresAndRecovery(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "service.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	router := NewRouter(st)

	// Seed records so post-recovery state can be compared exactly.
	denyBody := singleRuleBody("payments", "deny-web", "tier=backend",
		"ingress", "deny", 80, 100, `{"mode": "enforce"}`)
	deny := registerCreated(t, router, denyBody, 1, false)
	allowBody := singleRuleBody("payments", "allow-web", "tier=backend",
		"ingress", "allow", 100, 200, `{"mode": "enforce"}`)
	allow := registerCreated(t, router, allowBody, 2, true)

	// Total outage: the database handle is closed.
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	// A legal registration cannot write: 503 storage_unavailable.
	blockedBody := singleRuleBody("payments", "allow-dns", "tier=backend",
		"egress", "allow", 53, 53, `{"mode": "enforce"}`)
	postExpect(t, router, blockedBody, http.StatusServiceUnavailable, "storage_unavailable")

	// Invalid input is rejected first regardless of storage state: bad
	// direction and out-of-range ports both stay 400.
	badDirection := singleRuleBody("payments", "bad-direction", "tier=backend",
		"sideways", "allow", 80, 80, `{}`)
	postExpect(t, router, badDirection, http.StatusBadRequest, "InvalidNetPolicyInputError")
	portTooHigh := singleRuleBody("payments", "port-too-high", "tier=backend",
		"ingress", "allow", 1, 65536, `{}`)
	postExpect(t, router, portTooHigh, http.StatusBadRequest, "InvalidNetPolicyInputError")
	portTooLow := singleRuleBody("payments", "port-too-low", "tier=backend",
		"ingress", "allow", 0, 80, `{}`)
	postExpect(t, router, portTooLow, http.StatusBadRequest, "InvalidNetPolicyInputError")

	// The health check surfaces the same storage failure with the same shape.
	health := doRequest(router, http.MethodGet, "/healthz", "")
	if health.Code != http.StatusServiceUnavailable {
		t.Fatalf("healthz status = %d, want %d: %s",
			health.Code, http.StatusServiceUnavailable, health.Body.String())
	}
	assertExactErrorShape(t, health, "storage_unavailable")
	assertSafeErrorMessage(t, health)

	// Recover by reopening the same database file.
	reopened, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { reopened.Close() })
	router = NewRouter(reopened)

	healthy := doRequest(router, http.MethodGet, "/healthz", "")
	if healthy.Code != http.StatusOK || healthy.Body.String() != `{"database":"ok","status":"ok"}` {
		t.Fatalf("healthz after recovery = %d %s, want 200 ok", healthy.Code, healthy.Body.String())
	}

	// Invalid input is still 400 after recovery and still writes nothing.
	postExpect(t, router, badDirection, http.StatusBadRequest, "InvalidNetPolicyInputError")
	postExpect(t, router, portTooHigh, http.StatusBadRequest, "InvalidNetPolicyInputError")

	// Only the two seeded records remain: the 503 request and every 400 request
	// left no rows behind.
	wantOnlyOriginals := []map[string]any{deny, allow}
	if items := listItems(t, router, "/v1/net-policies?namespace=payments"); !reflect.DeepEqual(items, wantOnlyOriginals) {
		t.Fatalf("items after recovery = %v, want originals %v", items, wantOnlyOriginals)
	}

	// The request that failed with 503 now commits with the unconsumed order 3;
	// a further new identity continues at order 4.
	recovered := registerCreated(t, router, blockedBody, 3, false)
	nextBody := singleRuleBody("payments", "after-outage", "tier=backend",
		"egress", "allow", 8053, 8053, `{}`)
	registerCreated(t, router, nextBody, 4, false)

	if items := listItems(t, router, "/v1/net-policies?namespace=payments"); len(items) != 4 {
		t.Fatalf("items = %d, want 4 (%v is the recovered order-3 record)", len(items), recovered["name"])
	}
}
