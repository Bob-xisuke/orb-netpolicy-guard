package api

// Regression tests for storage write failures during registration. Two real
// fault modes are injected at the SQLite layer through test-only store hooks:
//
//   - writes rejected while reads stay usable (a BEFORE INSERT trigger raises
//     on every new row), exercising the 503 response, transactional atomicity,
//     idempotent retries and recovery;
//   - the whole database handle torn down, exercising 503 precedence for
//     health and valid registrations while invalid input still fails first
//     with 400, and recovery proving no record or order was consumed.
//
// Every case drives only the public HTTP surface (POST /v1/net-policies,
// GET /v1/net-policies, GET /healthz), uses its own database file, and closes
// everything it opens.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/Bob-xisuke/orb-netpolicy-guard/internal/store"
)

// newFaultService opens a fresh database and returns its router, store handle
// and file path so a test can reopen the very same database afterwards.
func newFaultService(t *testing.T) (*gin.Engine, *store.Store, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "service.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return NewRouter(st), st, dbPath
}

// decodeRecordBytes decodes a single record carried in a response body.
func decodeRecordBytes(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatalf("decode record: %v", err)
	}
	return record
}

// assertCreatedRecord validates an already-captured 201 response carries the
// request's full submitted content plus the expected order and conflict flag,
// and returns the decoded record.
func assertCreatedRecord(t *testing.T, recorder *httptest.ResponseRecorder, body string, order int64, conflict bool) map[string]any {
	t.Helper()
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", recorder.Code, recorder.Body.String())
	}
	resp := decodeRecordBytes(t, recorder.Body.Bytes())
	want := wantRecord(t, body, order, conflict)
	if !reflect.DeepEqual(resp, want) {
		t.Fatalf("record = %v, want %v", resp, want)
	}
	return resp
}

// While the store refuses new rows it can still serve reads: a rejected
// registration answers 503/storage_unavailable without leaving anything
// behind, same-content retries of committed identities still answer 200 with
// the original record, and changed content still answers 409 before any insert
// is attempted. After the fault clears the exact failed request commits with
// the next order and no conflict; retrying it is idempotent. Close/reopen
// keeps all records and the global order intact.
func TestRegisterStorageWriteFailureAtomicityAndRecovery(t *testing.T) {
	router, st, dbPath := newFaultService(t)

	// Two committed records in the same namespace and label: deny [80,100]
	// first (order 1, no conflict), then allow [100,200] touching the closed
	// interval at endpoint 100 (order 2, conflict).
	denyBody := singleRuleBody("payments", "deny-web", "tier=backend",
		"ingress", "deny", 80, 100, `{"mode": "enforce"}`)
	deny := registerCreated(t, router, denyBody, 1, false)
	allowBody := singleRuleBody("payments", "allow-web", "tier=backend",
		"ingress", "allow", 100, 200, `{"mode": "enforce"}`)
	allow := registerCreated(t, router, allowBody, 2, true)

	// Storage keeps serving reads but rejects every new row.
	st.SetWritesFailForTesting(t, true)

	// A brand-new identity (egress, so it would not clash even once persisted)
	// must fail with 503 and the published storage error.
	egressBody := singleRuleBody("payments", "allow-dns", "tier=backend",
		"egress", "allow", 53, 53, `{"mode": "enforce"}`)
	failed := doRequest(router, http.MethodPost, "/v1/net-policies", egressBody)
	if failed.Code != http.StatusServiceUnavailable {
		t.Fatalf("failing write status = %d, want %d: %s",
			failed.Code, http.StatusServiceUnavailable, failed.Body.String())
	}
	assertExactErrorShape(t, failed, "storage_unavailable")
	assertSafeErrorMessage(t, failed)

	// Every query filter still answers 200 with exactly the two original
	// records, submitted fields, ordering and conflict flags unchanged.
	wantOriginal := []map[string]any{deny, allow}
	for _, target := range []string{
		"/v1/net-policies?namespace=payments",
		"/v1/net-policies?label=tier%3Dbackend",
		"/v1/net-policies?namespace=payments&label=tier%3Dbackend",
	} {
		if items := listItems(t, router, target); !reflect.DeepEqual(items, wantOriginal) {
			t.Fatalf("GET %s items during write failure = %v, want unchanged %v",
				target, items, wantOriginal)
		}
	}

	// Same identity with the same content still returns 200 with the original
	// record: the lookup path needs no write and keeps working.
	for name, body := range map[string]string{
		"deny-web":  denyBody,
		"allow-web": allowBody,
	} {
		retry := doRequest(router, http.MethodPost, "/v1/net-policies", body)
		if retry.Code != http.StatusOK {
			t.Fatalf("retry %s during write failure status = %d, want 200: %s",
				name, retry.Code, retry.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(retry.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode retry %s: %v", name, err)
		}
		var want map[string]any
		if name == "deny-web" {
			want = deny
		} else {
			want = allow
		}
		if !reflect.DeepEqual(resp, want) {
			t.Fatalf("retry %s record = %v, want the original %v", name, resp, want)
		}
	}

	// Same identity with different content is still a 409 content conflict —
	// detected on the read path before the rejected insert is reached.
	changed := singleRuleBody("payments", "deny-web", "tier=backend",
		"ingress", "deny", 80, 100, `{"mode": "audit"}`)
	conflict := doRequest(router, http.MethodPost, "/v1/net-policies", changed)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("changed content during write failure status = %d, want 409: %s",
			conflict.Code, conflict.Body.String())
	}
	assertExactErrorShape(t, conflict, "NetPolicyConflictError")
	assertSafeErrorMessage(t, conflict)

	// Nothing changed while writes were failing.
	if items := listItems(t, router, "/v1/net-policies?namespace=payments"); !reflect.DeepEqual(items, wantOriginal) {
		t.Fatalf("items after retries during write failure = %v, want unchanged %v", items, wantOriginal)
	}

	// Clear the fault and replay the exact failed request: it now commits with
	// order 3 and conflict=false.
	st.SetWritesFailForTesting(t, false)
	recovered := doRequest(router, http.MethodPost, "/v1/net-policies", egressBody)
	if recovered.Code != http.StatusCreated {
		t.Fatalf("recovered write status = %d, want 201: %s",
			recovered.Code, recovered.Body.String())
	}
	egress := assertCreatedRecord(t, recovered, egressBody, 3, false)

	// Submitting it again is idempotent: 200 with the same record, no new order.
	again := doRequest(router, http.MethodPost, "/v1/net-policies", egressBody)
	if again.Code != http.StatusOK {
		t.Fatalf("repeat after recovery status = %d, want 200: %s",
			again.Code, again.Body.String())
	}
	if resp := decodeRecordBytes(t, again.Body.Bytes()); !reflect.DeepEqual(resp, egress) {
		t.Fatalf("repeat record = %v, want the same record %v", resp, egress)
	}

	// Close the service's handle and reopen the same database file through a
	// fresh connection: all three records survive with every submitted field,
	// order and conflict flag intact.
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	reopened, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { reopened.Close() })
	router = NewRouter(reopened)

	wantAll := []map[string]any{deny, allow, egress}
	if items := listItems(t, router, "/v1/net-policies?namespace=payments"); !reflect.DeepEqual(items, wantAll) {
		t.Fatalf("items after reopen = %v, want all three records %v", items, wantAll)
	}

	// The failed-and-recovered registration consumed exactly one order: the
	// next legal new identity (egress, disjoint ports, no clash) takes order 4.
	nextBody := singleRuleBody("payments", "after-recovery", "tier=backend",
		"egress", "deny", 7000, 7000, `{}`)
	registerCreated(t, router, nextBody, 4, false)
}

// With the whole database unavailable a valid registration and the health
// check answer 503/storage_unavailable, while malformed input still fails
// validation first with 400/InvalidNetPolicyInputError. Once storage returns,
// the rejected valid request commits at order 1 — neither the outage nor the
// invalid requests wrote a record or consumed an order.
func TestRegisterAndHealthzStorageFullyUnavailable(t *testing.T) {
	router, st, _ := newFaultService(t)

	validBody := singleRuleBody("payments", "allow-dns", "tier=backend",
		"egress", "allow", 53, 53, `{"mode": "enforce"}`)
	badDirectionBody := singleRuleBody("bad-dir-ns", "sideways-policy", "tier=backend",
		"sideways", "allow", 80, 80, `{}`)
	portBelowBody := singleRuleBody("bad-port-below-ns", "low-port", "tier=backend",
		"ingress", "allow", 0, 80, `{}`)
	portAboveBody := singleRuleBody("bad-port-above-ns", "high-port", "tier=backend",
		"ingress", "allow", 1, 65536, `{}`)

	// Take the database fully down: handle closed, reads and writes fail.
	st.SetStorageDownForTesting(t, true)

	health := doRequest(router, http.MethodGet, "/healthz", "")
	if health.Code != http.StatusServiceUnavailable {
		t.Fatalf("healthz down status = %d, want 503: %s", health.Code, health.Body.String())
	}
	assertExactErrorShape(t, health, "storage_unavailable")
	assertSafeErrorMessage(t, health)

	valid := doRequest(router, http.MethodPost, "/v1/net-policies", validBody)
	if valid.Code != http.StatusServiceUnavailable {
		t.Fatalf("valid POST while down status = %d, want 503: %s",
			valid.Code, valid.Body.String())
	}
	assertExactErrorShape(t, valid, "storage_unavailable")
	assertSafeErrorMessage(t, valid)

	// Input validation runs before any storage access: invalid requests never
	// degrade to 503 even while the database is fully unavailable.
	for name, body := range map[string]string{
		"bad direction":  badDirectionBody,
		"port below 1":   portBelowBody,
		"port above max": portAboveBody,
	} {
		rejected := doRequest(router, http.MethodPost, "/v1/net-policies", body)
		if rejected.Code != http.StatusBadRequest {
			t.Fatalf("%s while down status = %d, want 400: %s",
				name, rejected.Code, rejected.Body.String())
		}
		assertExactErrorShape(t, rejected, "InvalidNetPolicyInputError")
		assertSafeErrorMessage(t, rejected)
	}

	// Bring storage back: health recovers and committed state is queryable.
	st.SetStorageDownForTesting(t, false)
	health = doRequest(router, http.MethodGet, "/healthz", "")
	if health.Code != http.StatusOK {
		t.Fatalf("healthz recovered status = %d, want 200: %s", health.Code, health.Body.String())
	}

	// The invalid requests left no records behind.
	for _, ns := range []string{"bad-dir-ns", "bad-port-below-ns", "bad-port-above-ns"} {
		miss := doRequest(router, http.MethodGet, "/v1/net-policies?namespace="+ns, "")
		if miss.Code != http.StatusNotFound {
			t.Fatalf("namespace %s after recovery status = %d, want 404: %s",
				ns, miss.Code, miss.Body.String())
		}
		assertExactErrorShape(t, miss, "NetPolicyNotFoundError")
	}

	// The request that 503'd during the outage wrote nothing and consumed no
	// order: replaying it now creates the very first record with order 1.
	created := doRequest(router, http.MethodPost, "/v1/net-policies", validBody)
	if created.Code != http.StatusCreated {
		t.Fatalf("valid POST after recovery status = %d, want 201: %s",
			created.Code, created.Body.String())
	}
	record := assertCreatedRecord(t, created, validBody, 1, false)

	if items := listItems(t, router, "/v1/net-policies?namespace=payments"); len(items) != 1 ||
		!reflect.DeepEqual(items[0], record) {
		t.Fatalf("items after recovery = %v, want exactly %v", items, record)
	}
}
