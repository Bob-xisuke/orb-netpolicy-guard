package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// escMode is the JSON escape spelling of the member name "mode" (backslash,
// "u006d", "ode"): the server's JSON decoder unescapes it, so it collides with
// the plain spelling. Built from the rune code so the source keeps the literal
// escape sequence.
var escMode = string(rune(0x5C)) + "u006dode"

// A non-string member value rejects the whole registration even when a later
// (or earlier) occurrence of the same member name holds a legal string: every
// occurrence is validated, not just the final decoded value.
func TestPostNetPolicyDuplicateMemberHidingInvalidValue(t *testing.T) {
	cases := map[string]string{
		"null then string adjacent":      `{"mode": null, "mode": "enforce"}`,
		"null then string separated":     `{"mode": null, "zone": "north", "mode": "enforce"}`,
		"number then string":             `{"mode": 1, "mode": "enforce"}`,
		"boolean then string":            `{"mode": true, "mode": "enforce"}`,
		"array then string":              `{"mode": ["enforce"], "mode": "enforce"}`,
		"object then string":             `{"mode": {"x": 1}, "mode": "enforce"}`,
		"string then null adjacent":      `{"mode": "enforce", "mode": null}`,
		"string then null separated":     `{"mode": "enforce", "zone": "north", "mode": null}`,
		"null on other repeated member":  `{"zone": "north", "mode": "enforce", "zone": null}`,
		"escaped duplicate null first":   `{` + `"` + escMode + `": null, "mode": "enforce"}`,
		"escaped duplicate null last":    `{"mode": "enforce", ` + `"` + escMode + `": null}`,
		"escaped duplicate number first": `{` + `"` + escMode + `": 7, "mode": "enforce"}`,
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			router, st := newTestRouter(t)
			recorder := doRequest(router, http.MethodPost, "/v1/net-policies",
				policyBody("payments", "default-deny", "tier=backend", params))
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
			}
			assertErrorCode(t, recorder, "InvalidNetPolicyInputError")
			assertSafeErrorMessage(t, recorder)
			assertSingleErrorObject(t, recorder)

			records, err := st.List("payments", "")
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if len(records) != 0 {
				t.Fatalf("invalid input left records behind: %+v", records)
			}
		})
	}
}

// When every occurrence of a repeated member is a legal string, registration
// succeeds and the last occurrence wins — including across escape-encoded
// spellings of the same name. The response and later queries show only the
// final key/value object.
func TestPostNetPolicyDuplicateMemberAllStringsLastWins(t *testing.T) {
	router, _ := newTestRouter(t)
	params := `{"mode": "audit", "zone": "north", "mode": "enforce", ` + `"` + escMode + `": "strict"}`
	created := doRequest(router, http.MethodPost, "/v1/net-policies",
		policyBody("payments", "default-deny", "tier=backend", params))
	if created.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", created.Code, http.StatusCreated, created.Body.String())
	}
	wantParams := map[string]any{"mode": "strict", "zone": "north"}
	var resp map[string]any
	if err := json.Unmarshal(created.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !reflect.DeepEqual(resp["pluginParams"], wantParams) {
		t.Fatalf("response pluginParams = %v, want %v", resp["pluginParams"], wantParams)
	}

	items := listItems(t, router, "/v1/net-policies?namespace=payments")
	if len(items) != 1 || !reflect.DeepEqual(items[0]["pluginParams"], wantParams) {
		t.Fatalf("listed pluginParams = %v, want %v", items, wantParams)
	}

	// Idempotent retry with the same final content returns the original record.
	retry := doRequest(router, http.MethodPost, "/v1/net-policies",
		policyBody("payments", "default-deny", "tier=backend", `{"zone": "north", "mode": "strict"}`))
	if retry.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want %d: %s", retry.Code, http.StatusOK, retry.Body.String())
	}

	// A different final content is still a conflict.
	changed := doRequest(router, http.MethodPost, "/v1/net-policies",
		policyBody("payments", "default-deny", "tier=backend", `{"mode": "audit", "mode": "audit", "zone": "south"}`))
	if changed.Code != http.StatusConflict {
		t.Fatalf("changed status = %d, want %d: %s", changed.Code, http.StatusConflict, changed.Body.String())
	}
	assertErrorCode(t, changed, "NetPolicyConflictError")
}

// A rejected duplicate-member request on a fresh identity writes nothing and
// consumes no order: both queries stay 404 and the next valid registration
// takes the order the rejected one would have had.
func TestPostNetPolicyDuplicateInvalidRejectedBeforeAnyWrite(t *testing.T) {
	router, _ := newTestRouter(t)
	bad := policyBody("payments", "default-deny", "tier=backend", `{"mode": null, "mode": "enforce"}`)

	recorder := doRequest(router, http.MethodPost, "/v1/net-policies", bad)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	assertErrorCode(t, recorder, "InvalidNetPolicyInputError")

	for _, target := range []string{
		"/v1/net-policies?namespace=payments",
		"/v1/net-policies?label=tier%3Dbackend",
	} {
		miss := doRequest(router, http.MethodGet, target, "")
		if miss.Code != http.StatusNotFound {
			t.Fatalf("GET %s after reject status = %d, want %d", target, miss.Code, http.StatusNotFound)
		}
		assertErrorCode(t, miss, "NetPolicyNotFoundError")
	}

	good := policyBody("payments", "default-deny", "tier=backend", `{"mode": "enforce"}`)
	created := doRequest(router, http.MethodPost, "/v1/net-policies", good)
	if created.Code != http.StatusCreated {
		t.Fatalf("valid status = %d, want %d: %s", created.Code, http.StatusCreated, created.Body.String())
	}
	var stored map[string]any
	if err := json.Unmarshal(created.Body.Bytes(), &stored); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if stored["order"] != float64(1) {
		t.Fatalf("order = %v, want 1 (rejected request must not consume an order)", stored["order"])
	}
}

// On an existing identity a duplicate member hiding a non-string value is a
// 400 — never a 200 retry or a 409 conflict — whether the final string equals
// the stored value or differs from it. The committed record, its order and its
// conflict flag stay untouched, and the next new identity keeps its sequence.
func TestPostNetPolicyDuplicateInvalidOnExistingIdentity(t *testing.T) {
	cases := []struct {
		name        string
		retryParams string
	}{
		{"final string equals stored", `{"mode": null, "mode": "enforce"}`},
		{"final string differs from stored", `{"mode": null, "mode": "audit"}`},
		{"invalid after legal duplicate", `{"mode": "enforce", "mode": null}`},
		{"escaped duplicate hides null", `{"mode": "enforce", ` + `"` + escMode + `": null}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			seed := doRequest(router, http.MethodPost, "/v1/net-policies",
				policyBody("payments", "default-deny", "tier=backend", `{"mode": "enforce"}`))
			if seed.Code != http.StatusCreated {
				t.Fatalf("seed status = %d: %s", seed.Code, seed.Body.String())
			}
			var seedRecord map[string]any
			if err := json.Unmarshal(seed.Body.Bytes(), &seedRecord); err != nil {
				t.Fatalf("decode seed: %v", err)
			}

			retry := doRequest(router, http.MethodPost, "/v1/net-policies",
				policyBody("payments", "default-deny", "tier=backend", tc.retryParams))
			if retry.Code != http.StatusBadRequest {
				t.Fatalf("retry status = %d, want %d (never 200 or 409): %s",
					retry.Code, http.StatusBadRequest, retry.Body.String())
			}
			assertErrorCode(t, retry, "InvalidNetPolicyInputError")
			assertSafeErrorMessage(t, retry)

			items := listItems(t, router, "/v1/net-policies?namespace=payments")
			if len(items) != 1 {
				t.Fatalf("items = %v, want the single original record", items)
			}
			if !reflect.DeepEqual(items[0], seedRecord) {
				t.Fatalf("record changed after rejected retry:\n got %v\nwant %v", items[0], seedRecord)
			}

			next := doRequest(router, http.MethodPost, "/v1/net-policies",
				policyBody("payments", "after-reject", "tier=backend", `{}`))
			if next.Code != http.StatusCreated {
				t.Fatalf("next status = %d: %s", next.Code, next.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(next.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode next: %v", err)
			}
			if body["order"] != float64(2) {
				t.Fatalf("order after reject = %v, want 2 (rejection must not consume an order)", body["order"])
			}
		})
	}
}

// assertSingleErrorObject checks the published error shape: exactly one
// top-level "error" object holding string code and message fields.
func assertSingleErrorObject(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	var body map[string]json.RawMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if len(body) != 1 {
		t.Fatalf("error body keys = %v, want only \"error\" (body %s)", keysOf(body), recorder.Body.String())
	}
	var errObj map[string]string
	if err := json.Unmarshal(body["error"], &errObj); err != nil {
		t.Fatalf("error is not an object of strings: %v (body %s)", err, recorder.Body.String())
	}
	if errObj["code"] == "" || errObj["message"] == "" {
		t.Fatalf("error object = %v, want non-empty code and message", errObj)
	}
}

func keysOf(body map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(body))
	for key := range body {
		keys = append(keys, key)
	}
	return keys
}
