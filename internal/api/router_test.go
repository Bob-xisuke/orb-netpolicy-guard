package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/Bob-xisuke/orb-netpolicy-guard/internal/store"
)

func newTestRouter(t *testing.T) (*gin.Engine, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return NewRouter(st), st
}

func doRequest(router http.Handler, method, target, body string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, target, reader)
	router.ServeHTTP(recorder, request)
	return recorder
}

const validPolicy = `{
	"namespace": "payments",
	"name": "default-deny",
	"label": "tier=backend",
	"rules": [{"direction": "ingress", "action": "deny", "ports": [1, 65535]}],
	"pluginParams": {"mode": "enforce"}
}`

func TestHealthzReportsOK(t *testing.T) {
	router, _ := newTestRouter(t)
	recorder := doRequest(router, http.MethodGet, "/healthz", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got := recorder.Body.String(); got != `{"database":"ok","status":"ok"}` {
		t.Fatalf("body = %s", got)
	}
}

func TestUnknownRouteUsesPublishedErrorShape(t *testing.T) {
	router, _ := newTestRouter(t)
	recorder := doRequest(router, http.MethodGet, "/missing", "")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
	var body map[string]map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"]["code"] == "" || body["error"]["message"] == "" {
		t.Fatalf("body = %s, want error.code and error.message", recorder.Body.String())
	}
}

func TestPostNetPolicyCreated(t *testing.T) {
	router, _ := newTestRouter(t)
	recorder := doRequest(router, http.MethodPost, "/v1/net-policies", validPolicy)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["namespace"] != "payments" || body["name"] != "default-deny" || body["label"] != "tier=backend" {
		t.Fatalf("identity fields = %v", body)
	}
	if body["order"] != float64(1) {
		t.Fatalf("order = %v, want 1", body["order"])
	}
	if body["conflict"] != false {
		t.Fatalf("conflict = %v, want false", body["conflict"])
	}
	if _, ok := body["rules"].([]any); !ok {
		t.Fatalf("rules missing from response: %v", body)
	}
	if _, ok := body["pluginParams"].(map[string]any); !ok {
		t.Fatalf("pluginParams missing from response: %v", body)
	}
}

func TestPostNetPolicyIncrementsOrder(t *testing.T) {
	router, _ := newTestRouter(t)
	doRequest(router, http.MethodPost, "/v1/net-policies", validPolicy)
	second := strings.Replace(validPolicy, `"default-deny"`, `"allow-dns"`, 1)
	recorder := doRequest(router, http.MethodPost, "/v1/net-policies", second)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var body map[string]any
	json.Unmarshal(recorder.Body.Bytes(), &body)
	if body["order"] != float64(2) {
		t.Fatalf("order = %v, want 2", body["order"])
	}
}

func TestPostNetPolicyRetryReturnsOriginal(t *testing.T) {
	router, _ := newTestRouter(t)
	doRequest(router, http.MethodPost, "/v1/net-policies", validPolicy)

	// Same content with keys in a different order: object key order is irrelevant.
	reordered := `{
		"pluginParams": {"mode": "enforce"},
		"rules": [{"ports": [1, 65535], "action": "deny", "direction": "ingress"}],
		"label": "tier=backend",
		"name": "default-deny",
		"namespace": "payments"
	}`
	recorder := doRequest(router, http.MethodPost, "/v1/net-policies", reordered)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var body map[string]any
	json.Unmarshal(recorder.Body.Bytes(), &body)
	if body["order"] != float64(1) {
		t.Fatalf("order = %v, want original order 1", body["order"])
	}

	// The retry must not consume an order value.
	other := strings.Replace(validPolicy, `"default-deny"`, `"next"`, 1)
	recorder = doRequest(router, http.MethodPost, "/v1/net-policies", other)
	var next map[string]any
	json.Unmarshal(recorder.Body.Bytes(), &next)
	if next["order"] != float64(2) {
		t.Fatalf("order after retry = %v, want 2", next["order"])
	}
}

func TestPostNetPolicyRuleOrderIsSignificant(t *testing.T) {
	router, _ := newTestRouter(t)
	first := `{
		"namespace": "payments", "name": "ordered", "label": "tier=backend",
		"rules": [
			{"direction": "ingress", "action": "deny", "ports": [1, 100]},
			{"direction": "egress", "action": "allow", "ports": [53, 53]}
		],
		"pluginParams": {}
	}`
	if rec := doRequest(router, http.MethodPost, "/v1/net-policies", first); rec.Code != http.StatusCreated {
		t.Fatalf("seed status = %d: %s", rec.Code, rec.Body.String())
	}
	swapped := `{
		"namespace": "payments", "name": "ordered", "label": "tier=backend",
		"rules": [
			{"direction": "egress", "action": "allow", "ports": [53, 53]},
			{"direction": "ingress", "action": "deny", "ports": [1, 100]}
		],
		"pluginParams": {}
	}`
	recorder := doRequest(router, http.MethodPost, "/v1/net-policies", swapped)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d (rule order matters)", recorder.Code, http.StatusConflict)
	}
}

func TestPostNetPolicyConflict(t *testing.T) {
	router, _ := newTestRouter(t)
	doRequest(router, http.MethodPost, "/v1/net-policies", validPolicy)
	changed := strings.Replace(validPolicy, `"mode": "enforce"`, `"mode": "audit"`, 1)
	recorder := doRequest(router, http.MethodPost, "/v1/net-policies", changed)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusConflict)
	}
	assertErrorCode(t, recorder, "NetPolicyConflictError")
}

func TestPostNetPolicyFlagsRuleConflict(t *testing.T) {
	router, _ := newTestRouter(t)
	doRequest(router, http.MethodPost, "/v1/net-policies", validPolicy)
	clashing := `{
		"namespace": "payments", "name": "allow-web", "label": "tier=backend",
		"rules": [{"direction": "ingress", "action": "allow", "ports": [80, 443]}],
		"pluginParams": {}
	}`
	recorder := doRequest(router, http.MethodPost, "/v1/net-policies", clashing)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var body map[string]any
	json.Unmarshal(recorder.Body.Bytes(), &body)
	if body["conflict"] != true {
		t.Fatalf("conflict = %v, want true", body["conflict"])
	}
}

func TestPostNetPolicyRejectsInvalidInput(t *testing.T) {
	cases := map[string]string{
		"empty body":              ``,
		"malformed json":          `{"namespace":`,
		"multiple json values":    validPolicy + ` {}`,
		"trailing garbage":        validPolicy + ` oops`,
		"top level array":         `[]`,
		"missing namespace":       `{"name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[1,2]}],"pluginParams":{}}`,
		"missing rules":           `{"namespace":"n","name":"a","label":"l","pluginParams":{}}`,
		"missing pluginParams":    `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[1,2]}]}`,
		"blank namespace":         `{"namespace":"  ","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[1,2]}],"pluginParams":{}}`,
		"blank label":             `{"namespace":"n","name":"a","label":" ","rules":[{"direction":"ingress","action":"allow","ports":[1,2]}],"pluginParams":{}}`,
		"non-string name":         `{"namespace":"n","name":7,"label":"l","rules":[{"direction":"ingress","action":"allow","ports":[1,2]}],"pluginParams":{}}`,
		"empty rules":             `{"namespace":"n","name":"a","label":"l","rules":[],"pluginParams":{}}`,
		"bad direction enum":      `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"sideways","action":"allow","ports":[1,2]}],"pluginParams":{}}`,
		"bad action enum":         `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"permit","ports":[1,2]}],"pluginParams":{}}`,
		"missing ports":           `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow"}],"pluginParams":{}}`,
		"single port":             `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[80]}],"pluginParams":{}}`,
		"three ports":             `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[1,2,3]}],"pluginParams":{}}`,
		"port below range":        `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[0,80]}],"pluginParams":{}}`,
		"port above range":        `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[1,65536]}],"pluginParams":{}}`,
		"reversed ports":          `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[443,80]}],"pluginParams":{}}`,
		"fractional port":         `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[1.5,80]}],"pluginParams":{}}`,
		"non-string pluginParams": `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[1,2]}],"pluginParams":{"mode":1}}`,
		"boolean pluginParam":     `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[1,2]}],"pluginParams":{"mode":true}}`,
		"array pluginParam":       `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[1,2]}],"pluginParams":{"mode":["enforce"]}}`,
		"object pluginParam":      `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[1,2]}],"pluginParams":{"mode":{"x":1}}}`,
		"null pluginParams":       `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[1,2]}],"pluginParams":null}`,
		"null pluginParam member": `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[1,2]}],"pluginParams":{"mode":null}}`,
		"mixed null pluginParam":  `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[1,2]}],"pluginParams":{"mode":"enforce","retries":null}}`,
		"null rules":              `{"namespace":"n","name":"a","label":"l","rules":null,"pluginParams":{}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			router, st := newTestRouter(t)
			recorder := doRequest(router, http.MethodPost, "/v1/net-policies", body)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
			}
			assertErrorCode(t, recorder, "InvalidNetPolicyInputError")
			records, err := st.List("n", "")
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if len(records) != 0 {
				t.Fatalf("invalid input left records behind: %+v", records)
			}
		})
	}
}

func TestGetNetPoliciesRequiresCondition(t *testing.T) {
	router, _ := newTestRouter(t)
	for _, target := range []string{
		"/v1/net-policies",
		"/v1/net-policies?namespace=",
		"/v1/net-policies?namespace=%20%20",
		"/v1/net-policies?label=",
		"/v1/net-policies?namespace=a&namespace=b",
		"/v1/net-policies?label=x&label=y",
	} {
		recorder := doRequest(router, http.MethodGet, target, "")
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("GET %s: status = %d, want %d", target, recorder.Code, http.StatusBadRequest)
		}
		assertErrorCode(t, recorder, "InvalidNetPolicyInputError")
	}
}

func TestGetNetPoliciesNotFound(t *testing.T) {
	router, _ := newTestRouter(t)
	recorder := doRequest(router, http.MethodGet, "/v1/net-policies?namespace=missing", "")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
	assertErrorCode(t, recorder, "NetPolicyNotFoundError")
}

func TestGetNetPoliciesReturnsItemsSorted(t *testing.T) {
	router, _ := newTestRouter(t)
	doRequest(router, http.MethodPost, "/v1/net-policies", validPolicy)
	second := strings.Replace(validPolicy, `"default-deny"`, `"allow-dns"`, 1)
	doRequest(router, http.MethodPost, "/v1/net-policies", second)
	otherNs := strings.Replace(validPolicy, `"payments"`, `"staging"`, 1)
	otherNs = strings.Replace(otherNs, `"default-deny"`, `"other"`, 1)
	doRequest(router, http.MethodPost, "/v1/net-policies", otherNs)

	recorder := doRequest(router, http.MethodGet, "/v1/net-policies?namespace=payments", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Items) != 2 {
		t.Fatalf("items = %v, want 2 entries", body.Items)
	}
	if body.Items[0]["order"] != float64(1) || body.Items[1]["order"] != float64(2) {
		t.Fatalf("items not sorted by order: %v", body.Items)
	}

	// Intersection of namespace and label.
	recorder = doRequest(router, http.MethodGet, "/v1/net-policies?namespace=payments&label=tier%3Dbackend", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("intersection status = %d", recorder.Code)
	}
	json.Unmarshal(recorder.Body.Bytes(), &body)
	if len(body.Items) != 2 {
		t.Fatalf("intersection items = %v, want 2 entries", body.Items)
	}

	// Label-only query crosses namespaces.
	recorder = doRequest(router, http.MethodGet, "/v1/net-policies?label=tier%3Dbackend", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("label status = %d", recorder.Code)
	}
	json.Unmarshal(recorder.Body.Bytes(), &body)
	if len(body.Items) != 3 {
		t.Fatalf("label items = %v, want 3 entries", body.Items)
	}
}

// policyBody builds a registration body for identity (ns/name/label) with the
// given raw pluginParams JSON object.
func policyBody(ns, name, label, paramsJSON string) string {
	return fmt.Sprintf(`{
		"namespace": %q,
		"name": %q,
		"label": %q,
		"rules": [{"direction": "ingress", "action": "allow", "ports": [80, 80]}],
		"pluginParams": %s
	}`, ns, name, label, paramsJSON)
}

func listItems(t *testing.T, router *gin.Engine, target string) []map[string]any {
	t.Helper()
	recorder := doRequest(router, http.MethodGet, target, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d: %s", target, recorder.Code, recorder.Body.String())
	}
	var body struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode items: %v", err)
	}
	return body.Items
}

// assertSafeErrorMessage checks the published error message carries no SQL,
// stack trace or file path.
func assertSafeErrorMessage(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	var body map[string]map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	msg := strings.ToLower(body["error"]["message"])
	if msg == "" {
		t.Fatalf("error.message is empty (body %s)", recorder.Body.String())
	}
	for _, leak := range []string{"sql", "sqlite", "goroutine", ".go:", "panic", "/", "\\"} {
		if strings.Contains(msg, leak) {
			t.Fatalf("error.message leaks %q: %s", leak, body["error"]["message"])
		}
	}
}

// A null member on a brand-new identity must be rejected without writing a row:
// both the namespace and the label queries stay 404 and the later valid
// registration still takes order 1, i.e. the rejection must not consume an order.
func TestPostNetPolicyNullMemberRejectedBeforeAnyWrite(t *testing.T) {
	router, _ := newTestRouter(t)
	bad := policyBody("payments", "default-deny", "tier=backend", `{"mode": null}`)

	recorder := doRequest(router, http.MethodPost, "/v1/net-policies", bad)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	assertErrorCode(t, recorder, "InvalidNetPolicyInputError")
	assertSafeErrorMessage(t, recorder)

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

// Re-posting an existing identity with a null member is invalid input whether
// the stored value is an empty string or a non-empty string, and regardless of
// which member is null. It must surface the same 400 (never 200 or 409) and must
// leave the committed record, its order and its conflict flag untouched.
func TestPostNetPolicyNullMemberOnExistingIdentity(t *testing.T) {
	cases := []struct {
		name        string
		seedParams  string
		retryParams string
	}{
		{
			name:        "stored empty string retried as null",
			seedParams:  `{"mode": ""}`,
			retryParams: `{"mode": null}`,
		},
		{
			name:        "stored non-empty string retried as null",
			seedParams:  `{"mode": "enforce"}`,
			retryParams: `{"mode": null}`,
		},
		{
			name:        "second member null alongside legal string",
			seedParams:  `{"mode": "enforce", "retries": "3"}`,
			retryParams: `{"mode": "enforce", "retries": null}`,
		},
		{
			name:        "first member null alongside legal string",
			seedParams:  `{"mode": "enforce", "retries": "3"}`,
			retryParams: `{"retries": "3", "mode": null}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			seed := doRequest(router, http.MethodPost, "/v1/net-policies",
				policyBody("payments", "default-deny", "tier=backend", tc.seedParams))
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
			// The committed record must be untouched in every field.
			if !reflect.DeepEqual(items[0], seedRecord) {
				t.Fatalf("record changed after rejected retry:\n got %v\nwant %v", items[0], seedRecord)
			}
		})
	}
}

// Every legal string value is preserved verbatim, including the empty string,
// whitespace-only strings, non-ASCII text and the literal string "null".
func TestPostNetPolicyPreservesLegalPluginParamValues(t *testing.T) {
	cases := []struct {
		name       string
		identity   string
		paramsJSON string
		want       map[string]any
	}{
		{"empty object", "empty-obj", `{}`, map[string]any{}},
		{"empty string value", "empty-val", `{"mode": ""}`, map[string]any{"mode": ""}},
		{"whitespace value", "space-val", `{"mode": " \t "}`, map[string]any{"mode": " \t "}},
		{"chinese value", "cn-val", `{"mode": "拦截"}`, map[string]any{"mode": "拦截"}},
		{"literal null string", "literal-null", `{"mode": "null"}`, map[string]any{"mode": "null"}},
		{"mixed empty and non-empty", "mixed", `{"a": "", "b": "enforce"}`, map[string]any{"a": "", "b": "enforce"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			body := policyBody("payments", tc.identity, "tier=backend", tc.paramsJSON)
			created := doRequest(router, http.MethodPost, "/v1/net-policies", body)
			if created.Code != http.StatusCreated {
				t.Fatalf("status = %d, want %d: %s", created.Code, http.StatusCreated, created.Body.String())
			}
			var resp map[string]any
			if err := json.Unmarshal(created.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !reflect.DeepEqual(resp["pluginParams"], tc.want) {
				t.Fatalf("registration pluginParams = %v, want %v", resp["pluginParams"], tc.want)
			}

			items := listItems(t, router, "/v1/net-policies?namespace=payments")
			if len(items) != 1 || !reflect.DeepEqual(items[0]["pluginParams"], tc.want) {
				t.Fatalf("stored pluginParams = %v, want %v", items, tc.want)
			}
		})
	}
}

// An idempotent retry containing empty/non-ASCII values returns 200 with the
// original record regardless of object key order, consumes no order, and the
// next brand-new identity keeps the expected sequence.
func TestPostNetPolicyIdempotentRetryWithSpecialValues(t *testing.T) {
	router, _ := newTestRouter(t)
	seed := policyBody("payments", "default-deny", "tier=backend", `{"zone": "华北", "mode": ""}`)
	if rec := doRequest(router, http.MethodPost, "/v1/net-policies", seed); rec.Code != http.StatusCreated {
		t.Fatalf("seed status = %d: %s", rec.Code, rec.Body.String())
	}

	reordered := policyBody("payments", "default-deny", "tier=backend", `{"mode": "", "zone": "华北"}`)
	retry := doRequest(router, http.MethodPost, "/v1/net-policies", reordered)
	if retry.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want %d: %s", retry.Code, http.StatusOK, retry.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(retry.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["order"] != float64(1) {
		t.Fatalf("retry order = %v, want original 1", body["order"])
	}
	wantParams := map[string]any{"mode": "", "zone": "华北"}
	if !reflect.DeepEqual(body["pluginParams"], wantParams) {
		t.Fatalf("retry pluginParams = %v, want %v", body["pluginParams"], wantParams)
	}

	next := doRequest(router, http.MethodPost, "/v1/net-policies",
		policyBody("payments", "after-retry", "tier=backend", `{}`))
	if next.Code != http.StatusCreated {
		t.Fatalf("next status = %d: %s", next.Code, next.Body.String())
	}
	json.Unmarshal(next.Body.Bytes(), &body)
	if body["order"] != float64(2) {
		t.Fatalf("order after retry = %v, want 2", body["order"])
	}
}

// A legal change of a previously empty string value is still a content conflict:
// 409 NetPolicyConflictError, with the original record left intact.
func TestPostNetPolicyLegalChangeStillConflicts(t *testing.T) {
	router, _ := newTestRouter(t)
	seed := doRequest(router, http.MethodPost, "/v1/net-policies",
		policyBody("payments", "default-deny", "tier=backend", `{"mode": ""}`))
	if seed.Code != http.StatusCreated {
		t.Fatalf("seed status = %d: %s", seed.Code, seed.Body.String())
	}

	changed := doRequest(router, http.MethodPost, "/v1/net-policies",
		policyBody("payments", "default-deny", "tier=backend", `{"mode": "enforce"}`))
	if changed.Code != http.StatusConflict {
		t.Fatalf("changed status = %d, want %d: %s", changed.Code, http.StatusConflict, changed.Body.String())
	}
	assertErrorCode(t, changed, "NetPolicyConflictError")

	items := listItems(t, router, "/v1/net-policies?namespace=payments")
	if len(items) != 1 {
		t.Fatalf("items = %v, want single original record", items)
	}
	if !reflect.DeepEqual(items[0]["pluginParams"], map[string]any{"mode": ""}) {
		t.Fatalf("pluginParams = %v, want unchanged {mode:''}", items[0]["pluginParams"])
	}
	if items[0]["order"] != float64(1) {
		t.Fatalf("order = %v, want unchanged 1", items[0]["order"])
	}
}

// A repeated member name must not let an illegal value hide behind a later
// string: every occurrence in pluginParams is validated, whether the illegal
// value lands before or after the legal one, adjacent to it or separated by
// another member, and whether the shared name is written literally or with a
// JSON escape ("mode" and "\u006dode" decode to the same key).
func TestPostNetPolicyRejectsIllegalValueHiddenByDuplicateMember(t *testing.T) {
	cases := map[string]string{
		"null before legal string, adjacent":       `{"mode": null, "mode": "enforce"}`,
		"null after legal string, adjacent":        `{"mode": "enforce", "mode": null}`,
		"null before legal string, separated":      `{"mode": null, "retries": "3", "mode": "enforce"}`,
		"null after legal string, separated":       `{"mode": "enforce", "retries": "3", "mode": null}`,
		"number hidden by later string":            `{"mode": 1, "mode": "enforce"}`,
		"boolean hidden by later string":           `{"mode": true, "mode": "enforce"}`,
		"array hidden by later string":             `{"mode": ["enforce"], "mode": "enforce"}`,
		"object hidden by later string":            `{"mode": {"x": 1}, "mode": "enforce"}`,
		"legal string hidden by later null":        `{"mode": "enforce", "mode": null}`,
		"escaped name null first, literal legal":   `{"\u006dode": null, "mode": "enforce"}`,
		"literal legal first, escaped name null":   `{"mode": "enforce", "\u006dode": null}`,
		"escaped name number, literal legal after": `{"\u006dode": 7, "mode": "enforce"}`,
		"two illegal occurrences around a legal":   `{"mode": false, "retries": "3", "mode": null}`,
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			bad := policyBody("payments", "default-deny", "tier=backend", params)

			recorder := doRequest(router, http.MethodPost, "/v1/net-policies", bad)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
			}
			assertErrorCode(t, recorder, "InvalidNetPolicyInputError")
			assertSafeErrorMessage(t, recorder)

			// A rejected new identity leaves no record behind.
			for _, target := range []string{
				"/v1/net-policies?namespace=payments",
				"/v1/net-policies?label=tier%3Dbackend",
			} {
				miss := doRequest(router, http.MethodGet, target, "")
				if miss.Code != http.StatusNotFound {
					t.Fatalf("GET %s status = %d, want %d", target, miss.Code, http.StatusNotFound)
				}
				assertErrorCode(t, miss, "NetPolicyNotFoundError")
			}

			// The rejected registration must not consume an order value.
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
		})
	}
}

// Posting a duplicate-name pluginParams against an existing identity is invalid
// input whenever any occurrence is non-string, even if the final value equals
// the stored one (never 200) or differs (never 409). The committed record, its
// order and its conflict flag stay untouched.
func TestPostNetPolicyDuplicateMemberIllegalOnExistingIdentity(t *testing.T) {
	cases := []struct {
		name        string
		retryParams string
	}{
		{"illegal hidden by value equal to stored", `{"mode": null, "mode": "enforce"}`},
		{"illegal hidden by value differing stored", `{"mode": null, "mode": "audit"}`},
		{"legal then illegal, final differs", `{"mode": "enforce", "retries": "3", "mode": null}`},
		{"escaped illegal occurrence", `{"mode": "enforce", "\u006dode": null}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			// A clashing rule first so the seed record carries conflict=true,
			// which the rejected retry must leave intact.
			clash := policyWithRules("payments", "clash", "tier=backend",
				`[{"direction":"ingress","action":"deny","ports":[80,80]}]`, `{}`)
			if rec := doRequest(router, http.MethodPost, "/v1/net-policies", clash); rec.Code != http.StatusCreated {
				t.Fatalf("clash seed status = %d: %s", rec.Code, rec.Body.String())
			}
			seed := doRequest(router, http.MethodPost, "/v1/net-policies",
				policyBody("payments", "default-deny", "tier=backend", `{"mode": "enforce"}`))
			if seed.Code != http.StatusCreated {
				t.Fatalf("seed status = %d: %s", seed.Code, seed.Body.String())
			}
			var seedRecord map[string]any
			if err := json.Unmarshal(seed.Body.Bytes(), &seedRecord); err != nil {
				t.Fatalf("decode seed: %v", err)
			}
			if seedRecord["conflict"] != true {
				t.Fatalf("seed conflict = %v, want true", seedRecord["conflict"])
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
			if len(items) != 2 {
				t.Fatalf("items = %v, want the two original records only", items)
			}
			var original map[string]any
			for _, item := range items {
				if item["name"] == "default-deny" {
					original = item
				}
			}
			if original == nil {
				t.Fatalf("seed record missing after rejected retry: %v", items)
			}
			if !reflect.DeepEqual(original, seedRecord) {
				t.Fatalf("record changed after rejected retry:\n got %v\nwant %v", original, seedRecord)
			}
		})
	}
}

// When every occurrence of a repeated member name is a string the request stays
// valid: the last occurrence after JSON key unescaping wins, and only the final
// key/value object is presented in the response and in queries. Special legal
// strings (empty, whitespace, Chinese, the literal "null") keep working when
// repeated.
func TestPostNetPolicyDuplicateMembersAllStringsLastWins(t *testing.T) {
	cases := []struct {
		name       string
		identity   string
		paramsJSON string
		want       map[string]any
	}{
		{"literal duplicate last wins", "dup-literal",
			`{"mode": "audit", "mode": "enforce"}`, map[string]any{"mode": "enforce"}},
		{"escaped duplicate last wins", "dup-escaped",
			`{"\u006dode": "audit", "mode": "enforce"}`, map[string]any{"mode": "enforce"}},
		{"escaped first then literal", "dup-escaped-first",
			`{"\u006dode": "enforce", "mode": "audit"}`, map[string]any{"mode": "audit"}},
		{"duplicates separated by other members", "dup-separated",
			`{"a": "1", "mode": "audit", "b": "2", "mode": "enforce"}`,
			map[string]any{"a": "1", "b": "2", "mode": "enforce"}},
		{"empty string then non-empty", "dup-empty-first",
			`{"mode": "", "mode": "enforce"}`, map[string]any{"mode": "enforce"}},
		{"non-empty then empty string", "dup-empty-last",
			`{"mode": "enforce", "mode": ""}`, map[string]any{"mode": ""}},
		{"whitespace, chinese and literal null repeated", "dup-special",
			`{"mode": "null", "\u006dode": " 拦截 "}`, map[string]any{"mode": " 拦截 "}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			body := policyBody("payments", tc.identity, "tier=backend", tc.paramsJSON)
			created := doRequest(router, http.MethodPost, "/v1/net-policies", body)
			if created.Code != http.StatusCreated {
				t.Fatalf("status = %d, want %d: %s", created.Code, http.StatusCreated, created.Body.String())
			}
			var resp map[string]any
			if err := json.Unmarshal(created.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !reflect.DeepEqual(resp["pluginParams"], tc.want) {
				t.Fatalf("response pluginParams = %v, want %v", resp["pluginParams"], tc.want)
			}

			items := listItems(t, router, "/v1/net-policies?namespace=payments")
			if len(items) != 1 || !reflect.DeepEqual(items[0]["pluginParams"], tc.want) {
				t.Fatalf("stored pluginParams = %v, want %v", items, tc.want)
			}
		})
	}
}

// A retry of an identity created from duplicate member names returns 200 with
// the original record when the final content matches, regardless of how the
// members are spelled, consumes no order, and the following fresh identity
// takes the next sequence value.
func TestPostNetPolicyDuplicateMembersIdempotentRetryAndOrder(t *testing.T) {
	router, _ := newTestRouter(t)
	seed := policyBody("payments", "default-deny", "tier=backend",
		`{"a": "1", "mode": "audit", "mode": "enforce"}`)
	if rec := doRequest(router, http.MethodPost, "/v1/net-policies", seed); rec.Code != http.StatusCreated {
		t.Fatalf("seed status = %d: %s", rec.Code, rec.Body.String())
	}

	// Same final content, single occurrence this time.
	retry := doRequest(router, http.MethodPost, "/v1/net-policies",
		policyBody("payments", "default-deny", "tier=backend", `{"mode": "enforce", "a": "1"}`))
	if retry.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want %d: %s", retry.Code, http.StatusOK, retry.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(retry.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode retry: %v", err)
	}
	if body["order"] != float64(1) {
		t.Fatalf("retry order = %v, want original 1", body["order"])
	}
	wantParams := map[string]any{"a": "1", "mode": "enforce"}
	if !reflect.DeepEqual(body["pluginParams"], wantParams) {
		t.Fatalf("retry pluginParams = %v, want %v", body["pluginParams"], wantParams)
	}

	// Different final content is still a conflict rather than an overwrite.
	conflict := doRequest(router, http.MethodPost, "/v1/net-policies",
		policyBody("payments", "default-deny", "tier=backend",
			`{"mode": "audit", "mode": "audit"}`))
	if conflict.Code != http.StatusConflict {
		t.Fatalf("changed retry status = %d, want %d: %s", conflict.Code, http.StatusConflict, conflict.Body.String())
	}
	assertErrorCode(t, conflict, "NetPolicyConflictError")

	next := doRequest(router, http.MethodPost, "/v1/net-policies",
		policyBody("payments", "after", "tier=backend",
			`{"mode": "x", "mode": "x"}`))
	if next.Code != http.StatusCreated {
		t.Fatalf("next status = %d, want %d: %s", next.Code, http.StatusCreated, next.Body.String())
	}
	json.Unmarshal(next.Body.Bytes(), &body)
	if body["order"] != float64(2) {
		t.Fatalf("next order = %v, want 2", body["order"])
	}
	if !reflect.DeepEqual(body["pluginParams"], map[string]any{"mode": "x"}) {
		t.Fatalf("next pluginParams = %v, want single final key", body["pluginParams"])
	}

	items := listItems(t, router, "/v1/net-policies?namespace=payments")
	if len(items) != 2 {
		t.Fatalf("items = %v, want 2 records", items)
	}
}

func assertErrorCode(t *testing.T, recorder *httptest.ResponseRecorder, want string) {
	t.Helper()
	var body map[string]map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if body["error"]["code"] != want {
		t.Fatalf("error.code = %q, want %q (body %s)", body["error"]["code"], want, recorder.Body.String())
	}
	if body["error"]["message"] == "" {
		t.Fatalf("error.message is empty (body %s)", recorder.Body.String())
	}
}
