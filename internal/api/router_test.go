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

// registerPolicy posts the body, requires a 201 and returns the decoded record.
func registerPolicy(t *testing.T, router *gin.Engine, body string) map[string]any {
	t.Helper()
	recorder := doRequest(router, http.MethodPost, "/v1/net-policies", body)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want %d: %s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	var record map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &record); err != nil {
		t.Fatalf("decode record: %v", err)
	}
	return record
}

// assertErrorShape verifies the published error contract: a single top-level
// error object holding exactly the string fields code and message, with the
// message free of SQL, stack traces and file paths.
func assertErrorShape(t *testing.T, recorder *httptest.ResponseRecorder, wantCode string) {
	t.Helper()
	var body map[string]json.RawMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if len(body) != 1 {
		t.Fatalf("error body has %d top-level keys, want only \"error\": %s", len(body), recorder.Body.String())
	}
	raw, ok := body["error"]
	if !ok {
		t.Fatalf("error body missing \"error\": %s", recorder.Body.String())
	}
	var errObj map[string]any
	if err := json.Unmarshal(raw, &errObj); err != nil {
		t.Fatalf("error is not an object: %v", err)
	}
	if len(errObj) != 2 {
		t.Fatalf("error fields = %v, want exactly code and message", errObj)
	}
	code, ok := errObj["code"].(string)
	if !ok || code != wantCode {
		t.Fatalf("error.code = %v, want %q (body %s)", errObj["code"], wantCode, recorder.Body.String())
	}
	message, ok := errObj["message"].(string)
	if !ok || message == "" {
		t.Fatalf("error.message = %v, want a non-empty string", errObj["message"])
	}
	lower := strings.ToLower(message)
	for _, leak := range []string{"sql", "sqlite", "goroutine", ".go:", "panic", "/", "\\"} {
		if strings.Contains(lower, leak) {
			t.Fatalf("error.message leaks %q: %s", leak, message)
		}
	}
}

// The conflict flag is fixed at registration time: the first record keeps
// conflict=false, a later opposite-action record with touching port intervals
// is flagged true, and every query angle returns exactly what registration
// returned, sorted by global order.
func TestConflictFlagLifecycleAcrossRegisterAndQuery(t *testing.T) {
	router, _ := newTestRouter(t)

	first := registerPolicy(t, router, policyWithRules("payments", "alpha", "tier=backend",
		`[{"direction": "ingress", "action": "deny", "ports": [100, 200]}]`,
		`{"mode": "enforce"}`))
	wantFirst := map[string]any{
		"namespace": "payments",
		"name":      "alpha",
		"label":     "tier=backend",
		"rules": []any{map[string]any{
			"direction": "ingress", "action": "deny", "ports": []any{float64(100), float64(200)},
		}},
		"pluginParams": map[string]any{"mode": "enforce"},
		"order":        float64(1),
		"conflict":     false,
	}
	if !reflect.DeepEqual(first, wantFirst) {
		t.Fatalf("first record = %v, want %v", first, wantFirst)
	}

	// Same namespace, label and direction, opposite action; the intervals
	// touch at port 200, which counts as overlap.
	second := registerPolicy(t, router, policyWithRules("payments", "beta", "tier=backend",
		`[{"direction": "ingress", "action": "allow", "ports": [200, 300]}]`,
		`{"mode": "audit"}`))
	if second["order"] != float64(2) {
		t.Fatalf("second order = %v, want 2", second["order"])
	}
	if second["conflict"] != true {
		t.Fatalf("second conflict = %v, want true", second["conflict"])
	}

	// Namespace, label and intersection queries all return both records in
	// global order, identical to the registration responses.
	for _, target := range []string{
		"/v1/net-policies?namespace=payments",
		"/v1/net-policies?label=tier%3Dbackend",
		"/v1/net-policies?namespace=payments&label=tier%3Dbackend",
	} {
		items := listItems(t, router, target)
		if len(items) != 2 {
			t.Fatalf("GET %s items = %v, want 2 entries", target, items)
		}
		if !reflect.DeepEqual(items[0], first) {
			t.Fatalf("GET %s first item = %v, want registration response %v", target, items[0], first)
		}
		if !reflect.DeepEqual(items[1], second) {
			t.Fatalf("GET %s second item = %v, want registration response %v", target, items[1], second)
		}
	}
}

// Overlap is decided on closed intervals: touching endpoints count, a single
// port is an interval of one, and 1..65535 overlaps everything. Adjacent but
// separated intervals do not overlap. The older record keeps its flag either
// way.
func TestConflictFlagPortBoundaries(t *testing.T) {
	cases := []struct {
		name      string
		seedPorts [2]int
		newPorts  [2]int
		conflict  bool
	}{
		{"single port equal", [2]int{80, 80}, [2]int{80, 80}, true},
		{"touching lower endpoint", [2]int{100, 200}, [2]int{200, 300}, true},
		{"touching upper endpoint", [2]int{200, 300}, [2]int{100, 200}, true},
		{"adjacent but separated", [2]int{100, 200}, [2]int{201, 300}, false},
		{"single ports apart", [2]int{80, 80}, [2]int{81, 81}, false},
		{"full range against port 1", [2]int{1, 65535}, [2]int{1, 1}, true},
		{"full range against port 65535", [2]int{1, 65535}, [2]int{65535, 65535}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			seed := registerPolicy(t, router, policyWithRules("payments", "seed", "tier=backend",
				fmt.Sprintf(`[{"direction": "ingress", "action": "deny", "ports": [%d, %d]}]`, tc.seedPorts[0], tc.seedPorts[1]),
				`{}`))
			if seed["conflict"] != false || seed["order"] != float64(1) {
				t.Fatalf("seed = %v, want order 1 and conflict false", seed)
			}

			candidate := registerPolicy(t, router, policyWithRules("payments", "candidate", "tier=backend",
				fmt.Sprintf(`[{"direction": "ingress", "action": "allow", "ports": [%d, %d]}]`, tc.newPorts[0], tc.newPorts[1]),
				`{}`))
			if candidate["order"] != float64(2) {
				t.Fatalf("candidate order = %v, want 2", candidate["order"])
			}
			if candidate["conflict"] != tc.conflict {
				t.Fatalf("candidate conflict = %v, want %v", candidate["conflict"], tc.conflict)
			}

			items := listItems(t, router, "/v1/net-policies?namespace=payments")
			if len(items) != 2 {
				t.Fatalf("items = %v, want 2 entries", items)
			}
			if !reflect.DeepEqual(items[0], seed) {
				t.Fatalf("seed record changed after candidate: got %v, want %v", items[0], seed)
			}
			if !reflect.DeepEqual(items[1], candidate) {
				t.Fatalf("queried candidate = %v, want registration response %v", items[1], candidate)
			}
		})
	}
}

// A clash is found even when the conflicting rule sits behind non-clashing
// rules, in the new policy or in the stored one.
func TestConflictDetectedBeyondFirstRule(t *testing.T) {
	router, _ := newTestRouter(t)

	seed := registerPolicy(t, router, policyWithRules("payments", "multi-seed", "tier=backend", `[
		{"direction": "egress", "action": "deny", "ports": [53, 53]},
		{"direction": "ingress", "action": "deny", "ports": [1000, 2000]}
	]`, `{}`))
	if seed["conflict"] != false {
		t.Fatalf("seed conflict = %v, want false", seed["conflict"])
	}

	// Only the last rule clashes, and only with the seed's last rule.
	candidate := registerPolicy(t, router, policyWithRules("payments", "multi-candidate", "tier=backend", `[
		{"direction": "ingress", "action": "allow", "ports": [9000, 9100]},
		{"direction": "egress", "action": "allow", "ports": [53, 53]},
		{"direction": "ingress", "action": "allow", "ports": [1500, 1600]}
	]`, `{}`))
	if candidate["order"] != float64(2) {
		t.Fatalf("candidate order = %v, want 2", candidate["order"])
	}
	if candidate["conflict"] != true {
		t.Fatalf("candidate conflict = %v, want true (late rule must be found)", candidate["conflict"])
	}

	items := listItems(t, router, "/v1/net-policies?namespace=payments&label=tier%3Dbackend")
	if len(items) != 2 || !reflect.DeepEqual(items[0], seed) || !reflect.DeepEqual(items[1], candidate) {
		t.Fatalf("items = %v, want unchanged seed then flagged candidate", items)
	}
}

// None of these dimensions relax the flag: separated ports, a different
// direction, the same action, a different namespace or a different label all
// leave the new record at conflict=false. Each scenario uses distinct policy
// names.
func TestConflictFlagNegativeCases(t *testing.T) {
	cases := []struct {
		name           string
		seedNS         string
		seedLabel      string
		seedRules      string
		candidateNS    string
		candidateLabel string
		candidateRules string
	}{
		{
			name:           "ports fully separated",
			seedNS:         "payments", seedLabel: "tier=backend",
			seedRules:      `[{"direction": "ingress", "action": "deny", "ports": [100, 200]}]`,
			candidateNS:    "payments", candidateLabel: "tier=backend",
			candidateRules: `[{"direction": "ingress", "action": "allow", "ports": [300, 400]}]`,
		},
		{
			name:           "different direction",
			seedNS:         "payments", seedLabel: "tier=backend",
			seedRules:      `[{"direction": "ingress", "action": "deny", "ports": [1, 65535]}]`,
			candidateNS:    "payments", candidateLabel: "tier=backend",
			candidateRules: `[{"direction": "egress", "action": "allow", "ports": [80, 80]}]`,
		},
		{
			name:           "same action",
			seedNS:         "payments", seedLabel: "tier=backend",
			seedRules:      `[{"direction": "ingress", "action": "deny", "ports": [1, 65535]}]`,
			candidateNS:    "payments", candidateLabel: "tier=backend",
			candidateRules: `[{"direction": "ingress", "action": "deny", "ports": [80, 80]}]`,
		},
		{
			name:           "different namespace",
			seedNS:         "payments", seedLabel: "tier=backend",
			seedRules:      `[{"direction": "ingress", "action": "deny", "ports": [1, 65535]}]`,
			candidateNS:    "staging", candidateLabel: "tier=backend",
			candidateRules: `[{"direction": "ingress", "action": "allow", "ports": [80, 80]}]`,
		},
		{
			name:           "different label",
			seedNS:         "payments", seedLabel: "tier=backend",
			seedRules:      `[{"direction": "ingress", "action": "deny", "ports": [1, 65535]}]`,
			candidateNS:    "payments", candidateLabel: "tier=frontend",
			candidateRules: `[{"direction": "ingress", "action": "allow", "ports": [80, 80]}]`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			seed := registerPolicy(t, router, policyWithRules(tc.seedNS, "seed", tc.seedLabel, tc.seedRules, `{}`))
			if seed["order"] != float64(1) || seed["conflict"] != false {
				t.Fatalf("seed = %v, want order 1 and conflict false", seed)
			}
			candidate := registerPolicy(t, router, policyWithRules(tc.candidateNS, "candidate", tc.candidateLabel, tc.candidateRules, `{}`))
			if candidate["order"] != float64(2) {
				t.Fatalf("candidate order = %v, want 2", candidate["order"])
			}
			if candidate["conflict"] != false {
				t.Fatalf("candidate conflict = %v, want false", candidate["conflict"])
			}

			// Records queried back through a namespace+label intersection match
			// the registration responses exactly, in global order.
			sharedIdentity := tc.seedNS == tc.candidateNS && tc.seedLabel == tc.candidateLabel
			for _, want := range []map[string]any{seed, candidate} {
				target := fmt.Sprintf("/v1/net-policies?namespace=%s&label=%s",
					want["namespace"], strings.ReplaceAll(want["label"].(string), "=", "%3D"))
				items := listItems(t, router, target)
				expected := []map[string]any{want}
				if sharedIdentity {
					expected = []map[string]any{seed, candidate}
				}
				if !reflect.DeepEqual(items, expected) {
					t.Fatalf("GET %s items = %v, want %v", target, items, expected)
				}
			}
		})
	}
}

// Records carrying true and false flags survive closing and reopening the same
// database file with every field and the global order intact. Re-submitting
// the original policy afterwards returns 200 with the original record: the
// stored flag is served as-is, never recomputed against the newer
// opposite-action record, and pluginParams member order is irrelevant.
func TestConflictFlagsSurviveReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	router := NewRouter(st)

	first := registerPolicy(t, router, policyWithRules("payments", "alpha", "tier=backend",
		`[{"direction": "ingress", "action": "deny", "ports": [80, 80]}]`,
		`{"mode": "enforce", "zone": "north"}`))
	if first["conflict"] != false || first["order"] != float64(1) {
		t.Fatalf("first = %v, want order 1 and conflict false", first)
	}
	second := registerPolicy(t, router, policyWithRules("payments", "beta", "tier=backend",
		`[{"direction": "ingress", "action": "allow", "ports": [80, 80]}]`,
		`{"mode": "audit"}`))
	if second["conflict"] != true || second["order"] != float64(2) {
		t.Fatalf("second = %v, want order 2 and conflict true", second)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := store.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { reopened.Close() })
	router = NewRouter(reopened)

	items := listItems(t, router, "/v1/net-policies?namespace=payments")
	if len(items) != 2 {
		t.Fatalf("items after reopen = %v, want 2 entries", items)
	}
	if !reflect.DeepEqual(items[0], first) {
		t.Fatalf("first record after reopen = %v, want %v", items[0], first)
	}
	if !reflect.DeepEqual(items[1], second) {
		t.Fatalf("second record after reopen = %v, want %v", items[1], second)
	}

	// Same content, pluginParams members in a different order: still the
	// original record, still conflict=false, still 200.
	retry := doRequest(router, http.MethodPost, "/v1/net-policies", policyWithRules("payments", "alpha", "tier=backend",
		`[{"direction": "ingress", "action": "deny", "ports": [80, 80]}]`,
		`{"zone": "north", "mode": "enforce"}`))
	if retry.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want %d: %s", retry.Code, http.StatusOK, retry.Body.String())
	}
	var retryRecord map[string]any
	if err := json.Unmarshal(retry.Body.Bytes(), &retryRecord); err != nil {
		t.Fatalf("decode retry: %v", err)
	}
	if !reflect.DeepEqual(retryRecord, first) {
		t.Fatalf("retry record = %v, want original %v (flags must not be recomputed)", retryRecord, first)
	}

	// The retry consumed no order: the next new identity takes max order + 1.
	third := registerPolicy(t, router, policyWithRules("payments", "gamma", "tier=backend",
		`[{"direction": "egress", "action": "allow", "ports": [53, 53]}]`, `{}`))
	if third["order"] != float64(3) {
		t.Fatalf("order after reopen and retry = %v, want 3", third["order"])
	}
}

// Rejected requests (400/409) and same-content retries never add records,
// never change stored fields and never consume an order value; the next legal
// policy takes the current maximum order plus one.
func TestRejectedAndRetriedRequestsLeaveRegistryUntouched(t *testing.T) {
	router, _ := newTestRouter(t)

	seedBody := policyWithRules("payments", "alpha", "tier=backend",
		`[{"direction": "ingress", "action": "deny", "ports": [1, 65535]}]`,
		`{"mode": "enforce"}`)
	seed := registerPolicy(t, router, seedBody)

	// Same-content retry: 200 with the original record, nothing changes.
	retry := doRequest(router, http.MethodPost, "/v1/net-policies", seedBody)
	if retry.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want %d: %s", retry.Code, http.StatusOK, retry.Body.String())
	}
	var retryRecord map[string]any
	if err := json.Unmarshal(retry.Body.Bytes(), &retryRecord); err != nil {
		t.Fatalf("decode retry: %v", err)
	}
	if !reflect.DeepEqual(retryRecord, seed) {
		t.Fatalf("retry record = %v, want original %v", retryRecord, seed)
	}

	// A legal change to an existing identity's plugin string value: 409.
	changed := doRequest(router, http.MethodPost, "/v1/net-policies",
		policyWithRules("payments", "alpha", "tier=backend",
			`[{"direction": "ingress", "action": "deny", "ports": [1, 65535]}]`,
			`{"mode": "audit"}`))
	if changed.Code != http.StatusConflict {
		t.Fatalf("changed status = %d, want %d: %s", changed.Code, http.StatusConflict, changed.Body.String())
	}
	assertErrorShape(t, changed, "NetPolicyConflictError")

	// Invalid direction and out-of-range ports: 400.
	for name, body := range map[string]string{
		"bad direction": policyWithRules("payments", "beta", "tier=backend",
			`[{"direction": "sideways", "action": "allow", "ports": [80, 80]}]`, `{}`),
		"port below range": policyWithRules("payments", "gamma", "tier=backend",
			`[{"direction": "ingress", "action": "allow", "ports": [0, 80]}]`, `{}`),
		"port above range": policyWithRules("payments", "delta", "tier=backend",
			`[{"direction": "ingress", "action": "allow", "ports": [1, 65536]}]`, `{}`),
	} {
		recorder := doRequest(router, http.MethodPost, "/v1/net-policies", body)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want %d: %s", name, recorder.Code, http.StatusBadRequest, recorder.Body.String())
		}
		assertErrorShape(t, recorder, "InvalidNetPolicyInputError")
	}

	// A filter matching nothing: 404.
	miss := doRequest(router, http.MethodGet, "/v1/net-policies?namespace=staging", "")
	if miss.Code != http.StatusNotFound {
		t.Fatalf("miss status = %d, want %d: %s", miss.Code, http.StatusNotFound, miss.Body.String())
	}
	assertErrorShape(t, miss, "NetPolicyNotFoundError")

	// Nothing was added and the committed record is untouched in every field.
	items := listItems(t, router, "/v1/net-policies?namespace=payments")
	if len(items) != 1 {
		t.Fatalf("items = %v, want the single original record", items)
	}
	if !reflect.DeepEqual(items[0], seed) {
		t.Fatalf("record changed after rejected requests: got %v, want %v", items[0], seed)
	}

	// The next legal new policy takes the current maximum order plus one.
	next := registerPolicy(t, router, policyWithRules("payments", "epsilon", "tier=backend",
		`[{"direction": "egress", "action": "allow", "ports": [53, 53]}]`, `{}`))
	if next["order"] != float64(2) {
		t.Fatalf("next order = %v, want 2 (rejections and retries consume no order)", next["order"])
	}
}
