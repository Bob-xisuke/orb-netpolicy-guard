package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// policyWithPluginParams builds a well-formed policy for the given identity
// whose pluginParams object is encoded by pluginJSON (e.g. {"mode": null}).
func policyWithPluginParams(namespace, name, pluginJSON string) string {
	return fmt.Sprintf(`{
		"namespace": %q,
		"name": %q,
		"label": "tier=backend",
		"rules": [{"direction": "ingress", "action": "deny", "ports": [1, 65535]}],
		"pluginParams": %s
	}`, namespace, name, pluginJSON)
}

// queryBy filters committed records through the public GET endpoint using the
// given namespace/label; an empty condition is omitted from the query string.
func queryBy(t *testing.T, router http.Handler, namespace, label string) (int, map[string]any) {
	t.Helper()
	values := url.Values{}
	if namespace != "" {
		values.Set("namespace", namespace)
	}
	if label != "" {
		values.Set("label", label)
	}
	target := "/v1/net-policies"
	if encoded := values.Encode(); encoded != "" {
		target += "?" + encoded
	}
	recorder := doRequest(router, http.MethodGet, target, "")
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode GET %s: %v (body %s)", target, err, recorder.Body.String())
	}
	return recorder.Code, body
}

func assertQueryNotFound(t *testing.T, router http.Handler, namespace, label string) {
	t.Helper()
	status, body := queryBy(t, router, namespace, label)
	if status != http.StatusNotFound {
		t.Fatalf("GET namespace=%q label=%q status = %d, want %d: %v", namespace, label, status, http.StatusNotFound, body)
	}
	if code, _ := body["error"].(map[string]any)["code"].(string); code != "NetPolicyNotFoundError" {
		t.Fatalf("GET namespace=%q label=%q error.code = %v, want NetPolicyNotFoundError", namespace, label, body)
	}
}

func assertQueryReturnsRecord(t *testing.T, router http.Handler, namespace, label string, want map[string]any) map[string]any {
	t.Helper()
	status, body := queryBy(t, router, namespace, label)
	if status != http.StatusOK {
		t.Fatalf("GET namespace=%q label=%q status = %d, want %d: %v", namespace, label, status, http.StatusOK, body)
	}
	items, ok := body["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("GET namespace=%q label=%q items = %v, want exactly one record", namespace, label, body["items"])
	}
	got, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("record is not an object: %v", items[0])
	}
	for key, wantValue := range want {
		if !reflect.DeepEqual(got[key], wantValue) {
			t.Fatalf("GET namespace=%q label=%q field %s = %#v, want %#v (full record %v)", namespace, label, key, got[key], wantValue, got)
		}
	}
	return got
}

func TestPostNetPolicyNullParamOnNewIdentityIsRejectedAndSkipsNothing(t *testing.T) {
	router, st := newTestRouter(t)

	rejected := policyWithPluginParams("payments", "bad", `{"mode": null}`)
	recorder := doRequest(router, http.MethodPost, "/v1/net-policies", rejected)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	assertErrorCode(t, recorder, "InvalidNetPolicyInputError")

	// The rejected identity is visible nowhere: both lookup dimensions 404.
	assertQueryNotFound(t, router, "payments", "")
	assertQueryNotFound(t, router, "", "tier=backend")

	// Nothing was persisted and the rejected attempt must not consume an order.
	records, err := st.List("", "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("rejected registration left records behind: %+v", records)
	}

	// The first legitimate registration afterwards starts the order at 1.
	valid := policyWithPluginParams("payments", "good", `{"mode": "enforce"}`)
	recorder = doRequest(router, http.MethodPost, "/v1/net-policies", valid)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("valid status = %d, want %d: %s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if created["order"] != float64(1) {
		t.Fatalf("order = %v, want 1 (rejected request must not consume an order)", created["order"])
	}
	assertQueryReturnsRecord(t, router, "payments", "tier=backend", map[string]any{
		"name":         "good",
		"order":        float64(1),
		"pluginParams": map[string]any{"mode": "enforce"},
	})
}

func TestPostNetPolicyNullParamOnExistingIdentityLeavesRecordUntouched(t *testing.T) {
	cases := []struct {
		name       string
		pluginJSON string
		wantParams map[string]any
	}{
		{name: "empty string value", pluginJSON: `{"mode": ""}`, wantParams: map[string]any{"mode": ""}},
		{name: "non-empty string value", pluginJSON: `{"mode": "enforce"}`, wantParams: map[string]any{"mode": "enforce"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, _ := newTestRouter(t)

			seed := policyWithPluginParams("payments", "seed", tc.pluginJSON)
			if rec := doRequest(router, http.MethodPost, "/v1/net-policies", seed); rec.Code != http.StatusCreated {
				t.Fatalf("seed status = %d: %s", rec.Code, rec.Body.String())
			}

			// Null member alone and mixed with valid members: both must be rejected
			// with the same 400, never 200 (identical retry) or 409 (content change).
			for _, badParams := range []string{`{"mode": null}`, `{"mode": "enforce", "trace": null}`} {
				recorder := doRequest(router, http.MethodPost, "/v1/net-policies", policyWithPluginParams("payments", "seed", badParams))
				if recorder.Code != http.StatusBadRequest {
					t.Fatalf("params %s: status = %d, want %d: %s", badParams, recorder.Code, http.StatusBadRequest, recorder.Body.String())
				}
				assertErrorCode(t, recorder, "InvalidNetPolicyInputError")
			}

			// The stored record survives with its original content, order and conflict.
			got := assertQueryReturnsRecord(t, router, "payments", "tier=backend", map[string]any{
				"name":         "seed",
				"label":        "tier=backend",
				"order":        float64(1),
				"conflict":     false,
				"pluginParams": tc.wantParams,
			})

			// No order was consumed: the next new identity gets order 2.
			other := policyWithPluginParams("payments", "next", `{"mode": "audit"}`)
			recorder := doRequest(router, http.MethodPost, "/v1/net-policies", other)
			if recorder.Code != http.StatusCreated {
				t.Fatalf("next status = %d: %s", recorder.Code, recorder.Body.String())
			}
			var nextBody map[string]any
			json.Unmarshal(recorder.Body.Bytes(), &nextBody)
			if nextBody["order"] != float64(2) {
				t.Fatalf("order after rejected resubmit = %v, want 2 (full seed record %v)", nextBody["order"], got)
			}
		})
	}
}

func TestPostNetPolicyPreservesSpecialPluginParamValues(t *testing.T) {
	specials := []struct {
		name  string
		value string
	}{
		{name: "empty string", value: ``},
		{name: "whitespace only", value: `   `},
		{name: "chinese", value: `拦截模式`},
		{name: "literal null", value: `null`},
	}
	for _, tc := range specials {
		t.Run(tc.name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			pluginJSON := fmt.Sprintf(`{"mode": %q}`, tc.value)
			body := policyWithPluginParams("payments", "special-"+strings.ReplaceAll(tc.name, " ", "-"), pluginJSON)
			recorder := doRequest(router, http.MethodPost, "/v1/net-policies", body)
			if recorder.Code != http.StatusCreated {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusCreated, recorder.Body.String())
			}
			var created map[string]any
			json.Unmarshal(recorder.Body.Bytes(), &created)
			params, _ := created["pluginParams"].(map[string]any)
			if params["mode"] != tc.value {
				t.Fatalf("pluginParams.mode = %#v, want preserved original %#v", params["mode"], tc.value)
			}
		})
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
		"null plugin param":       `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[1,2]}],"pluginParams":{"mode":null}}`,
		"null plugin param mixed": `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[1,2]}],"pluginParams":{"mode":"enforce","trace":null}}`,
		"boolean plugin param":    `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[1,2]}],"pluginParams":{"mode":true}}`,
		"array plugin param":      `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[1,2]}],"pluginParams":{"mode":[]}}`,
		"object plugin param":     `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[1,2]}],"pluginParams":{"mode":{"k":"v"}}}`,
		"null pluginParams":       `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[1,2]}],"pluginParams":null}`,
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
