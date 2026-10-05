package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Bob-xisuke/orb-netpolicy-guard/internal/store"
)

func newRouter(t *testing.T) (*ginRouterHarness, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return &ginRouterHarness{router: NewRouter(st)}, st
}

type ginRouterHarness struct{ router http.Handler }

func (h *ginRouterHarness) do(method, target string, body string) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body != "" {
		reader = bytes.NewReader([]byte(body))
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, target, reader)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var payload struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("error payload is not JSON: %s", rec.Body.String())
	}
	if payload.Error.Code == "" {
		t.Fatalf("error.code missing in %s", rec.Body.String())
	}
	return payload.Error.Code
}

const validPolicyBody = `{
  "namespace": "team-a",
  "name": "web-policy",
  "label": "frontend",
  "rules": [{"direction": "ingress", "action": "allow", "ports": [80, 90]}],
  "pluginParams": {"mode": "enforce"}
}`

func TestPostNetPolicyCreatesThenReplays(t *testing.T) {
	h, _ := newRouter(t)

	rec := h.do(http.MethodPost, "/v1/net-policies", validPolicyBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", rec.Code, rec.Body.String())
	}
	var created struct {
		Namespace    string            `json:"namespace"`
		Name         string            `json:"name"`
		Label        string            `json:"label"`
		Rules        []map[string]any  `json:"rules"`
		PluginParams map[string]string `json:"pluginParams"`
		Order        int64             `json:"order"`
		Conflict     bool              `json:"conflict"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Order != 1 || created.Conflict {
		t.Fatalf("unexpected create payload: %s", rec.Body.String())
	}
	if created.Namespace != "team-a" || created.Name != "web-policy" || created.Label != "frontend" {
		t.Fatalf("identity fields wrong: %s", rec.Body.String())
	}
	if ports := created.Rules[0]["ports"]; fmt.Sprint(ports) != "[80 90]" {
		t.Fatalf("ports wrong: %v", ports)
	}

	// Identical replay returns the original record and takes no new order.
	rec = h.do(http.MethodPost, "/v1/net-policies", validPolicyBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("replay status = %d body=%s", rec.Code, rec.Body.String())
	}
	var replay struct {
		Order int64 `json:"order"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &replay); err != nil {
		t.Fatal(err)
	}
	if replay.Order != 1 {
		t.Fatalf("replay must keep order 1, body=%s", rec.Body.String())
	}
}

func TestPostNetPolicyConflictAndFlags(t *testing.T) {
	h, _ := newRouter(t)

	first := h.do(http.MethodPost, "/v1/net-policies", validPolicyBody)
	if first.Code != http.StatusCreated {
		t.Fatalf("first status = %d %s", first.Code, first.Body.String())
	}

	different := `{
      "namespace": "team-a", "name": "web-policy", "label": "frontend",
      "rules": [{"direction": "egress", "action": "deny", "ports": [1, 1024]}],
      "pluginParams": {}
    }`
	rec := h.do(http.MethodPost, "/v1/net-policies", different)
	if rec.Code != http.StatusConflict {
		t.Fatalf("conflict status = %d want 409, body=%s", rec.Code, rec.Body.String())
	}
	if code := errorCode(t, rec); code != "NetPolicyConflictError" {
		t.Fatalf("code = %s", code)
	}

	// The new record that conflicts with a previously committed same
	// namespace/label policy is still created and flagged.
	flagged := `{
      "namespace": "team-a", "name": "other-policy", "label": "frontend",
      "rules": [{"direction": "ingress", "action": "deny", "ports": [85, 100]}],
      "pluginParams": {}
    }`
	rec = h.do(http.MethodPost, "/v1/net-policies", flagged)
	if rec.Code != http.StatusCreated {
		t.Fatalf("flagged create status = %d body=%s", rec.Code, rec.Body.String())
	}
	var p struct {
		Order    int64 `json:"order"`
		Conflict bool  `json:"conflict"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Order != 2 || !p.Conflict {
		t.Fatalf("new conflicting policy must be order 2 + conflict true: %s", rec.Body.String())
	}

	// Disjoint ports never conflict.
	disjoint := `{
      "namespace": "team-a", "name": "third-policy", "label": "frontend",
      "rules": [{"direction": "ingress", "action": "deny", "ports": [91, 100]}],
      "pluginParams": {}
    }`
	rec = h.do(http.MethodPost, "/v1/net-policies", disjoint)
	if rec.Code != http.StatusCreated {
		t.Fatalf("disjoint create status = %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"conflict":true`) {
		t.Fatalf("disjoint ports must not conflict: %s", rec.Body.String())
	}
}

func TestPostNetPolicyKeyOrderIrrelevant(t *testing.T) {
	h, _ := newRouter(t)
	if rec := h.do(http.MethodPost, "/v1/net-policies", validPolicyBody); rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}

	// Same content, but the JSON text lists object keys in a different order.
	sameReordered := `{
      "pluginParams": {"mode": "enforce"},
      "rules": [{"ports": [80, 90], "action": "allow", "direction": "ingress"}],
      "label": "frontend", "name": "web-policy", "namespace": "team-a"
    }`
	if rec := h.do(http.MethodPost, "/v1/net-policies", sameReordered); rec.Code != 200 {
		t.Fatalf("same content with reordered keys must replay 200, got %d %s", rec.Code, rec.Body.String())
	}

	// Different pluginParams content conflicts regardless of key order.
	different := `{
      "namespace": "team-a", "name": "web-policy", "label": "frontend",
      "rules": [{"direction": "ingress", "action": "allow", "ports": [80, 90]}],
      "pluginParams": {"z": "1", "a": "2"}
    }`
	if rec := h.do(http.MethodPost, "/v1/net-policies", different); rec.Code != 409 {
		t.Fatalf("different content must 409, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestPostNetPolicyRejectsInvalidInput(t *testing.T) {
	bodies := map[string]string{
		"malformed json":              `{"namespace":`,
		"multiple json values":        validPolicyBody + `{"namespace":"x"}`,
		"trailing garbage":            validPolicyBody + ` wat`,
		"empty object":                `{}`,
		"missing namespace":           `{"name":"n","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[80,80]}],"pluginParams":{}}`,
		"missing name":                `{"namespace":"ns","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[80,80]}],"pluginParams":{}}`,
		"missing label":               `{"namespace":"ns","name":"n","rules":[{"direction":"ingress","action":"allow","ports":[80,80]}],"pluginParams":{}}`,
		"missing rules":               `{"namespace":"ns","name":"n","label":"l","pluginParams":{}}`,
		"missing pluginParams":        `{"namespace":"ns","name":"n","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[80,80]}]}`,
		"blank namespace":             `{"namespace":"  ","name":"n","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[80,80]}],"pluginParams":{}}`,
		"blank name":                  `{"namespace":"ns","name":"\t","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[80,80]}],"pluginParams":{}}`,
		"blank label":                 `{"namespace":"ns","name":"n","label":" ","rules":[{"direction":"ingress","action":"allow","ports":[80,80]}],"pluginParams":{}}`,
		"empty rules":                 `{"namespace":"ns","name":"n","label":"l","rules":[],"pluginParams":{}}`,
		"wrong namespace type":        `{"namespace":7,"name":"n","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[80,80]}],"pluginParams":{}}`,
		"rules not array":             `{"namespace":"ns","name":"n","label":"l","rules":{},"pluginParams":{}}`,
		"pluginParams not object":     `{"namespace":"ns","name":"n","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[80,80]}],"pluginParams":[]}`,
		"pluginParams non-string val": `{"namespace":"ns","name":"n","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[80,80]}],"pluginParams":{"a":1}}`,
		"bad direction":               `{"namespace":"ns","name":"n","label":"l","rules":[{"direction":"in","action":"allow","ports":[80,80]}],"pluginParams":{}}`,
		"missing direction":           `{"namespace":"ns","name":"n","label":"l","rules":[{"action":"allow","ports":[80,80]}],"pluginParams":{}}`,
		"bad action":                  `{"namespace":"ns","name":"n","label":"l","rules":[{"direction":"ingress","action":"permit","ports":[80,80]}],"pluginParams":{}}`,
		"port zero":                   `{"namespace":"ns","name":"n","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[0,80]}],"pluginParams":{}}`,
		"port over max":               `{"namespace":"ns","name":"n","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[80,65536]}],"pluginParams":{}}`,
		"negative port":               `{"namespace":"ns","name":"n","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[-1,80]}],"pluginParams":{}}`,
		"start greater than end":      `{"namespace":"ns","name":"n","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[100,80]}],"pluginParams":{}}`,
		"ports too few":               `{"namespace":"ns","name":"n","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[80]}],"pluginParams":{}}`,
		"ports too many":              `{"namespace":"ns","name":"n","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[80,90,100]}],"pluginParams":{}}`,
		"ports wrong type":            `{"namespace":"ns","name":"n","label":"l","rules":[{"direction":"ingress","action":"allow","ports":["80","90"]}],"pluginParams":{}}`,
		"missing ports":               `{"namespace":"ns","name":"n","label":"l","rules":[{"direction":"ingress","action":"allow"}],"pluginParams":{}}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			h, _ := newRouter(t)
			rec := h.do(http.MethodPost, "/v1/net-policies", body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d want 400, body=%s", rec.Code, rec.Body.String())
			}
			if code := errorCode(t, rec); code != "InvalidNetPolicyInputError" {
				t.Fatalf("code = %s", code)
			}
		})
	}
}

func TestPostNetPolicyEmptyPluginParamsAccepted(t *testing.T) {
	h, _ := newRouter(t)
	body := `{"namespace":"ns","name":"n","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[443,443]}],"pluginParams":{}}`
	rec := h.do(http.MethodPost, "/v1/net-policies", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"pluginParams":{}`) {
		t.Fatalf("empty pluginParams should round-trip: %s", rec.Body.String())
	}
}

func TestPostNetPolicyInvalidInputWritesNothing(t *testing.T) {
	h, _ := newRouter(t)
	bad := `{"namespace":"ns","name":"n","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[0,0]}],"pluginParams":{}}`
	if rec := h.do(http.MethodPost, "/v1/net-policies", bad); rec.Code != 400 {
		t.Fatalf("bad create = %d", rec.Code)
	}
	rec := h.do(http.MethodGet, "/v1/net-policies?namespace=ns", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("invalid POST must leave no records, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestPostNetPolicyConcurrentSameIdentity(t *testing.T) {
	h, st := newRouter(t)

	const n = 20
	var wg sync.WaitGroup
	start := make(chan struct{})
	statuses := make(chan int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			statuses <- h.do(http.MethodPost, "/v1/net-policies", validPolicyBody).Code
		}()
	}
	close(start)
	wg.Wait()
	close(statuses)

	created, replayed := 0, 0
	for s := range statuses {
		switch s {
		case 201:
			created++
		case 200:
			replayed++
		default:
			t.Fatalf("unexpected concurrent status %d", s)
		}
	}
	if created != 1 || created+replayed != n {
		t.Fatalf("created=%d replayed=%d (want exactly one 201)", created, replayed)
	}
	_ = st
}

func TestGetNetPolicies(t *testing.T) {
	h, _ := newRouter(t)

	if rec := h.do(http.MethodGet, "/v1/net-policies", ""); rec.Code != 400 {
		t.Fatalf("no conditions status = %d want 400", rec.Code)
	} else if code := errorCode(t, rec); code != "InvalidNetPolicyInputError" {
		t.Fatalf("code = %s", code)
	}

	for _, target := range []string{
		"/v1/net-policies?namespace=",
		"/v1/net-policies?label=%20%20",
		"/v1/net-policies?namespace=a&namespace=b",
		"/v1/net-policies?label=l&label=l2",
	} {
		if rec := h.do(http.MethodGet, target, ""); rec.Code != 400 {
			t.Fatalf("%s status = %d want 400", target, rec.Code)
		}
	}

	// Nothing matches before data exists.
	if rec := h.do(http.MethodGet, "/v1/net-policies?namespace=team-a", ""); rec.Code != 404 {
		t.Fatalf("empty result status = %d want 404", rec.Code)
	} else if code := errorCode(t, rec); code != "NetPolicyNotFoundError" {
		t.Fatalf("code = %s", code)
	}

	mk := func(ns, name, label string, order int) string {
		return fmt.Sprintf(`{"namespace":%q,"name":%q,"label":%q,`+
			`"rules":[{"direction":"ingress","action":"allow","ports":[80,80]}],"pluginParams":{}}`, ns, name, label)
	}
	for _, body := range []string{
		mk("a", "first", "red", 1),
		mk("a", "second", "blue", 2),
		mk("b", "third", "red", 3),
	} {
		if rec := h.do(http.MethodPost, "/v1/net-policies", body); rec.Code != 201 {
			t.Fatalf("seed status = %d %s", rec.Code, rec.Body.String())
		}
	}

	rec := h.do(http.MethodGet, "/v1/net-policies?namespace=a", "")
	if rec.Code != 200 {
		t.Fatalf("list status = %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Items []struct {
			Name  string `json:"name"`
			Order int64  `json:"order"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 2 || resp.Items[0].Name != "first" || resp.Items[1].Name != "second" {
		t.Fatalf("namespace items/order wrong: %s", rec.Body.String())
	}

	if rec = h.do(http.MethodGet, "/v1/net-policies?label=red", ""); rec.Code != 200 {
		t.Fatalf("label list status = %d", rec.Code)
	} else {
		var r struct {
			Items []map[string]any `json:"items"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil || len(r.Items) != 2 {
			t.Fatalf("label items wrong: %d %s", len(r.Items), rec.Body.String())
		}
	}

	rec = h.do(http.MethodGet, "/v1/net-policies?namespace=a&label=red", "")
	if rec.Code != 200 {
		t.Fatalf("intersection status = %d %s", rec.Code, rec.Body.String())
	}
	var inter struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &inter); err != nil || len(inter.Items) != 1 || inter.Items[0].Name != "first" {
		t.Fatalf("intersection wrong: %s", rec.Body.String())
	}
}

func TestNetPolicyEndpointsStorageUnavailable(t *testing.T) {
	h, st := newRouter(t)
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	rec := h.do(http.MethodPost, "/v1/net-policies", validPolicyBody)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST status = %d want 503", rec.Code)
	}
	if code := errorCode(t, rec); code != "storage_unavailable" {
		t.Fatalf("POST code = %s", code)
	}

	rec = h.do(http.MethodGet, "/v1/net-policies?namespace=a", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET status = %d want 503", rec.Code)
	}
	if code := errorCode(t, rec); code != "storage_unavailable" {
		t.Fatalf("GET code = %s", code)
	}
}

func TestExistingBehaviorPreserved(t *testing.T) {
	h, _ := newRouter(t)

	if rec := h.do(http.MethodGet, "/healthz", ""); rec.Code != 200 ||
		rec.Body.String() != `{"database":"ok","status":"ok"}` {
		t.Fatalf("healthz changed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := h.do(http.MethodGet, "/missing", ""); rec.Code != 404 {
		t.Fatalf("unknown route status = %d", rec.Code)
	}
	if rec := h.do(http.MethodPut, "/v1/net-policies", validPolicyBody); rec.Code != 404 {
		t.Fatalf("PUT on POST-only route status = %d want 404", rec.Code)
	}
}
