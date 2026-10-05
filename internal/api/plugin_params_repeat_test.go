package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"
)

// policyBodyWithParamFields builds a registration body whose top-level object
// carries the given raw pluginParams field snippets in order, e.g.
// `"pluginParams": {"mode": null}` or an escaped-name variant. This is how a
// repeated top-level pluginParams field is exercised: a map-based decode would
// silently keep only the last occurrence.
func policyBodyWithParamFields(ns, name, label string, fields ...string) string {
	body := fmt.Sprintf(`{
		"namespace": %q,
		"name": %q,
		"label": %q,
		"rules": [{"direction": "ingress", "action": "allow", "ports": [80, 80]}]`,
		ns, name, label)
	for _, field := range fields {
		body += ", " + field
	}
	return body + "}"
}

// A repeated top-level pluginParams field must not let an illegal occurrence
// hide behind a later legal object: every occurrence is validated, whether the
// illegal value is a non-string member inside an object or the field value
// itself is null, a number, a boolean, an array or a string, and whether the
// shared field name is written literally or with a JSON unicode escape on its
// first letter (both decode to the same field name). A rejected new identity
// leaves no record behind and consumes no order.
func TestPostNetPolicyRejectsIllegalRepeatedPluginParamsField(t *testing.T) {
	legal := `"pluginParams": {"mode": "enforce"}`
	cases := map[string][]string{
		"null member in first object, legal second":  {`"pluginParams": {"mode": null}`, legal},
		"legal first, null member in second":         {legal, `"pluginParams": {"mode": null}`},
		"number member in first, legal second":       {`"pluginParams": {"mode": 1}`, legal},
		"boolean member in second":                   {legal, `"pluginParams": {"mode": true}`},
		"array member in first":                      {`"pluginParams": {"mode": ["enforce"]}`, legal},
		"object member in second":                    {legal, `"pluginParams": {"mode": {"x": 1}}`},
		"null field value first":                     {`"pluginParams": null`, legal},
		"null field value second":                    {legal, `"pluginParams": null`},
		"string field value first":                   {`"pluginParams": "enforce"`, legal},
		"number field value first":                   {`"pluginParams": 7`, legal},
		"boolean field value second":                 {legal, `"pluginParams": false`},
		"array field value first":                    {`"pluginParams": ["enforce"]`, legal},
		"escaped name illegal first, literal legal":  {"\"\\u0070luginParams\": {\"mode\": null}", legal},
		"literal legal first, escaped name illegal":  {legal, "\"\\u0070luginParams\": {\"mode\": null}"},
		"illegal middle of three occurrences":        {legal, `"pluginParams": {"mode": null}`, legal},
		"illegal member hidden by two legal objects": {`"pluginParams": {"mode": null, "mode": "enforce"}`, legal},
	}
	for name, fields := range cases {
		t.Run(name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			bad := policyBodyWithParamFields("payments", "default-deny", "tier=backend", fields...)

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

// Posting a repeated top-level pluginParams against an existing identity is
// invalid input whenever any occurrence is illegal, even if the last object
// equals the stored content (never 200) or differs from it (never 409). The
// committed record, its order and its conflict flag stay untouched, and the
// next brand-new identity keeps the expected sequence.
func TestPostNetPolicyRepeatedPluginParamsIllegalOnExistingIdentity(t *testing.T) {
	cases := []struct {
		name   string
		fields []string
	}{
		{"last object equals stored, earlier null member",
			[]string{`"pluginParams": {"mode": null}`, `"pluginParams": {"mode": "enforce"}`}},
		{"last object differs, earlier null member",
			[]string{`"pluginParams": {"mode": null}`, `"pluginParams": {"mode": "audit"}`}},
		{"escaped name illegal, last equals stored",
			[]string{"\"\\u0070luginParams\": {\"mode\": null}", `"pluginParams": {"mode": "enforce"}`}},
		{"illegal second occurrence, first equals stored",
			[]string{`"pluginParams": {"mode": "enforce"}`, `"pluginParams": {"mode": null}`}},
		{"non-object second occurrence",
			[]string{`"pluginParams": {"mode": "enforce"}`, `"pluginParams": null`}},
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
				policyBodyWithParamFields("payments", "default-deny", "tier=backend", tc.fields...))
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

			// The rejected retry consumes no order: the next fresh identity
			// continues the original sequence.
			next := doRequest(router, http.MethodPost, "/v1/net-policies",
				policyBody("payments", "after-reject", "tier=backend", `{}`))
			if next.Code != http.StatusCreated {
				t.Fatalf("next status = %d, want %d: %s", next.Code, http.StatusCreated, next.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(next.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode next: %v", err)
			}
			if body["order"] != float64(3) {
				t.Fatalf("next order = %v, want 3", body["order"])
			}
		})
	}
}

// When every occurrence of a repeated top-level pluginParams is a legal
// string-to-string object the request stays valid: the last complete object
// wins as a whole (earlier members are not merged in), a trailing empty object
// registers as an empty object, and only the final object appears in the
// response and in queries. Field names match after JSON unescaping.
func TestPostNetPolicyRepeatedPluginParamsAllLegalLastObjectWins(t *testing.T) {
	cases := []struct {
		name     string
		identity string
		fields   []string
		want     map[string]any
	}{
		{"earlier members not merged", "no-merge",
			[]string{`"pluginParams": {"a": "1", "mode": "audit"}`, `"pluginParams": {"mode": "enforce"}`},
			map[string]any{"mode": "enforce"}},
		{"later empty object wins", "empty-last",
			[]string{`"pluginParams": {"mode": "enforce"}`, `"pluginParams": {}`},
			map[string]any{}},
		{"earlier empty, later non-empty", "empty-first",
			[]string{`"pluginParams": {}`, `"pluginParams": {"mode": "enforce"}`},
			map[string]any{"mode": "enforce"}},
		{"escaped name first occurrence", "escaped-first",
			[]string{"\"\\u0070luginParams\": {\"a\": \"1\"}", `"pluginParams": {"b": "2"}`},
			map[string]any{"b": "2"}},
		{"escaped name last occurrence", "escaped-last",
			[]string{`"pluginParams": {"a": "1"}`, "\"\\u0070luginParams\": {\"b\": \"2\"}"},
			map[string]any{"b": "2"}},
		{"three occurrences", "three",
			[]string{`"pluginParams": {"a": "1"}`, `"pluginParams": {"b": "2"}`, `"pluginParams": {"c": "3"}`},
			map[string]any{"c": "3"}},
		{"duplicate members inside last object", "dup-in-last",
			[]string{`"pluginParams": {"a": "9"}`, `"pluginParams": {"mode": "audit", "mode": "enforce"}`},
			map[string]any{"mode": "enforce"}},
		{"special values in last object", "special-last",
			[]string{`"pluginParams": {"mode": "audit"}`, `"pluginParams": {"mode": " 拦截 ", "empty": ""}`},
			map[string]any{"mode": " 拦截 ", "empty": ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			body := policyBodyWithParamFields("payments", tc.identity, "tier=backend", tc.fields...)
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

// An identity registered through repeated pluginParams fields keeps the
// published semantics: an idempotent retry with the same final content returns
// 200 with the original record and consumes no order, different final content
// returns 409, and the following fresh identity takes the next sequence value.
func TestPostNetPolicyRepeatedPluginParamsRetrySemantics(t *testing.T) {
	router, _ := newTestRouter(t)
	seed := policyBodyWithParamFields("payments", "default-deny", "tier=backend",
		`"pluginParams": {"a": "1", "mode": "audit"}`,
		`"pluginParams": {"mode": "enforce", "a": "1"}`)
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

	// Same final content spelled with a repeated field is also an idempotent retry.
	repeat := doRequest(router, http.MethodPost, "/v1/net-policies",
		policyBodyWithParamFields("payments", "default-deny", "tier=backend",
			`"pluginParams": {"mode": "enforce", "a": "1"}`,
			`"pluginParams": {"mode": "enforce", "a": "1"}`))
	if repeat.Code != http.StatusOK {
		t.Fatalf("repeat status = %d, want %d: %s", repeat.Code, http.StatusOK, repeat.Body.String())
	}

	// Different final content is still a conflict rather than an overwrite.
	conflict := doRequest(router, http.MethodPost, "/v1/net-policies",
		policyBodyWithParamFields("payments", "default-deny", "tier=backend",
			`"pluginParams": {"mode": "enforce", "a": "1"}`,
			`"pluginParams": {"mode": "audit"}`))
	if conflict.Code != http.StatusConflict {
		t.Fatalf("changed retry status = %d, want %d: %s", conflict.Code, http.StatusConflict, conflict.Body.String())
	}
	assertErrorCode(t, conflict, "NetPolicyConflictError")

	next := doRequest(router, http.MethodPost, "/v1/net-policies",
		policyBody("payments", "after", "tier=backend", `{}`))
	if next.Code != http.StatusCreated {
		t.Fatalf("next status = %d, want %d: %s", next.Code, http.StatusCreated, next.Body.String())
	}
	json.Unmarshal(next.Body.Bytes(), &body)
	if body["order"] != float64(2) {
		t.Fatalf("next order = %v, want 2", body["order"])
	}

	items := listItems(t, router, "/v1/net-policies?namespace=payments")
	if len(items) != 2 {
		t.Fatalf("items = %v, want 2 records", items)
	}
	if !reflect.DeepEqual(items[0]["pluginParams"], wantParams) {
		t.Fatalf("stored pluginParams = %v, want %v", items[0]["pluginParams"], wantParams)
	}
}
