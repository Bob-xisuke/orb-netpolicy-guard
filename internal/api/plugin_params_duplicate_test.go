package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// Spellings of the top-level field name as raw JSON key text.
const (
	pluginParamsKey        = "pluginParams"
	pluginParamsKeyEscaped = `\u0070luginParams` // JSON escape of "p"; decodes to pluginParams
)

// pluginParamsField is one occurrence of the top-level pluginParams field:
// keyJSON is its raw JSON key text (allowing the p spelling) and
// valueJSON is the raw JSON value of that occurrence.
type pluginParamsField struct {
	keyJSON   string
	valueJSON string
}

func pp(valueJSON string) pluginParamsField {
	return pluginParamsField{keyJSON: pluginParamsKey, valueJSON: valueJSON}
}

func ppEscaped(valueJSON string) pluginParamsField {
	return pluginParamsField{keyJSON: pluginParamsKeyEscaped, valueJSON: valueJSON}
}

// policyBodyWithParamFields builds a registration body carrying the given
// pluginParams occurrences in order, so a case can repeat the top-level field
// (including an escaped spelling of its name).
func policyBodyWithParamFields(ns, name, label string, fields ...pluginParamsField) string {
	var b strings.Builder
	fmt.Fprintf(&b, `{"namespace":%q,"name":%q,"label":%q,"rules":[{"direction":"ingress","action":"allow","ports":[80,80]}]`,
		ns, name, label)
	for _, f := range fields {
		b.WriteString(`,"`)
		b.WriteString(f.keyJSON)
		b.WriteString(`":`)
		b.WriteString(f.valueJSON)
	}
	b.WriteString("}")
	return b.String()
}

// Every occurrence of a repeated top-level pluginParams must be an object of
// string values. A null/scalar/array field value or an object carrying a
// non-string member is rejected even when a later legal object would overwrite
// it; field names match after JSON unescaping, so the literal and the
// \u0070-escaped spellings of pluginParams are the same field. On a brand-new identity the rejection
// writes nothing: namespace and label queries stay 404 NetPolicyNotFoundError
// and the first legal registration afterwards still takes order 1.
func TestPostNetPolicyRejectsIllegalRepeatedPluginParamsOnNewIdentity(t *testing.T) {
	cases := map[string][]pluginParamsField{
		"null member first, legal object last": {
			pp(`{"mode": null}`), pp(`{"mode": "enforce"}`),
		},
		"legal object first, null member last": {
			pp(`{"mode": "enforce"}`), pp(`{"mode": null}`),
		},
		"null field value first, legal object last": {
			pp(`null`), pp(`{"mode": "enforce"}`),
		},
		"legal object first, null field value last": {
			pp(`{"mode": "enforce"}`), pp(`null`),
		},
		"string field value then object": {
			pp(`"enforce"`), pp(`{}`),
		},
		"number field value then object": {
			pp(`1`), pp(`{}`),
		},
		"boolean field value then object": {
			pp(`true`), pp(`{}`),
		},
		"array field value then object": {
			pp(`["enforce"]`), pp(`{}`),
		},
		"object field value then object": {
			pp(`{"nested": 1}`), pp(`{}`),
		},
		"number member first, legal object last": {
			pp(`{"mode": 1}`), pp(`{"mode": "enforce"}`),
		},
		"boolean member first, legal object last": {
			pp(`{"mode": true}`), pp(`{"mode": "enforce"}`),
		},
		"array member first, legal object last": {
			pp(`{"mode": ["x"]}`), pp(`{"mode": "enforce"}`),
		},
		"object member first, legal object last": {
			pp(`{"mode": {"x": 1}}`), pp(`{"mode": "enforce"}`),
		},
		"legal object first, number member last": {
			pp(`{"mode": "enforce"}`), pp(`{"mode": 1}`),
		},
		"null member first, empty object last": {
			pp(`{"mode": null}`), pp(`{}`),
		},
		"empty object first, null member last": {
			pp(`{}`), pp(`{"mode": null}`),
		},
		"illegal middle occurrence among three": {
			pp(`{}`), pp(`{"mode": null}`), pp(`{"mode": "enforce"}`),
		},
		"illegal first object carries an extra member": {
			pp(`{"mode": null, "retries": "3"}`), pp(`{"mode": "enforce"}`),
		},
		"illegal last object, first carries other members": {
			pp(`{"mode": "enforce", "retries": "3"}`), pp(`{"zone": null}`),
		},
		"escaped name null object first, literal legal last": {
			ppEscaped(`{"mode": null}`), pp(`{"mode": "enforce"}`),
		},
		"literal null object first, escaped name legal last": {
			pp(`{"mode": null}`), ppEscaped(`{"mode": "enforce"}`),
		},
		"literal legal first, escaped name null object last": {
			pp(`{"mode": "enforce"}`), ppEscaped(`{"mode": null}`),
		},
	}
	for name, fields := range cases {
		t.Run(name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			body := policyBodyWithParamFields("payments", "default-deny", "tier=backend", fields...)

			recorder := doRequest(router, http.MethodPost, "/v1/net-policies", body)
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

// Re-posting an existing identity with an illegal repeated pluginParams is
// invalid input whether the final legal-looking object matches the stored
// content (never 200) or differs (never 409). The committed record, its order
// and its conflict flag stay untouched, and the next legal new identity keeps
// the sequence.
func TestPostNetPolicyIllegalRepeatedPluginParamsOnExistingIdentity(t *testing.T) {
	cases := map[string][]pluginParamsField{
		"illegal first, last object equal to stored": {
			pp(`{"mode": null}`), pp(`{"mode": "enforce"}`),
		},
		"illegal first, last object differing stored": {
			pp(`{"mode": null}`), pp(`{"mode": "audit"}`),
		},
		"null field value first, last object equal": {
			pp(`null`), pp(`{"mode": "enforce"}`),
		},
		"illegal last object equal except for the hidden member": {
			pp(`{"mode": "enforce", "retries": null}`), pp(`{"mode": "enforce"}`),
		},
		"escaped illegal occurrence, literal last equal": {
			ppEscaped(`{"mode": null}`), pp(`{"mode": "enforce"}`),
		},
	}
	for name, fields := range cases {
		t.Run(name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			// A clashing rule first so the seed record carries conflict=true,
			// which every rejected retry must leave intact.
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
			if seedRecord["order"] != float64(2) || seedRecord["conflict"] != true {
				t.Fatalf("seed metadata = order %v conflict %v, want order 2 conflict true",
					seedRecord["order"], seedRecord["conflict"])
			}

			retry := doRequest(router, http.MethodPost, "/v1/net-policies",
				policyBodyWithParamFields("payments", "default-deny", "tier=backend", fields...))
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

			// The rejected retries consumed no order: the next fresh identity
			// continues at max order + 1.
			next := doRequest(router, http.MethodPost, "/v1/net-policies",
				policyBody("payments", "after-reject", "tier=backend", `{}`))
			if next.Code != http.StatusCreated {
				t.Fatalf("next status = %d, want %d: %s", next.Code, http.StatusCreated, next.Body.String())
			}
			var nextRecord map[string]any
			json.Unmarshal(next.Body.Bytes(), &nextRecord)
			if nextRecord["order"] != float64(3) {
				t.Fatalf("next order = %v, want 3", nextRecord["order"])
			}
		})
	}
}

// When every repeated pluginParams occurrence is a legal string object the
// request stays valid: the LAST complete object is registered without merging
// members from earlier objects, an empty last object is saved as {}, and empty
// or whitespace-only strings in the last object are preserved verbatim. Both
// the registration response and GET queries expose only the final object.
func TestPostNetPolicyLegalRepeatedPluginParamsLastObjectWins(t *testing.T) {
	cases := map[string]struct {
		identity string
		fields   []pluginParamsField
		want     map[string]any
	}{
		"distinct members are not merged": {
			"no-merge",
			[]pluginParamsField{
				pp(`{"mode": "audit", "zone": "east"}`),
				pp(`{"mode": "enforce"}`),
			},
			map[string]any{"mode": "enforce"},
		},
		"empty object last saves empty object": {
			"empty-last",
			[]pluginParamsField{pp(`{"mode": "enforce"}`), pp(`{}`)},
			map[string]any{},
		},
		"empty object first keeps later members": {
			"empty-first",
			[]pluginParamsField{pp(`{}`), pp(`{"mode": "enforce"}`)},
			map[string]any{"mode": "enforce"},
		},
		"same members take last object values": {
			"same-members",
			[]pluginParamsField{
				pp(`{"mode": "audit", "retries": "1"}`),
				pp(`{"mode": "enforce", "retries": "5"}`),
			},
			map[string]any{"mode": "enforce", "retries": "5"},
		},
		"last object keeps empty and whitespace values": {
			"special-values",
			[]pluginParamsField{
				pp(`{"mode": "enforce"}`),
				pp(`{"mode": "  ", "zone": ""}`),
			},
			map[string]any{"mode": "  ", "zone": ""},
		},
		"escaped spelling of a legal occurrence": {
			"escaped-key",
			[]pluginParamsField{
				ppEscaped(`{"zone": "east"}`),
				pp(`{"mode": "enforce"}`),
			},
			map[string]any{"mode": "enforce"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
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
			if resp["order"] != float64(1) {
				t.Fatalf("order = %v, want 1", resp["order"])
			}
			if !reflect.DeepEqual(resp["pluginParams"], tc.want) {
				t.Fatalf("response pluginParams = %v, want %v (only the last object)", resp["pluginParams"], tc.want)
			}

			items := listItems(t, router, "/v1/net-policies?namespace=payments")
			if len(items) != 1 || !reflect.DeepEqual(items[0]["pluginParams"], tc.want) {
				t.Fatalf("stored pluginParams = %v, want %v (only the last object)", items, tc.want)
			}
		})
	}
}

// An identity first registered from repeated legal objects behaves like any
// other record: a retry whose single object matches the final content returns
// 200 with the original record without consuming an order, different final
// content returns 409 NetPolicyConflictError, and the following fresh identity
// takes the next order. GET always shows only the last object's parameters.
func TestPostNetPolicyLegalRepeatedPluginParamsRetryConflictAndOrder(t *testing.T) {
	router, _ := newTestRouter(t)
	seedBody := policyBodyWithParamFields("payments", "default-deny", "tier=backend",
		pp(`{"mode": "audit", "zone": "east"}`),
		pp(`{"mode": "enforce"}`))
	seed := doRequest(router, http.MethodPost, "/v1/net-policies", seedBody)
	if seed.Code != http.StatusCreated {
		t.Fatalf("seed status = %d: %s", seed.Code, seed.Body.String())
	}
	var seedRecord map[string]any
	if err := json.Unmarshal(seed.Body.Bytes(), &seedRecord); err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	if !reflect.DeepEqual(seedRecord["pluginParams"], map[string]any{"mode": "enforce"}) {
		t.Fatalf("seed pluginParams = %v, want only the last object {mode:enforce}", seedRecord["pluginParams"])
	}

	// Same final content, spelled as a single object this time: 200 original.
	same := doRequest(router, http.MethodPost, "/v1/net-policies",
		policyBody("payments", "default-deny", "tier=backend", `{"mode": "enforce"}`))
	if same.Code != http.StatusOK {
		t.Fatalf("same-content retry status = %d, want %d: %s", same.Code, http.StatusOK, same.Body.String())
	}
	var sameRecord map[string]any
	json.Unmarshal(same.Body.Bytes(), &sameRecord)
	if !reflect.DeepEqual(sameRecord, seedRecord) {
		t.Fatalf("retry record = %v, want original %v", sameRecord, seedRecord)
	}

	// Different final content: 409, record untouched.
	diff := doRequest(router, http.MethodPost, "/v1/net-policies",
		policyBody("payments", "default-deny", "tier=backend", `{"mode": "audit"}`))
	if diff.Code != http.StatusConflict {
		t.Fatalf("different-content retry status = %d, want %d: %s", diff.Code, http.StatusConflict, diff.Body.String())
	}
	assertErrorCode(t, diff, "NetPolicyConflictError")

	items := listItems(t, router, "/v1/net-policies?namespace=payments")
	if len(items) != 1 || !reflect.DeepEqual(items[0], seedRecord) {
		t.Fatalf("items after retries = %v, want the unchanged seed %v", items, seedRecord)
	}

	// Neither retry consumed an order: the next fresh identity takes order 2.
	next := doRequest(router, http.MethodPost, "/v1/net-policies",
		policyBodyWithParamFields("payments", "after", "tier=backend",
			pp(`{"mode": "audit"}`), pp(`{}`)))
	if next.Code != http.StatusCreated {
		t.Fatalf("next status = %d: %s", next.Code, next.Body.String())
	}
	var nextRecord map[string]any
	json.Unmarshal(next.Body.Bytes(), &nextRecord)
	if nextRecord["order"] != float64(2) {
		t.Fatalf("next order = %v, want 2", nextRecord["order"])
	}
	if !reflect.DeepEqual(nextRecord["pluginParams"], map[string]any{}) {
		t.Fatalf("next pluginParams = %v, want empty last object {}", nextRecord["pluginParams"])
	}
}
