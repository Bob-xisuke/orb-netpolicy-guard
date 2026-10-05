package api

// Registration-boundary system regressions around identity retries, content
// conflicts, illegal rule input and sequence numbering:
//
//   - the same identity with the same content retries with 200 and the
//     original record,
//   - the same identity with changed rule order or a changed plugin string
//     value is rejected with 409 NetPolicyConflictError,
//   - port 0, port 65536, a reversed interval and an illegal direction are
//     rejected with 400 InvalidNetPolicyInputError,
//   - rejected requests and same-content retries add no record, change no
//     committed conflict flag and consume no order value; the next legal new
//     record takes the current maximum order plus one,
//   - every error response keeps the published {"error":{code,message}}
//     object with string members,
//   - running the same sequence twice yields identical observations.
//
// Expectations come from README.md only.

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
)

// errorSnapshot records what one failed attempt exposed.
type errorSnapshot struct {
	status int
	code   string
}

// boundarySequenceObservation captures the externally visible results of one
// full boundary sequence; two runs on fresh databases must compare equal.
type boundarySequenceObservation struct {
	retryStatus int
	retryRecord map[string]any
	failures    []errorSnapshot
	items       []map[string]any
	nextOrder   float64
}

// Same identity, same content: the retry answers 200 (never 201) with the
// exact stored record — same fields, order and conflict flag — even when the
// JSON object keys are reordered and pluginParams members appear in a
// different order. Consuming no order is proved by the next record.
func TestRegisterSameIdentitySameContentRetryReturns200Original(t *testing.T) {
	router := newMatrixRouter(t)

	seedBody := policyWithRules("payments", "default-policy", "tier=backend", `[
		{"direction": "ingress", "action": "deny", "ports": [80, 100]},
		{"direction": "egress",  "action": "allow", "ports": [53, 53]}
	]`, `{"zone": "east", "mode": "enforce"}`)
	seed := registerCreated(t, router, seedBody, 1, false)

	retryBody := `{
		"pluginParams": {"mode": "enforce", "zone": "east"},
		"rules": [
			{"ports": [80, 100], "action": "deny", "direction": "ingress"},
			{"ports": [53, 53],  "action": "allow", "direction": "egress"}
		],
		"label": "tier=backend",
		"name": "default-policy",
		"namespace": "payments"
	}`
	retry := doRequest(router, http.MethodPost, "/v1/net-policies", retryBody)
	if retry.Code != http.StatusOK {
		t.Fatalf("input: same identity/name, identical content, reordered JSON keys\nstatus = %d, want %d: %s",
			retry.Code, http.StatusOK, retry.Body.String())
	}
	var retryRecord map[string]any
	if err := json.Unmarshal(retry.Body.Bytes(), &retryRecord); err != nil {
		t.Fatalf("decode retry: %v", err)
	}
	if !reflect.DeepEqual(retryRecord, seed) {
		t.Fatalf("input: same identity/name, identical content\nexpected record = %v\nactual record =   %v", seed, retryRecord)
	}

	// The retry consumed no order: the brand-new policy following it gets 2.
	registerCreated(t, router,
		singleRuleBody("payments", "after-retry", "tier=backend", "ingress", "allow", 200, 200, `{}`),
		2, false)
}

// Same identity but the rule array reordered is different content (rule order
// is significant): 409 NetPolicyConflictError with the published error shape,
// and the stored record stays untouched.
func TestRegisterSameIdentityChangedRuleOrderReturns409(t *testing.T) {
	router := newMatrixRouter(t)
	seedBody := policyWithRules("payments", "ordered", "tier=backend", `[
		{"direction": "ingress", "action": "deny", "ports": [1, 100]},
		{"direction": "egress",  "action": "allow", "ports": [53, 53]}
	]`, `{}`)
	seed := registerCreated(t, router, seedBody, 1, false)

	swapped := policyWithRules("payments", "ordered", "tier=backend", `[
		{"direction": "egress",  "action": "allow", "ports": [53, 53]},
		{"direction": "ingress", "action": "deny", "ports": [1, 100]}
	]`, `{}`)
	recorder := doRequest(router, http.MethodPost, "/v1/net-policies", swapped)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("input: same identity, rules array order swapped\nstatus = %d, want %d: %s",
			recorder.Code, http.StatusConflict, recorder.Body.String())
	}
	assertExactErrorShape(t, recorder, "NetPolicyConflictError")
	assertSafeErrorMessage(t, recorder)

	items := listItems(t, router, "/v1/net-policies?namespace=payments")
	if len(items) != 1 || !reflect.DeepEqual(items[0], seed) {
		t.Fatalf("expected the single original record %v\nactual items = %v", seed, items)
	}
}

// Same identity but a pluginParams string value changed is different content:
// 409 NetPolicyConflictError; the stored plugin value is preserved.
func TestRegisterSameIdentityChangedPluginStringValueReturns409(t *testing.T) {
	router := newMatrixRouter(t)
	seed := registerCreated(t, router,
		singleRuleBody("payments", "default-policy", "tier=backend", "ingress", "deny", 80, 100,
			`{"mode":"enforce"}`), 1, false)

	changed := singleRuleBody("payments", "default-policy", "tier=backend", "ingress", "deny", 80, 100,
		`{"mode":"audit"}`)
	recorder := doRequest(router, http.MethodPost, "/v1/net-policies", changed)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("input: same identity, pluginParams mode changed enforce -> audit\nstatus = %d, want %d: %s",
			recorder.Code, http.StatusConflict, recorder.Body.String())
	}
	assertExactErrorShape(t, recorder, "NetPolicyConflictError")
	assertSafeErrorMessage(t, recorder)

	items := listItems(t, router, "/v1/net-policies?namespace=payments")
	if len(items) != 1 || !reflect.DeepEqual(items[0], seed) {
		t.Fatalf("expected unchanged original %v\nactual items = %v", seed, items)
	}
}

// Illegal rule inputs on brand-new identities are rejected with 400
// InvalidNetPolicyInputError: port 0, port 65536 (as the upper endpoint or on
// both endpoints), a reversed interval and an illegal direction. None adds a
// record or consumes an order value.
func TestRegisterInvalidPortsAndDirectionReturn400(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"port zero", singleRuleBody("payments", "bad-zero", "tier=backend", "ingress", "allow", 0, 80, `{}`)},
		{"both endpoints zero", singleRuleBody("payments", "bad-zero-both", "tier=backend", "ingress", "allow", 0, 0, `{}`)},
		{"port 65536 upper", singleRuleBody("payments", "bad-high", "tier=backend", "ingress", "allow", 1, 65536, `{}`)},
		{"port 65536 both endpoints", singleRuleBody("payments", "bad-high-both", "tier=backend", "ingress", "allow", 65536, 65536, `{}`)},
		{"reversed interval", singleRuleBody("payments", "bad-reversed", "tier=backend", "ingress", "allow", 443, 80, `{}`)},
		{"illegal direction", singleRuleBody("payments", "bad-direction", "tier=backend", "sideways", "allow", 80, 80, `{}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router := newMatrixRouter(t)
			recorder := doRequest(router, http.MethodPost, "/v1/net-policies", tc.body)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("input: %s\nstatus = %d, want %d: %s",
					tc.body, recorder.Code, http.StatusBadRequest, recorder.Body.String())
			}
			assertExactErrorShape(t, recorder, "InvalidNetPolicyInputError")
			assertSafeErrorMessage(t, recorder)

			// No record was written: the namespace still misses with 404
			// NetPolicyNotFoundError.
			miss := doRequest(router, http.MethodGet, "/v1/net-policies?namespace=payments", "")
			if miss.Code != http.StatusNotFound {
				t.Fatalf("rejected input left records behind: GET status = %d, want %d",
					miss.Code, http.StatusNotFound)
			}
			assertExactErrorShape(t, miss, "NetPolicyNotFoundError")

			// The rejected registration consumed no order: a legal follow-up
			// starts at 1.
			registerCreated(t, router,
				singleRuleBody("payments", "after", "tier=backend", "ingress", "allow", 80, 80, `{}`),
				1, false)
		})
	}
}

// The combined registry-invariant sequence: invalid attempts (400), content
// conflicts (409) and a same-content retry (200) interleave with committed
// records, yet add no row, change no committed field or conflict flag and
// consume no order; the first legal new identity afterwards takes the current
// maximum order plus one. The same sequence run twice produces identical
// observations.
func TestRejectedAndRetriedRegistrationsLeaveRegistryUntouched(t *testing.T) {
	observe := func(t *testing.T) boundarySequenceObservation {
		router := newMatrixRouter(t)

		// Three committed records. The second genuinely clashes with the first
		// (conflict=true); the third carries multiple rules on disjoint ports
		// and directions so its rule order can later be "changed".
		deny := registerCreated(t, router,
			singleRuleBody("payments", "deny-web", "tier=backend", "ingress", "deny", 80, 100,
				`{"mode":"enforce"}`), 1, false)
		allow := registerCreated(t, router,
			singleRuleBody("payments", "allow-web", "tier=backend", "ingress", "allow", 100, 200,
				`{"mode":"enforce"}`), 2, true)
		ordered := registerCreated(t, router,
			policyWithRules("payments", "ordered-policy", "tier=backend", `[
				{"direction": "egress",  "action": "deny",  "ports": [4000, 4001]},
				{"direction": "ingress", "action": "allow", "ports": [7000, 7001]}
			]`, `{}`), 3, false)
		committed := []map[string]any{deny, allow, ordered}

		obs := boundarySequenceObservation{}

		// Invalid inputs on fresh identities: 400 InvalidNetPolicyInputError.
		invalid := []string{
			singleRuleBody("payments", "bad-zero", "tier=backend", "ingress", "allow", 0, 80, `{}`),
			singleRuleBody("payments", "bad-high", "tier=backend", "ingress", "allow", 1, 65536, `{}`),
			singleRuleBody("payments", "bad-reversed", "tier=backend", "ingress", "allow", 443, 80, `{}`),
			singleRuleBody("payments", "bad-direction", "tier=backend", "sideways", "allow", 80, 80, `{}`),
		}
		for i, body := range invalid {
			recorder := doRequest(router, http.MethodPost, "/v1/net-policies", body)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("invalid case %d input: %s\nstatus = %d, want %d: %s",
					i, body, recorder.Code, http.StatusBadRequest, recorder.Body.String())
			}
			assertExactErrorShape(t, recorder, "InvalidNetPolicyInputError")
			assertSafeErrorMessage(t, recorder)
			obs.failures = append(obs.failures, errorSnapshot{recorder.Code, "InvalidNetPolicyInputError"})
		}

		// Changed content on existing identities: the plugin string value of
		// deny-web and the rule order of ordered-policy — both 409
		// NetPolicyConflictError.
		pluginChanged := singleRuleBody("payments", "deny-web", "tier=backend",
			"ingress", "deny", 80, 100, `{"mode":"audit"}`)
		ruleOrderChanged := policyWithRules("payments", "ordered-policy", "tier=backend", `[
			{"direction": "ingress", "action": "allow", "ports": [7000, 7001]},
			{"direction": "egress",  "action": "deny",  "ports": [4000, 4001]}
		]`, `{}`)
		for i, body := range []string{pluginChanged, ruleOrderChanged} {
			recorder := doRequest(router, http.MethodPost, "/v1/net-policies", body)
			if recorder.Code != http.StatusConflict {
				t.Fatalf("content-conflict case %d input: %s\nstatus = %d, want %d: %s",
					i, body, recorder.Code, http.StatusConflict, recorder.Body.String())
			}
			assertExactErrorShape(t, recorder, "NetPolicyConflictError")
			assertSafeErrorMessage(t, recorder)
			obs.failures = append(obs.failures, errorSnapshot{recorder.Code, "NetPolicyConflictError"})
		}

		// Same-content retry of allow-web (top-level keys and rules-object keys
		// reordered, same content): 200 with the original record.
		retryBody := `{
			"pluginParams": {"mode": "enforce"},
			"rules": [{"ports": [100, 200], "action": "allow", "direction": "ingress"}],
			"label": "tier=backend",
			"name": "allow-web",
			"namespace": "payments"
		}`
		retry := doRequest(router, http.MethodPost, "/v1/net-policies", retryBody)
		if retry.Code != http.StatusOK {
			t.Fatalf("same-content retry status = %d, want %d: %s",
				retry.Code, http.StatusOK, retry.Body.String())
		}
		obs.retryStatus = retry.Code
		if err := json.Unmarshal(retry.Body.Bytes(), &obs.retryRecord); err != nil {
			t.Fatalf("decode retry: %v", err)
		}
		if !reflect.DeepEqual(obs.retryRecord, allow) {
			t.Fatalf("expected retry to return the original record %v\nactual = %v", allow, obs.retryRecord)
		}

		// Committed state is exactly the three original records, fields and
		// flags intact, in ascending order.
		obs.items = listItems(t, router, "/v1/net-policies?namespace=payments")
		if !reflect.DeepEqual(obs.items, committed) {
			t.Fatalf("expected committed records %v\nactual = %v (rejections and retries must change nothing)",
				committed, obs.items)
		}

		// The next legal new identity gets the current maximum order (3) + 1 = 4.
		// A fresh label keeps it conflict-free on purpose.
		next := registerCreated(t, router,
			singleRuleBody("payments", "after-all", "tier=frontend", "egress", "allow", 53, 53, `{}`),
			4, false)
		obs.nextOrder, _ = next["order"].(float64)
		if obs.nextOrder != 4 {
			t.Fatalf("next record order = %v, want 4 (rejected and retried requests consume no order)",
				obs.nextOrder)
		}
		return obs
	}

	first := observe(t)

	// Repetition on a fresh database must produce identical externally visible
	// results.
	second := observe(t)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("boundary sequence is not deterministic\nfirst run:  %#v\nsecond run: %#v", first, second)
	}
}
