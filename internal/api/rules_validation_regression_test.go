package api

// Regression coverage for the rules input validation published in README.md.
//
// These tests drive only the public HTTP surface (POST /v1/net-policies and
// GET /v1/net-policies); they never touch the storage layer directly. Every
// malformed rules value must be rejected with HTTP 400
// InvalidNetPolicyInputError, with exactly the published error envelope and a
// message that leaks no SQL, stack trace or file path, and must neither write a
// row nor consume an order. The rejection is identical for a brand-new identity
// and for an identity that already holds a record: an existing row can never
// turn an invalid request into a 200 retry or a 409 content conflict.
//
// Namespace, policy name, label and pluginParams always carry legal values, so
// a failure can only correspond to the rules input.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
)

// rulesFieldBody builds a registration body whose rules field is an arbitrary
// raw JSON fragment; every other field is a legal value.
func rulesFieldBody(ns, name, label, rulesFragment string) string {
	return policyWithRules(ns, name, label, rulesFragment, `{"mode": "enforce"}`)
}

// rulesBody builds a body with an explicit rules JSON array fragment.
func rulesBody(ns, name, label, rulesArray string) string {
	return rulesFieldBody(ns, name, label, rulesArray)
}

// joinJSON joins raw JSON fragments with commas.
func joinJSON(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}

// invalidRulesResponse runs one POST and asserts the full rejection contract:
// 400, the exact published error envelope, and a leak-free message.
func invalidRulesResponse(t *testing.T, router *gin.Engine, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := doRequest(router, http.MethodPost, "/v1/net-policies", body)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	assertExactErrorShape(t, recorder, "InvalidNetPolicyInputError")
	assertSafeErrorMessage(t, recorder)
	return recorder
}

// TestRulesValidationRejectsWrongTopLevelShape covers rules that is not the
// required non-empty JSON array: a string, a number, a boolean, an object or
// null. None may be coerced into an array and none may write a record.
func TestRulesValidationRejectsWrongTopLevelShape(t *testing.T) {
	cases := map[string]string{
		"rules as string":  `"ingress"`,
		"rules as integer": `1`,
		"rules as decimal": `1.5`,
		"rules as true":    `true`,
		"rules as false":   `false`,
		"rules as object":  `{"direction": "ingress", "action": "allow", "ports": [80, 80]}`,
		"rules as null":    `null`,
	}
	for name, fragment := range cases {
		t.Run(name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			body := rulesFieldBody("payments", "bad-rules", "tier=backend", fragment)
			invalidRulesResponse(t, router, body)

			for _, target := range []string{
				"/v1/net-policies?namespace=payments",
				"/v1/net-policies?label=tier%3Dbackend",
			} {
				miss := doRequest(router, http.MethodGet, target, "")
				if miss.Code != http.StatusNotFound {
					t.Fatalf("GET %s after reject status = %d, want %d", target, miss.Code, http.StatusNotFound)
				}
				assertExactErrorShape(t, miss, "NetPolicyNotFoundError")
			}
		})
	}
}

// TestRulesValidationRejectsNonObjectArrayMembers covers array members that are
// not rule objects: null, a scalar (string/number/boolean) or a nested array.
// The illegal member is placed first, in the middle and last, with every other
// member legal: no illegal member may be ignored or coerced into a rule.
func TestRulesValidationRejectsNonObjectArrayMembers(t *testing.T) {
	legal := `{"direction": "ingress", "action": "allow", "ports": [80, 80]}`
	illegal := map[string]string{
		"member null":         `null`,
		"member string":       `"ingress"`,
		"member number":       `7`,
		"member boolean":      `true`,
		"member nested array": `[80, 80]`,
	}
	placements := map[string][]string{
		// First, middle (of three) and last placement.
		"first":  {"ILLEGAL", legal, legal},
		"middle": {legal, "ILLEGAL", legal},
		"last":   {legal, legal, "ILLEGAL"},
	}
	for name, value := range illegal {
		for placement, members := range placements {
			t.Run(name+" at "+placement, func(t *testing.T) {
				router, _ := newTestRouter(t)
				filled := make([]string, len(members))
				for i, m := range members {
					if m == "ILLEGAL" {
						filled[i] = value
					} else {
						filled[i] = m
					}
				}
				body := rulesBody("payments", "bad-member", "tier=backend",
					"["+joinJSON(filled)+"]")
				invalidRulesResponse(t, router, body)

				miss := doRequest(router, http.MethodGet, "/v1/net-policies?namespace=payments", "")
				if miss.Code != http.StatusNotFound {
					t.Fatalf("rejected array left records behind: GET status = %d, body %s",
						miss.Code, miss.Body.String())
				}
				assertExactErrorShape(t, miss, "NetPolicyNotFoundError")
			})
		}
	}
}

// TestRulesValidationRejectsMissingRuleFields covers a rule object that omits
// direction, action or ports, alone or sitting among legal rules.
func TestRulesValidationRejectsMissingRuleFields(t *testing.T) {
	legal := `{"direction": "ingress", "action": "allow", "ports": [80, 80]}`
	cases := map[string][]string{
		"missing direction alone": {`{"action": "allow", "ports": [80, 80]}`},
		"missing action alone":    {`{"direction": "ingress", "ports": [80, 80]}`},
		"missing ports alone":     {`{"direction": "ingress", "action": "allow"}`},
		"empty rule object":       {`{}`},
		"missing direction among legal, first": {
			`{"action": "allow", "ports": [80, 80]}`, legal,
		},
		"missing action among legal, middle": {
			legal, `{"direction": "ingress", "ports": [80, 80]}`, legal,
		},
		"missing ports among legal, last": {
			legal, `{"direction": "ingress", "action": "allow"}`,
		},
	}
	for name, members := range cases {
		t.Run(name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			body := rulesBody("payments", "missing-field", "tier=backend",
				"["+joinJSON(members)+"]")
			invalidRulesResponse(t, router, body)

			miss := doRequest(router, http.MethodGet, "/v1/net-policies?namespace=payments", "")
			if miss.Code != http.StatusNotFound {
				t.Fatalf("rejected rule left records behind: GET status = %d, body %s",
					miss.Code, miss.Body.String())
			}
		})
	}
}

// TestRulesValidationRejectsBadDirectionAndAction covers non-string,
// wrongly-cased and unknown values for direction and action. They are rejected
// rather than case-folded or defaulted.
func TestRulesValidationRejectsBadDirectionAndAction(t *testing.T) {
	directions := map[string]string{
		"direction null":    `null`,
		"direction number":  `7`,
		"direction boolean": `true`,
		"direction array":   `["ingress"]`,
		"direction object":  `{"value": "ingress"}`,
		"direction upper":   `"INGRESS"`,
		"direction mixed":   `"Ingress"`,
		"direction unknown": `"sideways"`,
		"direction empty":   `""`,
	}
	actions := map[string]string{
		"action null":    `null`,
		"action number":  `7`,
		"action boolean": `false`,
		"action array":   `["allow"]`,
		"action object":  `{"value": "allow"}`,
		"action upper":   `"ALLOW"`,
		"action mixed":   `"Allow"`,
		"action unknown": `"permit"`,
		"action empty":   `""`,
	}
	ruleWith := func(directionJSON, actionJSON string) string {
		return fmt.Sprintf(
			`[{"direction": %s, "action": %s, "ports": [80, 80]}]`,
			directionJSON, actionJSON)
	}
	for name, value := range directions {
		t.Run(name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			body := rulesBody("payments", "bad-direction", "tier=backend",
				ruleWith(value, `"allow"`))
			invalidRulesResponse(t, router, body)
		})
	}
	for name, value := range actions {
		t.Run(name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			body := rulesBody("payments", "bad-action", "tier=backend",
				ruleWith(`"ingress"`, value))
			invalidRulesResponse(t, router, body)
		})
	}
}

// TestRulesValidationRejectsWrongPortsShape covers a ports value that is not a
// two-element array: null, scalar, object, empty, or the wrong length.
func TestRulesValidationRejectsWrongPortsShape(t *testing.T) {
	shapes := map[string]string{
		"ports null":    `null`,
		"ports number":  `80`,
		"ports string":  `"80"`,
		"ports boolean": `true`,
		"ports object":  `{"lo": 80, "hi": 80}`,
		"ports empty":   `[]`,
		"ports single":  `[80]`,
		"ports triple":  `[80, 80, 80]`,
	}
	for name, ports := range shapes {
		t.Run(name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			rule := fmt.Sprintf(
				`[{"direction": "ingress", "action": "allow", "ports": %s}]`, ports)
			body := rulesBody("payments", "bad-ports", "tier=backend", rule)
			invalidRulesResponse(t, router, body)
		})
	}
}

// TestRulesValidationRejectsBadPortEndpoints covers a single endpoint that is
// not a representable integer: null, a numeric string, a boolean, an array, an
// object, a decimal fraction (including an integral-looking 80.0), or a number
// beyond the 64-bit signed integer representation. Each bad endpoint is
// exercised at both the lower and the upper position. Nothing is coerced: a
// string never becomes a number, a null never becomes 0, and an out-of-range
// number never wraps.
func TestRulesValidationRejectsBadPortEndpoints(t *testing.T) {
	badEndpoints := map[string]string{
		"endpoint null":               `null`,
		"endpoint numeric string":     `"80"`,
		"endpoint non-numeric string": `"eighty"`,
		"endpoint boolean":            `true`,
		"endpoint array":              `[80]`,
		"endpoint object":             `{"port": 80}`,
		"endpoint decimal fraction":   `1.5`,
		"endpoint integral decimal":   `80.0`,
		// Beyond a 64-bit signed integer: must fail decoding rather than wrap.
		"endpoint beyond int64":  `9223372036854775808`,
		"endpoint huge exponent": `1e100`,
		"endpoint negative int":  `-65536`,
	}
	for name, bad := range badEndpoints {
		for _, position := range []struct {
			label     string
			portsJSON string
		}{
			{"lower endpoint", fmt.Sprintf("[%s, 80]", bad)},
			{"upper endpoint", fmt.Sprintf("[80, %s]", bad)},
		} {
			t.Run(name+" at "+position.label, func(t *testing.T) {
				router, _ := newTestRouter(t)
				rule := fmt.Sprintf(
					`[{"direction": "ingress", "action": "allow", "ports": %s}]`,
					position.portsJSON)
				body := rulesBody("payments", "bad-endpoint", "tier=backend", rule)
				invalidRulesResponse(t, router, body)

				miss := doRequest(router, http.MethodGet, "/v1/net-policies?namespace=payments", "")
				if miss.Code != http.StatusNotFound {
					t.Fatalf("rejected endpoint left records behind: GET status = %d, body %s",
						miss.Code, miss.Body.String())
				}
				assertExactErrorShape(t, miss, "NetPolicyNotFoundError")
			})
		}
	}
}

// TestRulesValidationRejectSameErrorOnFreshAndExistingIdentity verifies the
// central invariant: an invalid rules request fails identically whether the
// identity is brand new or already committed. Two records are committed first
// in the same namespace and label with opposite actions on overlapping ports,
// so they carry different conflict values (false then true). Every rejection
// must afterwards leave exactly those two records — every field, the order
// sequence and the sort order — untouched, and must never surface as a 200
// retry or a 409 conflict.
func TestRulesValidationRejectSameErrorOnFreshAndExistingIdentity(t *testing.T) {
	router, _ := newTestRouter(t)

	firstBody := singleRuleBody("guard", "policy-a", "tier=backend",
		"ingress", "deny", 80, 100, `{"mode": "enforce"}`)
	first := registerCreated(t, router, firstBody, 1, false)
	secondBody := singleRuleBody("guard", "policy-b", "tier=backend",
		"ingress", "allow", 100, 200, `{"zone": "east"}`)
	second := registerCreated(t, router, secondBody, 2, true)
	wantRecords := []map[string]any{first, second}

	// Every malformed body keeps a legal namespace/label/pluginParams; only
	// rules differ. It is posted against both committed identities and one
	// fresh identity.
	bodies := func(name string) map[string]string {
		legalRule := `{"direction": "ingress", "action": "allow", "ports": [80, 80]}`
		otherLegal := `{"direction": "egress", "action": "allow", "ports": [53, 53]}`
		return map[string]string{
			"rules as string":  rulesFieldBody("guard", name, "tier=backend", `"ingress"`),
			"rules as number":  rulesFieldBody("guard", name, "tier=backend", `1`),
			"rules as boolean": rulesFieldBody("guard", name, "tier=backend", `true`),
			"rules as object": rulesFieldBody("guard", name, "tier=backend",
				`{"direction": "ingress", "action": "allow", "ports": [80, 80]}`),
			"null member first": rulesBody("guard", name, "tier=backend",
				"[null, "+legalRule+"]"),
			"null member middle": rulesBody("guard", name, "tier=backend",
				"["+legalRule+", null, "+otherLegal+"]"),
			"null member last": rulesBody("guard", name, "tier=backend",
				"["+legalRule+", null]"),
			"scalar member first": rulesBody("guard", name, "tier=backend",
				`["ingress", `+legalRule+"]"),
			"array member last": rulesBody("guard", name, "tier=backend",
				"["+legalRule+`, [80, 80]]`),
			"missing direction": rulesBody("guard", name, "tier=backend",
				`[{"action": "allow", "ports": [80, 80]}]`),
			"missing action": rulesBody("guard", name, "tier=backend",
				`[{"direction": "ingress", "ports": [80, 80]}]`),
			"missing ports": rulesBody("guard", name, "tier=backend",
				`[{"direction": "ingress", "action": "allow"}]`),
			"direction non-string": rulesBody("guard", name, "tier=backend",
				`[{"direction": 7, "action": "allow", "ports": [80, 80]}]`),
			"direction wrong case": rulesBody("guard", name, "tier=backend",
				`[{"direction": "INGRESS", "action": "allow", "ports": [80, 80]}]`),
			"direction unknown": rulesBody("guard", name, "tier=backend",
				`[{"direction": "sideways", "action": "allow", "ports": [80, 80]}]`),
			"action non-string": rulesBody("guard", name, "tier=backend",
				`[{"direction": "ingress", "action": true, "ports": [80, 80]}]`),
			"action wrong case": rulesBody("guard", name, "tier=backend",
				`[{"direction": "ingress", "action": "ALLOW", "ports": [80, 80]}]`),
			"action unknown": rulesBody("guard", name, "tier=backend",
				`[{"direction": "ingress", "action": "permit", "ports": [80, 80]}]`),
			"ports non-array": rulesBody("guard", name, "tier=backend",
				`[{"direction": "ingress", "action": "allow", "ports": 80}]`),
			"port null": rulesBody("guard", name, "tier=backend",
				`[{"direction": "ingress", "action": "allow", "ports": [null, 80]}]`),
			"port numeric string": rulesBody("guard", name, "tier=backend",
				`[{"direction": "ingress", "action": "allow", "ports": ["80", 80]}]`),
			"port boolean": rulesBody("guard", name, "tier=backend",
				`[{"direction": "ingress", "action": "allow", "ports": [80, false]}]`),
			"port array": rulesBody("guard", name, "tier=backend",
				`[{"direction": "ingress", "action": "allow", "ports": [[80], 80]}]`),
			"port object": rulesBody("guard", name, "tier=backend",
				`[{"direction": "ingress", "action": "allow", "ports": [80, {"x": 1}]}]`),
			"port decimal": rulesBody("guard", name, "tier=backend",
				`[{"direction": "ingress", "action": "allow", "ports": [1.5, 80]}]`),
			"port beyond int64": rulesBody("guard", name, "tier=backend",
				`[{"direction": "ingress", "action": "allow", "ports": [80, 9223372036854775808]}]`),
		}
	}

	for _, identity := range []string{"policy-a", "policy-b", "policy-x-fresh"} {
		for caseName, body := range bodies(identity) {
			t.Run(identity+" / "+caseName, func(t *testing.T) {
				recorder := doRequest(router, http.MethodPost, "/v1/net-policies", body)
				if recorder.Code != http.StatusBadRequest {
					t.Fatalf("identity %s, %s: status = %d, want %d (existing records must not turn this into 200 or 409): %s",
						identity, caseName, recorder.Code, http.StatusBadRequest, recorder.Body.String())
				}
				assertExactErrorShape(t, recorder, "InvalidNetPolicyInputError")
				assertSafeErrorMessage(t, recorder)

				// Every rejection leaves only the two original records,
				// identical and order-ascending.
				items := listItems(t, router, "/v1/net-policies?namespace=guard")
				if !reflect.DeepEqual(items, wantRecords) {
					t.Fatalf("identity %s, %s changed the registry:\n items = %#v\n want  %#v",
						identity, caseName, items, wantRecords)
				}
			})
		}
	}

	// The label and intersection queries are unchanged as well, proving the
	// fresh identity rejections wrote nothing.
	items := listItems(t, router, "/v1/net-policies?label=tier%3Dbackend")
	if !reflect.DeepEqual(items, wantRecords) {
		t.Fatalf("label items = %#v, want %#v", items, wantRecords)
	}
	items = listItems(t, router, "/v1/net-policies?namespace=guard&label=tier%3Dbackend")
	if !reflect.DeepEqual(items, wantRecords) {
		t.Fatalf("intersection items = %#v, want %#v", items, wantRecords)
	}
}

// TestRulesValidationIsolatedRejectionThenRecovery uses a namespace and label
// that no record shares: every invalid request queries back as 404
// NetPolicyNotFoundError under both conditions, then correcting the rules
// creates the record with order = previous maximum + 1 and preserves the
// submitted rule order. An identical retry returns 200 with the original, and a
// legal rule change on the same identity is 409 NetPolicyConflictError.
func TestRulesValidationIsolatedRejectionThenRecovery(t *testing.T) {
	router, _ := newTestRouter(t)

	// An unrelated record fixes the current maximum order at 1.
	anchor := singleRuleBody("other-ns", "anchor", "tier=other",
		"egress", "allow", 53, 53, `{}`)
	registerCreated(t, router, anchor, 1, false)

	queryNS := "/v1/net-policies?namespace=" + url.QueryEscape("isolated-ns")
	queryLabel := "/v1/net-policies?label=" + url.QueryEscape("tier=isolated")

	badBodies := []string{
		rulesFieldBody("isolated-ns", "recovered", "tier=isolated", `"allow-all"`),
		rulesBody("isolated-ns", "recovered", "tier=isolated", `[
			{"direction": "ingress", "action": "allow", "ports": [80, 80]},
			{"direction": "ingress", "action": "deny"}
		]`),
		rulesBody("isolated-ns", "recovered", "tier=isolated", `[
			{"direction": "INGRESS", "action": "allow", "ports": [80, 80]}
		]`),
		rulesBody("isolated-ns", "recovered", "tier=isolated", `[
			{"direction": "ingress", "action": "allow", "ports": [80, 9223372036854775808]}
		]`),
	}
	for i, body := range badBodies {
		invalidRulesResponse(t, router, body)
		for _, target := range []string{queryNS, queryLabel} {
			miss := doRequest(router, http.MethodGet, target, "")
			if miss.Code != http.StatusNotFound {
				t.Fatalf("bad body %d: GET %s status = %d, want %d",
					i, target, miss.Code, http.StatusNotFound)
			}
			assertExactErrorShape(t, miss, "NetPolicyNotFoundError")
		}
	}

	// Correct the rules: first registration succeeds at order = max(1) + 1,
	// and the legal rule array is stored in submission order.
	fixedBody := policyWithRules("isolated-ns", "recovered", "tier=isolated", `[
		{"direction": "ingress", "action": "allow", "ports": [80, 100]},
		{"direction": "egress", "action": "deny", "ports": [53, 53]},
		{"direction": "ingress", "action": "deny", "ports": [443, 443]}
	]`, `{"mode": "enforce"}`)
	created := doRequest(router, http.MethodPost, "/v1/net-policies", fixedBody)
	if created.Code != http.StatusCreated {
		t.Fatalf("corrected status = %d, want %d: %s",
			created.Code, http.StatusCreated, created.Body.String())
	}
	var createdRecord map[string]any
	if err := json.Unmarshal(created.Body.Bytes(), &createdRecord); err != nil {
		t.Fatalf("decode created: %v", err)
	}
	if createdRecord["order"] != float64(2) {
		t.Fatalf("order = %v, want 2 (rejected requests must not consume an order)",
			createdRecord["order"])
	}
	wantRules := []any{
		map[string]any{"direction": "ingress", "action": "allow", "ports": []any{float64(80), float64(100)}},
		map[string]any{"direction": "egress", "action": "deny", "ports": []any{float64(53), float64(53)}},
		map[string]any{"direction": "ingress", "action": "deny", "ports": []any{float64(443), float64(443)}},
	}
	if !reflect.DeepEqual(createdRecord["rules"], wantRules) {
		t.Fatalf("rules not stored in submission order:\n got %#v\nwant %#v",
			createdRecord["rules"], wantRules)
	}

	// The created record is returned by both conditions, fields intact.
	if items := listItems(t, router, queryNS); !reflect.DeepEqual(items, []map[string]any{createdRecord}) {
		t.Fatalf("namespace items = %#v, want %#v", items, createdRecord)
	}
	if items := listItems(t, router, queryLabel); !reflect.DeepEqual(items, []map[string]any{createdRecord}) {
		t.Fatalf("label items = %#v, want %#v", items, createdRecord)
	}

	// Identical content retry: 200 with the original record.
	retry := doRequest(router, http.MethodPost, "/v1/net-policies", fixedBody)
	if retry.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want %d: %s",
			retry.Code, http.StatusOK, retry.Body.String())
	}
	var retriedRecord map[string]any
	if err := json.Unmarshal(retry.Body.Bytes(), &retriedRecord); err != nil {
		t.Fatalf("decode retry: %v", err)
	}
	if !reflect.DeepEqual(retriedRecord, createdRecord) {
		t.Fatalf("retry record = %#v, want original %#v", retriedRecord, createdRecord)
	}

	// Same identity with different but legal rules (reordered array): 409,
	// and the committed record stays untouched.
	changedRules := policyWithRules("isolated-ns", "recovered", "tier=isolated", `[
		{"direction": "ingress", "action": "allow", "ports": [80, 100]},
		{"direction": "ingress", "action": "deny", "ports": [443, 443]},
		{"direction": "egress", "action": "deny", "ports": [53, 53]}
	]`, `{"mode": "enforce"}`)
	conflict := doRequest(router, http.MethodPost, "/v1/net-policies", changedRules)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("legal change status = %d, want %d: %s",
			conflict.Code, http.StatusConflict, conflict.Body.String())
	}
	assertExactErrorShape(t, conflict, "NetPolicyConflictError")
	assertSafeErrorMessage(t, conflict)

	if items := listItems(t, router, queryNS); !reflect.DeepEqual(items, []map[string]any{createdRecord}) {
		t.Fatalf("record changed after 409:\n got %#v\nwant %#v", items, createdRecord)
	}
}

// TestRulesValidationLegalBaselineStillSucceeds pins that surrounding legal
// behaviour stays intact: representative legal rules register with 201 and read
// back in ascending order, so the rejection cases above are not failing the
// whole entry. Existing suites cover the full port-range matrix, query decoding
// and GET /healthz; this is a guard local to this file.
func TestRulesValidationLegalBaselineStillSucceeds(t *testing.T) {
	router, _ := newTestRouter(t)
	legalBodies := []string{
		singleRuleBody("payments", "one", "tier=backend", "ingress", "allow", 1, 1, `{}`),
		singleRuleBody("payments", "two", "tier=backend", "egress", "deny", 65535, 65535, `{}`),
		policyWithRules("payments", "three", "tier=frontend", `[
			{"direction": "ingress", "action": "allow", "ports": [80, 80]},
			{"direction": "ingress", "action": "deny", "ports": [81, 81]}
		]`, `{}`),
	}
	var want []map[string]any
	for i, body := range legalBodies {
		want = append(want, registerCreated(t, router, body, int64(i+1), false))
	}
	items := listItems(t, router, "/v1/net-policies?namespace=payments")
	if !reflect.DeepEqual(items, want) {
		t.Fatalf("legal items = %#v, want %#v", items, want)
	}
}
