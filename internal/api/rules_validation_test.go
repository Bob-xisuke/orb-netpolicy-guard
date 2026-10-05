package api

// Rules input validation regression tests: the rules field of POST
// /v1/net-policies must be a non-empty array of rule objects, each carrying a
// direction/action enum string and a two-integer closed port interval. Any
// deviation — a non-array rules field, a non-object member, a missing member,
// a non-string or misspelled enum, a non-array ports field, or a non-integer
// endpoint — is invalid input: 400 InvalidNetPolicyInputError, no type
// coercion, no silently dropped rules, nothing written. Rejections behave the
// same on fresh and existing identities and never disturb committed records.
// Every expectation below is derived from the public contract in README.md,
// never from observed service output.

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
)

// assertInvalidRulesRejected posts the body and requires the published invalid
// input response: 400 with exactly {"error":{"code","message"}} carrying
// InvalidNetPolicyInputError and a message free of SQL, stack or file paths.
func assertInvalidRulesRejected(t *testing.T, router *gin.Engine, body string) {
	t.Helper()
	recorder := doRequest(router, http.MethodPost, "/v1/net-policies", body)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	assertExactErrorShape(t, recorder, "InvalidNetPolicyInputError")
	assertSafeErrorMessage(t, recorder)
}

// assertQueryNotFound requires the GET target to answer 404 with the published
// NetPolicyNotFoundError shape.
func assertQueryNotFound(t *testing.T, router *gin.Engine, target string) {
	t.Helper()
	recorder := doRequest(router, http.MethodGet, target, "")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("GET %s status = %d, want %d: %s", target, recorder.Code, http.StatusNotFound, recorder.Body.String())
	}
	assertExactErrorShape(t, recorder, "NetPolicyNotFoundError")
	assertSafeErrorMessage(t, recorder)
}

// assertFreshIdentityRejectsThenRecovers runs one illegal rules fragment on a
// fresh router: the request is rejected as invalid input, both query
// conditions stay 404 (nothing was written), and the corrected body then
// registers at order 1 — the rejection consumed no order — with the legal
// rules kept in submitted order.
func assertFreshIdentityRejectsThenRecovers(t *testing.T, rulesJSON string) {
	t.Helper()
	router, _ := newTestRouter(t)
	bad := policyWithRules("payments", "default-deny", "tier=backend", rulesJSON, `{"mode": "enforce"}`)
	assertInvalidRulesRejected(t, router, bad)

	assertQueryNotFound(t, router, "/v1/net-policies?namespace=payments")
	assertQueryNotFound(t, router, "/v1/net-policies?label=tier%3Dbackend")

	good := policyWithRules("payments", "default-deny", "tier=backend", `[
		{"direction": "ingress", "action": "deny", "ports": [1, 100]},
		{"direction": "egress", "action": "allow", "ports": [53, 53]}
	]`, `{"mode": "enforce"}`)
	registerCreated(t, router, good, 1, false)
}

// The rules field itself must be a JSON array; a string, number, boolean or
// object is invalid input rather than coerced into a rule list.
func TestPostNetPolicyRejectsNonArrayRulesField(t *testing.T) {
	cases := map[string]string{
		"rules as string":  `"ingress"`,
		"rules as number":  `7`,
		"rules as boolean": `true`,
		"rules as object":  `{"direction": "ingress", "action": "allow", "ports": [80, 80]}`,
	}
	for name, rulesJSON := range cases {
		t.Run(name, func(t *testing.T) {
			assertFreshIdentityRejectsThenRecovers(t, rulesJSON)
		})
	}
}

// Every member of the rules array must be a rule object: null, scalars and
// nested arrays are invalid input, not skippable entries.
func TestPostNetPolicyRejectsNonObjectRuleMembers(t *testing.T) {
	cases := map[string]string{
		"null member":    `[null]`,
		"string member":  `["ingress"]`,
		"number member":  `[7]`,
		"boolean member": `[true]`,
		"array member":   `[["ingress", "allow", 80, 80]]`,
	}
	for name, rulesJSON := range cases {
		t.Run(name, func(t *testing.T) {
			assertFreshIdentityRejectsThenRecovers(t, rulesJSON)
		})
	}
}

// A rule object missing any of direction, action or ports is invalid input.
func TestPostNetPolicyRejectsRuleMissingRequiredField(t *testing.T) {
	cases := map[string]string{
		"missing direction": `[{"action": "allow", "ports": [80, 80]}]`,
		"missing action":    `[{"direction": "ingress", "ports": [80, 80]}]`,
		"missing ports":     `[{"direction": "ingress", "action": "allow"}]`,
		"empty rule object": `[{}]`,
	}
	for name, rulesJSON := range cases {
		t.Run(name, func(t *testing.T) {
			assertFreshIdentityRejectsThenRecovers(t, rulesJSON)
		})
	}
}

// direction and action must be JSON strings drawn exactly from their enums:
// non-string values, wrong casing and unknown strings are all invalid input.
func TestPostNetPolicyRejectsInvalidDirectionAndAction(t *testing.T) {
	rule := func(directionJSON, actionJSON string) string {
		return `[{"direction": ` + directionJSON + `, "action": ` + actionJSON + `, "ports": [80, 80]}]`
	}
	cases := map[string]string{
		"direction number":       rule(`1`, `"allow"`),
		"direction boolean":      rule(`true`, `"allow"`),
		"direction null":         rule(`null`, `"allow"`),
		"direction array":        rule(`["ingress"]`, `"allow"`),
		"direction object":       rule(`{"x": 1}`, `"allow"`),
		"direction wrong case":   rule(`"Ingress"`, `"allow"`),
		"direction upper case":   rule(`"INGRESS"`, `"allow"`),
		"direction unknown":      rule(`"sideways"`, `"allow"`),
		"direction empty string": rule(`""`, `"allow"`),
		"action number":          rule(`"ingress"`, `0`),
		"action boolean":         rule(`"ingress"`, `false`),
		"action null":            rule(`"ingress"`, `null`),
		"action array":           rule(`"ingress"`, `["allow"]`),
		"action object":          rule(`"ingress"`, `{"x": 1}`),
		"action wrong case":      rule(`"ingress"`, `"Allow"`),
		"action upper case":      rule(`"ingress"`, `"DENY"`),
		"action unknown":         rule(`"ingress"`, `"permit"`),
		"action empty string":    rule(`"ingress"`, `""`),
	}
	for name, rulesJSON := range cases {
		t.Run(name, func(t *testing.T) {
			assertFreshIdentityRejectsThenRecovers(t, rulesJSON)
		})
	}
}

// ports must be an array; anything else is invalid input.
func TestPostNetPolicyRejectsNonArrayPorts(t *testing.T) {
	rule := func(portsJSON string) string {
		return `[{"direction": "ingress", "action": "allow", "ports": ` + portsJSON + `}]`
	}
	cases := map[string]string{
		"ports as string":  rule(`"80-90"`),
		"ports as number":  rule(`80`),
		"ports as boolean": rule(`true`),
		"ports as null":    rule(`null`),
		"ports as object":  rule(`{"lo": 80, "hi": 90}`),
	}
	for name, rulesJSON := range cases {
		t.Run(name, func(t *testing.T) {
			assertFreshIdentityRejectsThenRecovers(t, rulesJSON)
		})
	}
}

// Each port endpoint must be a JSON integer: null, numeric strings, booleans,
// arrays, objects, decimals and numbers beyond integer representation are
// invalid input at either endpoint — never coerced, never dropped.
func TestPostNetPolicyRejectsNonIntegerPortEndpoints(t *testing.T) {
	rule := func(portsJSON string) string {
		return `[{"direction": "ingress", "action": "allow", "ports": ` + portsJSON + `}]`
	}
	cases := map[string]string{
		"start null":              rule(`[null, 80]`),
		"end null":                rule(`[80, null]`),
		"start numeric string":    rule(`["80", 90]`),
		"end numeric string":      rule(`[80, "90"]`),
		"start boolean":           rule(`[true, 80]`),
		"end boolean":             rule(`[80, false]`),
		"start array":             rule(`[[80], 90]`),
		"end array":               rule(`[80, [90]]`),
		"start object":            rule(`[{"p": 80}, 90]`),
		"end object":              rule(`[80, {"p": 90}]`),
		"start decimal":           rule(`[80.5, 90]`),
		"end decimal":             rule(`[80, 90.5]`),
		"start beyond int64":      rule(`[9223372036854775808, 90]`),
		"end beyond int64":        rule(`[80, 9223372036854775808]`),
		"start exponent overflow": rule(`[1e30, 90]`),
		"end exponent overflow":   rule(`[80, 1e30]`),
	}
	for name, rulesJSON := range cases {
		t.Run(name, func(t *testing.T) {
			assertFreshIdentityRejectsThenRecovers(t, rulesJSON)
		})
	}
}

// An illegal member rejects the whole request wherever it sits in the rules
// array — first, middle or last — even when every other member is legal: the
// illegal rule is never ignored and the legal ones never partially committed.
func TestPostNetPolicyRejectsIllegalRuleAtAnyPosition(t *testing.T) {
	legalIngress := `{"direction": "ingress", "action": "allow", "ports": [80, 80]}`
	legalEgress := `{"direction": "egress", "action": "deny", "ports": [53, 53]}`
	illegal := `{"direction": "sideways", "action": "allow", "ports": [80, 80]}`
	cases := map[string]string{
		"illegal first":  `[` + illegal + `, ` + legalIngress + `, ` + legalEgress + `]`,
		"illegal middle": `[` + legalIngress + `, ` + illegal + `, ` + legalEgress + `]`,
		"illegal last":   `[` + legalIngress + `, ` + legalEgress + `, ` + illegal + `]`,
	}
	for name, rulesJSON := range cases {
		t.Run(name, func(t *testing.T) {
			assertFreshIdentityRejectsThenRecovers(t, rulesJSON)
		})
	}
}

// Illegal rules are rejected identically whether the identity is brand new or
// already committed: never a retry success (200) and never a content conflict
// (409). Two committed policies in the same namespace and label — carrying
// different conflict values — stay byte-for-byte intact through every
// rejection, and an isolated namespace/label pair stays 404. Once the rules
// are fixed the fresh identity registers at max order + 1 with the rules kept
// in submitted order; a same-content retry returns 200 with the original
// record and a legal rule change on the same identity returns 409.
func TestRejectedRulesKeepCommittedRecordsUntouched(t *testing.T) {
	router, _ := newTestRouter(t)

	// Same namespace, same label, clashing rules: the records carry different
	// conflict values (false then true) that rejections must not disturb.
	deny := registerCreated(t, router,
		singleRuleBody("payments", "default-deny", "tier=backend", "ingress", "deny", 80, 100, `{"mode": "enforce"}`),
		1, false)
	allow := registerCreated(t, router,
		singleRuleBody("payments", "allow-web", "tier=backend", "ingress", "allow", 100, 200, `{"mode": "enforce"}`),
		2, true)

	illegalRules := `[{"direction": "ingress", "action": "allow", "ports": ["80", 90]}]`
	cases := map[string]string{
		// A fresh identity with illegal rules: 400, never 201.
		"fresh identity": policyWithRules("payments", "new-policy", "tier=backend", illegalRules, `{}`),
		// An existing identity with illegal rules: 400, never 200 or 409.
		"existing identity": policyWithRules("payments", "default-deny", "tier=backend", illegalRules, `{"mode": "enforce"}`),
		// An independent namespace and label: its own conditions stay 404.
		"isolated identity": policyWithRules("isolated", "new-policy", "tier=isolated", illegalRules, `{}`),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			assertInvalidRulesRejected(t, router, body)

			// Every rejection leaves exactly the two original records, all
			// fields and the order-ascending sort unchanged.
			items := listItems(t, router, "/v1/net-policies?namespace=payments")
			if want := []map[string]any{deny, allow}; !reflect.DeepEqual(items, want) {
				t.Fatalf("items after rejection = %v, want unchanged %v", items, want)
			}
		})
	}

	// The isolated identity's own conditions never gained a record.
	assertQueryNotFound(t, router, "/v1/net-policies?namespace=isolated")
	assertQueryNotFound(t, router, "/v1/net-policies?label=tier%3Disolated")

	// Fixing the rules on the rejected fresh identity: 201 at max order + 1,
	// with the legal rules array preserved in submitted order.
	fixed := policyWithRules("payments", "new-policy", "tier=backend", `[
		{"direction": "egress", "action": "allow", "ports": [53, 53]},
		{"direction": "ingress", "action": "deny", "ports": [8000, 9000]}
	]`, `{}`)
	created := registerCreated(t, router, fixed, 3, false)

	// Same-content retry: 200 with the original record, consuming no order.
	retry := doRequest(router, http.MethodPost, "/v1/net-policies", fixed)
	if retry.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want %d: %s", retry.Code, http.StatusOK, retry.Body.String())
	}
	var retryRecord map[string]any
	if err := json.Unmarshal(retry.Body.Bytes(), &retryRecord); err != nil {
		t.Fatalf("decode retry: %v", err)
	}
	if !reflect.DeepEqual(retryRecord, created) {
		t.Fatalf("retry record = %v, want the original %v", retryRecord, created)
	}

	// Same identity with modified legal rules (array order swapped): 409.
	changed := policyWithRules("payments", "new-policy", "tier=backend", `[
		{"direction": "ingress", "action": "deny", "ports": [8000, 9000]},
		{"direction": "egress", "action": "allow", "ports": [53, 53]}
	]`, `{}`)
	conflict := doRequest(router, http.MethodPost, "/v1/net-policies", changed)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("changed status = %d, want %d: %s", conflict.Code, http.StatusConflict, conflict.Body.String())
	}
	assertExactErrorShape(t, conflict, "NetPolicyConflictError")
	assertSafeErrorMessage(t, conflict)

	// Final state: the two seeds plus the fixed record, order ascending.
	items := listItems(t, router, "/v1/net-policies?namespace=payments")
	if want := []map[string]any{deny, allow, created}; !reflect.DeepEqual(items, want) {
		t.Fatalf("final items = %v, want %v", items, want)
	}
}

// The existing port range validation, query decoding and GET /healthz keep
// their published behaviour alongside the rules validation.
func TestPortRangeQueryDecodingAndHealthzUnchanged(t *testing.T) {
	router, _ := newTestRouter(t)

	// The boundary ports 1 and 65535 remain a legal closed interval.
	edges := registerCreated(t, router,
		singleRuleBody("payments", "edges", "tier=backend", "ingress", "allow", 1, 65535, `{}`),
		1, false)

	// Out-of-range and reversed intervals remain invalid input.
	for name, body := range map[string]string{
		"port below range": singleRuleBody("payments", "bad-lo", "tier=backend", "ingress", "allow", 0, 80, `{}`),
		"port above range": singleRuleBody("payments", "bad-hi", "tier=backend", "ingress", "allow", 1, 65536, `{}`),
		"reversed ports":   singleRuleBody("payments", "bad-rev", "tier=backend", "ingress", "allow", 443, 80, `{}`),
	} {
		t.Run(name, func(t *testing.T) {
			assertInvalidRulesRejected(t, router, body)
		})
	}

	// Query decoding still matches the percent-encoded label exactly.
	items := listItems(t, router, "/v1/net-policies?label=tier%3Dbackend")
	if want := []map[string]any{edges}; !reflect.DeepEqual(items, want) {
		t.Fatalf("items = %v, want %v", items, want)
	}

	// GET /healthz still reports ok.
	recorder := doRequest(router, http.MethodGet, "/healthz", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("healthz status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got := recorder.Body.String(); got != `{"database":"ok","status":"ok"}` {
		t.Fatalf("healthz body = %s", got)
	}
}
