package api

// Regression coverage for conflict marking with multiple history records and
// multi-rule policies, plus the isolation, immutability and query-precision
// guarantees around them:
//
//   - a new record is flagged when it clashes with an *earlier* record even
//     when the latest record does not clash,
//   - a clash found only on the last rule of both multi-rule records counts,
//   - the first registration never conflicts with its own rules, even when
//     those rules carry opposite actions and overlapping ports,
//   - changing the namespace or the label isolates the records,
//   - plugin parameter differences do not influence the decision,
//   - older records keep their content, order and conflict flag verbatim,
//   - namespace/label/intersection queries match exactly, return complete
//     records in ascending order, and miss with 404 NetPolicyNotFoundError.
//
// All expectations are derived from the published rule in README.md.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

// recordConflict pulls the conflict flag out of a decoded record for messages.
func recordConflict(record map[string]any) bool {
	flag, _ := record["conflict"].(bool)
	return flag
}

// With several records already committed, the new record clashes with an
// earlier record but not with the latest one: the conflict must still be
// reported (detection scans every committed record with the same namespace and
// label, not just the newest), and none of the older records changes.
func TestConflictWithEarlierRecordEvenWhenLatestDoesNotClash(t *testing.T) {
	router := newMatrixRouter(t)

	// order 1: the earlier record the candidate will eventually clash with.
	olderBody := singleRuleBody("payments", "older-deny", "tier=backend",
		"ingress", "deny", 80, 100, `{"mode":"enforce"}`)
	older := registerCreated(t, router, olderBody, 1, false)

	// order 2: the latest record. It is opposite-action to the older one but on
	// disjoint ports, so it is not flagged itself; and the candidate below shares
	// its action, so it cannot clash with it either.
	latestBody := singleRuleBody("payments", "latest-allow", "tier=backend",
		"ingress", "allow", 200, 300, `{}`)
	latest := registerCreated(t, router, latestBody, 2, false)

	// order 3: allow on a port only the older deny covers. It clashes with the
	// older record (same direction, opposite action, overlapping ports) and is
	// action-identical to the latest record, so a newest-only check would
	// wrongly return false.
	candidateBody := singleRuleBody("payments", "candidate-allow", "tier=backend",
		"ingress", "allow", 90, 90, `{"mode":"audit"}`)
	candidate := registerCreated(t, router, candidateBody, 3, true)

	// Every older record keeps its exact content, order and conflict flag; the
	// namespace listing returns the complete records in ascending order.
	want := []map[string]any{older, latest, candidate}
	if items := listItems(t, router, "/v1/net-policies?namespace=payments"); !reflect.DeepEqual(items, want) {
		t.Fatalf("after candidate registration, items = %v\nwant %v", items, want)
	}
}

// Both records carry several rules and the only clashing pair is the last rule
// of the old record against the last rule of the new one. All other rule pairs
// are deliberately neutral (same action, or different direction), so a true
// flag proves the last positions of both sides are compared.
func TestConflictOnlyOnLastRuleOfBothRecords(t *testing.T) {
	router := newMatrixRouter(t)

	oldBody := policyWithRules("payments", "multi-old", "tier=backend", `[
		{"direction": "egress",  "action": "allow", "ports": [53, 53]},
		{"direction": "ingress", "action": "deny",  "ports": [80, 100]}
	]`, `{"mode": "enforce"}`)
	old := registerCreated(t, router, oldBody, 1, false)

	newBody := policyWithRules("payments", "multi-new", "tier=backend", `[
		{"direction": "egress",  "action": "allow", "ports": [53, 53]},
		{"direction": "ingress", "action": "allow", "ports": [90, 90]}
	]`, `{}`)
	// Rule-pair audit, derived from the published rule:
	//	old[0] vs new[0]: same direction egress, same action allow        -> no clash
	//	old[0] vs new[1]: different direction                             -> no clash
	//	old[1] vs new[0]: different direction                             -> no clash
	//	old[1] vs new[1]: same direction ingress, deny vs allow, overlap  -> CLASH
	created := registerCreated(t, router, newBody, 2, true)

	if items := listItems(t, router, "/v1/net-policies?label=tier%3Dbackend"); !reflect.DeepEqual(
		items, []map[string]any{old, created}) {
		t.Fatalf("items = %v\nwant the two complete records in order, older flag untouched", items)
	}
}

// A single first registration may itself contain rules with opposite actions
// on overlapping ports: with no history there is nothing to clash with, so the
// record is created (201, order 1) with conflict=false. A later truly clashing
// record is flagged, while the first record's flag is never recomputed — an
// idempotent retry of it still returns the original false.
func TestFirstRegistrationNeverConflictsWithOwnRules(t *testing.T) {
	router := newMatrixRouter(t)

	selfOverlapBody := policyWithRules("payments", "self-opposed", "tier=backend", `[
		{"direction": "ingress", "action": "deny",  "ports": [80, 100]},
		{"direction": "ingress", "action": "allow", "ports": [90, 90]}
	]`, `{}`)
	self := registerCreated(t, router, selfOverlapBody, 1, false)

	if items := listItems(t, router, "/v1/net-policies?namespace=payments"); len(items) != 1 ||
		!reflect.DeepEqual(items[0], self) {
		t.Fatalf("self-opposed first record saved as %v\nwant %v", items, self)
	}

	// A later record clashing with one of the first record's rules is flagged;
	// the first record stays false.
	clashBody := singleRuleBody("payments", "later-clash", "tier=backend",
		"ingress", "allow", 100, 100, `{}`)
	registerCreated(t, router, clashBody, 2, true)

	items := listItems(t, router, "/v1/net-policies?namespace=payments")
	if len(items) != 2 || !reflect.DeepEqual(items[0], self) {
		t.Fatalf("older record after clash = %v\nwant unchanged %v", items, self)
	}

	// Idempotent retry (rules reordered in the JSON object keys only, same
	// array content) returns 200 with the stored conflict=false even though a
	// clashing record now exists: flags are fixed at registration time.
	retry := doRequest(router, http.MethodPost, "/v1/net-policies", `{
		"pluginParams": {},
		"label": "tier=backend",
		"name": "self-opposed",
		"namespace": "payments",
		"rules": [
			{"ports": [80, 100], "action": "deny",  "direction": "ingress"},
			{"ports": [90, 90],  "action": "allow", "direction": "ingress"}
		]
	}`)
	if retry.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want %d: %s", retry.Code, http.StatusOK, retry.Body.String())
	}
	var retryRecord map[string]any
	if err := json.Unmarshal(retry.Body.Bytes(), &retryRecord); err != nil {
		t.Fatalf("decode retry: %v", err)
	}
	if !reflect.DeepEqual(retryRecord, self) {
		t.Fatalf("retry record = %v\nwant the original record %v with conflict=false", retryRecord, self)
	}
}

// Conflict scoping requires both the namespace and the label to match
// verbatim. Each subtest starts from the same clashing rule pair and changes
// exactly one scope dimension; only the exact match is flagged, and every
// saved record round-trips through GET with its computed flag.
func TestConflictIsolationAcrossNamespaceAndLabel(t *testing.T) {
	cases := []struct {
		name         string
		ns           string
		label        string
		wantConflict bool
	}{
		{"same namespace and label", "payments", "tier=backend", true},
		{"different namespace", "staging", "tier=backend", false},
		{"different label", "payments", "tier=frontend", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router := newMatrixRouter(t)
			registerCreated(t, router,
				singleRuleBody("payments", "old-deny", "tier=backend", "ingress", "deny", 80, 100, `{}`),
				1, false)
			// registerCreated below already demands status 201, the expected
			// conflict flag and the complete response object; then verify that
			// flag survives a GET and that scope is exact.
			candidate := registerCreated(t, router,
				singleRuleBody(tc.ns, "new-allow", tc.label, "ingress", "allow", 90, 90, `{}`),
				2, tc.wantConflict)
			if recordConflict(candidate) != tc.wantConflict {
				t.Fatalf("input: namespace=%q label=%q, clashing ingress allow [90,90] vs ingress deny [80,100]\nexpected conflict = %v, actual = %v",
					tc.ns, tc.label, tc.wantConflict, recordConflict(candidate))
			}

			items := listItems(t, router,
				"/v1/net-policies?namespace="+url.QueryEscape(tc.ns)+"&label="+url.QueryEscape(tc.label))
			var persisted map[string]any
			for _, item := range items {
				if item["name"] == "new-allow" {
					persisted = item
				}
			}
			if persisted == nil {
				t.Fatalf("candidate missing from its exact scope: %v", items)
			}
			if !reflect.DeepEqual(persisted, candidate) {
				t.Fatalf("persisted candidate = %v\nwant the complete record %v", persisted, candidate)
			}
			if tc.wantConflict {
				if len(items) != 2 {
					t.Fatalf("same-scope items = %v, want both records (the old one plus the candidate)", items)
				}
				return
			}
			if len(items) != 1 {
				t.Fatalf("isolated scope items = %v, want exactly the candidate", items)
			}
			oldScope := listItems(t, router, "/v1/net-policies?namespace=payments&label=tier%3Dbackend")
			if len(oldScope) != 1 || oldScope[0]["name"] != "old-deny" {
				t.Fatalf("old scope items = %v, want exactly the original old-deny record", oldScope)
			}
		})
	}
}

// Plugin parameters are content, not part of the conflict rule: two records
// with clashing rules are flagged regardless of differing plugin keys and
// values, while neutral rule pairs stay false even with wildly different
// parameters. The differing parameters are saved verbatim.
func TestConflictDecisionIgnoresPluginParams(t *testing.T) {
	router := newMatrixRouter(t)

	older := registerCreated(t, router,
		singleRuleBody("payments", "older", "tier=backend", "ingress", "deny", 80, 100,
			`{"mode":"enforce"}`), 1, false)

	// Clashing ports and opposite action, completely different plugin object:
	// still flagged.
	clash := registerCreated(t, router,
		singleRuleBody("payments", "clash", "tier=backend", "ingress", "allow", 90, 90,
			`{"zone":"edge","mode":"audit"}`), 2, true)
	if got := clash["pluginParams"]; !reflect.DeepEqual(got, map[string]any{"zone": "edge", "mode": "audit"}) {
		t.Fatalf("clashing record pluginParams = %v, want saved verbatim", got)
	}

	// Disjoint ports with another arbitrary plugin object: not flagged.
	disjoint := registerCreated(t, router,
		singleRuleBody("payments", "disjoint", "tier=backend", "ingress", "allow", 200, 300,
			`{"totally":"different","x":""}`), 3, false)

	// Overlapping ports but same action, differing params: not flagged.
	sameAction := registerCreated(t, router,
		singleRuleBody("payments", "same-action", "tier=backend", "ingress", "deny", 85, 85,
			`{"mode":"other"}`), 4, false)

	want := []map[string]any{older, clash, disjoint, sameAction}
	if items := listItems(t, router, "/v1/net-policies?namespace=payments"); !reflect.DeepEqual(items, want) {
		t.Fatalf("items = %v\nwant %v (only the port-clashing opposite-action record is true)", items, want)
	}
}

// Registering a new record never mutates older ones: their submitted fields,
// order and conflict flag (including an already-true flag) are byte-identical
// before and after the insert.
func TestNewRegistrationLeavesOlderRecordsUntouched(t *testing.T) {
	router := newMatrixRouter(t)

	first := registerCreated(t, router,
		singleRuleBody("payments", "first", "tier=backend", "ingress", "deny", 80, 100,
			`{"mode":"enforce"}`), 1, false)
	second := registerCreated(t, router,
		singleRuleBody("payments", "second", "tier=backend", "ingress", "allow", 90, 90,
			`{"mode":"enforce"}`), 2, true)

	// Third record in the same namespace and label clashes with the first
	// (opposite action over port 80) but not the second (same action), so the
	// insert sets a fresh conflict=true flag. The two older records — one
	// false, one already true — must nevertheless come back byte-identical.
	third := registerCreated(t, router,
		singleRuleBody("payments", "third", "tier=backend", "ingress", "allow", 80, 80,
			`{}`), 3, true)

	items := listItems(t, router, "/v1/net-policies?namespace=payments&label=tier%3Dbackend")
	if len(items) != 3 {
		t.Fatalf("items = %v, want the two older records plus %v", items, third)
	}
	if !reflect.DeepEqual(items[0], first) {
		t.Fatalf("first record changed after inserting %v\nbefore: %v\nafter:  %v", third, first, items[0])
	}
	if !reflect.DeepEqual(items[1], second) {
		t.Fatalf("second record changed after inserting %v\nbefore: %v\nafter:  %v", third, second, items[1])
	}
}

// Across several namespaces and labels, each query shape matches exactly:
// namespace alone crosses labels, the label alone crosses namespaces, the pair
// intersects, the returned records are complete and ordered by the global
// ascending order, and a scope that matches nothing answers 404 with the
// published NetPolicyNotFoundError error object.
func TestQueryExactMatchCompletenessOrderAndNotFound(t *testing.T) {
	router := newMatrixRouter(t)

	r1 := registerCreated(t, router,
		singleRuleBody("payments", "p1", "tier=backend", "egress", "allow", 53, 53, `{"x":"1"}`),
		1, false)
	r2 := registerCreated(t, router,
		singleRuleBody("staging", "s1", "tier=backend", "ingress", "deny", 80, 100, `{}`),
		2, false)
	r3 := registerCreated(t, router,
		singleRuleBody("payments", "p2", "tier=frontend", "ingress", "allow", 443, 443,
			`{"x":"2","y":""}`),
		3, false)

	queryCases := []struct {
		name   string
		target string
		want   []map[string]any
	}{
		{"namespace crosses labels", "/v1/net-policies?namespace=payments", []map[string]any{r1, r3}},
		{"label crosses namespaces", "/v1/net-policies?label=tier%3Dbackend", []map[string]any{r1, r2}},
		{"intersection", "/v1/net-policies?namespace=payments&label=tier%3Dbackend", []map[string]any{r1}},
		{"intersection other namespace", "/v1/net-policies?namespace=staging&label=tier%3Dbackend", []map[string]any{r2}},
	}
	for _, tc := range queryCases {
		t.Run(tc.name, func(t *testing.T) {
			items := listItems(t, router, tc.target)
			if !reflect.DeepEqual(items, tc.want) {
				t.Fatalf("GET %s\nactual items = %v\nexpected = %v (complete records, order ascending)",
					tc.target, items, tc.want)
			}
			var lastOrder float64
			for i, item := range items {
				order, _ := item["order"].(float64)
				if i > 0 && order <= lastOrder {
					t.Fatalf("GET %s items not ascending by order: %v", tc.target, items)
				}
				lastOrder = order
			}
		})
	}

	missCases := []string{
		"/v1/net-policies?namespace=missing",
		"/v1/net-policies?label=missing",
		"/v1/net-policies?namespace=staging&label=tier=frontend",
		"/v1/net-policies?namespace=payments&label=tier%3Dmissing",
	}
	for _, target := range missCases {
		t.Run("miss "+target, func(t *testing.T) {
			recorder := doRequest(router, http.MethodGet, target, "")
			if recorder.Code != http.StatusNotFound {
				t.Fatalf("GET %s status = %d, want %d: %s",
					target, recorder.Code, http.StatusNotFound, recorder.Body.String())
			}
			assertExactErrorShape(t, recorder, "NetPolicyNotFoundError")
			assertSafeErrorMessage(t, recorder)
		})
	}

	// Sanity on the enumeration itself: three records exist in total.
	if all := listItems(t, router, "/v1/net-policies?label=tier%3Dbackend"); len(all) != 2 {
		t.Fatalf("tier=backend count = %d, want 2", len(all))
	}
	if ns := listItems(t, router, "/v1/net-policies?namespace=payments"); len(ns) != 2 {
		t.Fatalf("payments count = %d, want 2", len(ns))
	}
}
