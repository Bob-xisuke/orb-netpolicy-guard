package api

// System regression coverage for the closed-interval conflict rule published in
// README.md: a newly registered record is flagged only when an already committed
// record shares its namespace AND label, carries a rule with the same direction
// and the opposite action, and the two rules' closed port intervals share at
// least one port (intervals that merely touch at an endpoint overlap).
//
// These tests drive only the public POST/GET HTTP entries. The expected outcome
// for every case is computed by the small independent oracle below — written
// straight from the published rule — and never by the storage layer's own
// conflict function. Every failure message carries the input, the expectation
// and the actual response.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
)

// closedIntervalsSharePort is the oracle's independent reading of "closed
// intervals sharing at least one port": [a0,a1] and [b0,b1] intersect exactly
// when each starts at or before the other's end.
func closedIntervalsSharePort(a, b [2]int) bool {
	return a[0] <= b[1] && b[0] <= a[1]
}

// oracleRule describes one rule in the language of the published contract.
type oracleRule struct {
	direction string
	action    string
	ports     [2]int
}

// expectConflictAgainstHistory evaluates one candidate rule against every
// committed history rule using only the published conflict rule.
func expectConflictAgainstHistory(candidate oracleRule, history ...oracleRule) bool {
	for _, older := range history {
		if candidate.direction == older.direction &&
			candidate.action != older.action &&
			closedIntervalsSharePort(candidate.ports, older.ports) {
			return true
		}
	}
	return false
}

// expectRulesConflict evaluates full rule lists: a record conflicts when any
// candidate rule clashes with any existing rule.
func expectRulesConflict(candidate, existing []oracleRule) bool {
	for _, cand := range candidate {
		for _, old := range existing {
			if cand.direction == old.direction &&
				cand.action != old.action &&
				closedIntervalsSharePort(cand.ports, old.ports) {
				return true
			}
		}
	}
	return false
}

// postAndDecode runs a POST and decodes a record body when one is present. The
// input description is echoed in every failure message.
func postAndDecode(t *testing.T, router *gin.Engine, body, input string) (int, map[string]any) {
	t.Helper()
	recorder := doRequest(router, http.MethodPost, "/v1/net-policies", body)
	var record map[string]any
	if recorder.Code == http.StatusCreated || recorder.Code == http.StatusOK {
		if err := json.Unmarshal(recorder.Body.Bytes(), &record); err != nil {
			t.Fatalf("input %s: decode %d response %q: %v", input, recorder.Code, recorder.Body.String(), err)
		}
	}
	return recorder.Code, record
}

// mustCreated demands a 201 and verifies the complete response object against
// the submitted body plus the independently expected order and conflict flag.
func mustCreated(t *testing.T, router *gin.Engine, body, input string, order int64, conflict bool) map[string]any {
	t.Helper()
	status, record := postAndDecode(t, router, body, input)
	if status != http.StatusCreated {
		t.Fatalf("input %s: status = %d, want %d; body %s", input, status, http.StatusCreated, body)
	}
	want := wantRecord(t, body, order, conflict)
	if !reflect.DeepEqual(record, want) {
		t.Fatalf("input %s:\nrecord = %#v\n want  %#v", input, record, want)
	}
	return record
}

// TestConflictMatrixClosedIntervalCombinations exhaustively compares every
// legal closed interval whose endpoints come from {1, 2, 3, 65534, 65535} — 15
// intervals, hence all 225 ordered interval pairs (each interval registered
// first as the old record and again as the new record, identity pairs included)
// — crossed with every legal direction/action combination on both sides (16),
// giving 3600 cases. The old record always lands in an empty history (201,
// conflict=false); the new record's flag must equal the independent oracle.
// Saved results are then read back through GET, and the whole set is executed a
// second time against a fresh store to prove repeatability.
func TestConflictMatrixClosedIntervalCombinations(t *testing.T) {
	endpoints := []int{1, 2, 3, 65534, 65535}
	var intervals [][2]int
	for _, lo := range endpoints {
		for _, hi := range endpoints {
			if lo <= hi {
				intervals = append(intervals, [2]int{lo, hi})
			}
		}
	}
	if len(intervals) != 15 {
		t.Fatalf("legal intervals = %d, want 15 closed intervals from %v", len(intervals), endpoints)
	}

	sides := []oracleRule{
		{direction: "ingress", action: "allow"},
		{direction: "ingress", action: "deny"},
		{direction: "egress", action: "allow"},
		{direction: "egress", action: "deny"},
	}

	routerA, _ := newTestRouter(t)
	routerB, _ := newTestRouter(t)

	var (
		gotTrue, wantTrue   int
		gotFalse, wantFalse int
	)

	caseNo := 0
	for _, seedPorts := range intervals {
		for _, candPorts := range intervals {
			for _, seedSide := range sides {
				for _, candSide := range sides {
					caseNo++
					seed := oracleRule{direction: seedSide.direction, action: seedSide.action, ports: seedPorts}
					cand := oracleRule{direction: candSide.direction, action: candSide.action, ports: candPorts}
					wantConflict := expectConflictAgainstHistory(cand, seed)
					if wantConflict {
						wantTrue++
					} else {
						wantFalse++
					}

					namespace := fmt.Sprintf("matrix-%04d", caseNo)
					label := fmt.Sprintf("tier=matrix-%04d", caseNo)
					input := fmt.Sprintf(
						"seed={%s %s ports=[%d,%d]} candidate={%s %s ports=[%d,%d]} namespace=%s label=%s",
						seed.direction, seed.action, seed.ports[0], seed.ports[1],
						cand.direction, cand.action, cand.ports[0], cand.ports[1], namespace, label)
					name := fmt.Sprintf("seed[%d,%d]%s/%s_cand[%d,%d]%s/%s",
						seedPorts[0], seedPorts[1], seed.direction, seed.action,
						candPorts[0], candPorts[1], candSide.direction, candSide.action)

					t.Run(name, func(t *testing.T) {
						seedBody := singleRuleBody(namespace, "old", label,
							seed.direction, seed.action, seed.ports[0], seed.ports[1], `{}`)
						candBody := singleRuleBody(namespace, "new", label,
							cand.direction, cand.action, cand.ports[0], cand.ports[1], `{}`)
						seedOrder, candOrder := int64(2*caseNo-1), int64(2*caseNo)

						var saved [2]map[string]any
						for run, router := range []*gin.Engine{routerA, routerB} {
							// First registration in this namespace: 201, no history, no flag.
							status, seedRecord := postAndDecode(t, router, seedBody, input+" run="+fmt.Sprint(run+1))
							if status != http.StatusCreated {
								t.Fatalf("input %s run %d: seed status = %d, want %d",
									input, run+1, status, http.StatusCreated)
							}
							if wantSeed := wantRecord(t, seedBody, seedOrder, false); !reflect.DeepEqual(seedRecord, wantSeed) {
								t.Fatalf("input %s run %d:\nseed record = %#v\n want       %#v",
									input, run+1, seedRecord, wantSeed)
							}

							status, candRecord := postAndDecode(t, router, candBody, input+" run="+fmt.Sprint(run+1))
							if status != http.StatusCreated {
								t.Fatalf("input %s run %d: candidate status = %d, want %d",
									input, run+1, status, http.StatusCreated)
							}
							if conflict, _ := candRecord["conflict"].(bool); conflict != wantConflict {
								t.Fatalf("input %s run %d: candidate conflict = %v, want %v\nrecord = %#v",
									input, run+1, conflict, wantConflict, candRecord)
							}
							if wantCand := wantRecord(t, candBody, candOrder, wantConflict); !reflect.DeepEqual(candRecord, wantCand) {
								t.Fatalf("input %s run %d:\ncandidate record = %#v\n want          %#v",
									input, run+1, candRecord, wantCand)
							}

							// Read the saved pair back: exact match, complete records,
							// ascending by order.
							items := listItems(t, router, "/v1/net-policies?namespace="+namespace)
							if len(items) != 2 {
								t.Fatalf("input %s run %d: GET returned %d items, want 2: %v",
									input, run+1, len(items), items)
							}
							wantItems := []map[string]any{seedRecord, candRecord}
							if !reflect.DeepEqual(items, wantItems) {
								t.Fatalf("input %s run %d:\nsaved items = %#v\n want       %#v",
									input, run+1, items, wantItems)
							}
							saved[run] = map[string]any{
								"seed": seedRecord, "candidate": candRecord, "items": items,
							}
						}

						// Repeating the same set against a fresh store is identical.
						if !reflect.DeepEqual(saved[0], saved[1]) {
							t.Fatalf("input %s: repeated run diverged:\nfirst  = %#v\nsecond = %#v",
								input, saved[0], saved[1])
						}

						actual, _ := saved[0]["candidate"].(map[string]any)["conflict"].(bool)
						if actual {
							gotTrue++
						} else {
							gotFalse++
						}
					})
				}
			}
		}
	}

	// Aggregate guard on the wiring: actual true/false counts must match the
	// oracle's counts, and both outcomes must actually have been exercised.
	if gotTrue != wantTrue || gotFalse != wantFalse {
		t.Fatalf("conflict tally = true %d/%d, false %d/%d (got/want)",
			gotTrue, wantTrue, gotFalse, wantFalse)
	}
	if wantTrue == 0 || wantFalse == 0 {
		t.Fatalf("oracle tally degenerate: true=%d false=%d", wantTrue, wantFalse)
	}

	// Literal boundary pins derived directly from the published rule, guarding
	// the generator and the oracle themselves: endpoint touching overlaps, the
	// gap between 3 and 65534 does not, and the extreme ports overlap anything.
	for _, tc := range []struct {
		name                 string
		seedPorts, candPorts [2]int
		overlap              bool
	}{
		{"touch at endpoint 2", [2]int{1, 2}, [2]int{2, 3}, true},
		{"touch at endpoint 3", [2]int{2, 3}, [2]int{3, 65534}, true},
		{"touch at endpoint 65534", [2]int{3, 65534}, [2]int{65534, 65535}, true},
		{"gap between 3 and 65534", [2]int{1, 3}, [2]int{65534, 65534}, false},
		{"lower extreme 1", [2]int{1, 1}, [2]int{1, 65535}, true},
		{"upper extreme 65535", [2]int{65535, 65535}, [2]int{1, 65535}, true},
		{"same singleton interval", [2]int{65534, 65534}, [2]int{65534, 65534}, true},
	} {
		if got := closedIntervalsSharePort(tc.seedPorts, tc.candPorts); got != tc.overlap {
			t.Fatalf("boundary pin %q: overlap = %v, want %v for %v and %v",
				tc.name, got, tc.overlap, tc.seedPorts, tc.candPorts)
		}
	}
}

// TestConflictRegressionMultipleHistoryRecords covers a history longer than
// one record: a candidate that clashes only with an EARLIER record (not the
// newest one) is still flagged, and every older record keeps its content, order
// and conflict flag afterwards.
func TestConflictRegressionMultipleHistoryRecords(t *testing.T) {
	router, _ := newTestRouter(t)

	earlyBody := singleRuleBody("payments", "early", "tier=backend", "ingress", "deny", 80, 100, `{}`)
	early := mustCreated(t, router, earlyBody, "early ingress deny [80,100]", 1, false)

	latestBody := singleRuleBody("payments", "latest", "tier=backend", "ingress", "allow", 300, 400, `{}`)
	// Opposite action from early but the intervals are disjoint: no conflict.
	latest := mustCreated(t, router, latestBody, "latest ingress allow [300,400]", 2,
		expectConflictAgainstHistory(
			oracleRule{"ingress", "allow", [2]int{300, 400}},
			oracleRule{"ingress", "deny", [2]int{80, 100}}))

	// Allow [90,90]: same action as the newest record (no clash there) but
	// opposite action and overlapping ports against the EARLIER record.
	candHistory := []oracleRule{
		{direction: "ingress", action: "deny", ports: [2]int{80, 100}},
		{direction: "ingress", action: "allow", ports: [2]int{300, 400}},
	}
	candBody := singleRuleBody("payments", "candidate", "tier=backend", "ingress", "allow", 90, 90, `{}`)
	wantConflict := expectConflictAgainstHistory(oracleRule{"ingress", "allow", [2]int{90, 90}}, candHistory...)
	if !wantConflict {
		t.Fatalf("oracle setup wrong: candidate against early deny [80,100] must conflict")
	}
	cand := mustCreated(t, router, candBody, "candidate ingress allow [90,90]", 3, true)

	items := listItems(t, router, "/v1/net-policies?namespace=payments")
	wantItems := []map[string]any{early, latest, cand}
	if !reflect.DeepEqual(items, wantItems) {
		t.Fatalf("after candidate registration:\nitems = %#v\n want %#v", items, wantItems)
	}
}

// TestConflictRegressionClashOnlyOnLastRules builds multi-rule records where the
// ONLY clashing rule pair is the last rule of each side; all preceding rule
// pairs differ in direction, share an action, or have disjoint ports.
func TestConflictRegressionClashOnlyOnLastRules(t *testing.T) {
	router, _ := newTestRouter(t)

	seedBody := policyWithRules("multi", "seed", "tier=backend", `[
		{"direction": "egress",  "action": "allow", "ports": [53, 53]},
		{"direction": "egress",  "action": "deny",  "ports": [8000, 9000]},
		{"direction": "ingress", "action": "deny",  "ports": [80, 100]}
	]`, `{"zone": "east"}`)
	seedSpecs := []oracleRule{
		{direction: "egress", action: "allow", ports: [2]int{53, 53}},
		{direction: "egress", action: "deny", ports: [2]int{8000, 9000}},
		{direction: "ingress", action: "deny", ports: [2]int{80, 100}},
	}
	seed := mustCreated(t, router, seedBody, "seed 3 rules ending ingress deny [80,100]", 1, false)

	candBody := policyWithRules("multi", "candidate", "tier=backend", `[
		{"direction": "egress",  "action": "deny",  "ports": [6000, 7000]},
		{"direction": "ingress", "action": "allow", "ports": [90, 90]}
	]`, `{"zone": "west"}`)
	candSpecs := []oracleRule{
		{direction: "egress", action: "deny", ports: [2]int{6000, 7000}},
		{direction: "ingress", action: "allow", ports: [2]int{90, 90}},
	}
	wantConflict := expectRulesConflict(candSpecs, seedSpecs)
	if !wantConflict {
		t.Fatalf("oracle setup wrong: last rules ingress deny [80,100] vs ingress allow [90,90] must conflict")
	}
	cand := mustCreated(t, router, candBody, "candidate last rule ingress allow [90,90]", 2, true)

	items := listItems(t, router, "/v1/net-policies?namespace=multi")
	if want := []map[string]any{seed, cand}; !reflect.DeepEqual(items, want) {
		t.Fatalf("last-rule-clash items = %#v, want %#v", items, want)
	}
}

// TestConflictRegressionNoSelfConflictInsideFirstRecord registers ONE record
// whose own rules oppose each other on overlapping ports: with no history there
// is nothing to conflict with, so the flag must be false.
func TestConflictRegressionNoSelfConflictInsideFirstRecord(t *testing.T) {
	router, _ := newTestRouter(t)

	body := policyWithRules("self", "split", "tier=backend", `[
		{"direction": "ingress", "action": "deny",  "ports": [80, 100]},
		{"direction": "ingress", "action": "allow", "ports": [90, 90]},
		{"direction": "egress",  "action": "allow", "ports": [80, 100]}
	]`, `{"mode": "enforce"}`)
	record := mustCreated(t, router, body,
		"single record containing ingress deny [80,100] and ingress allow [90,90]", 1, false)

	items := listItems(t, router, "/v1/net-policies?namespace=self")
	if !reflect.DeepEqual(items, []map[string]any{record}) {
		t.Fatalf("self-conflicting record stored as %#v, want %#v", items, record)
	}
}

// TestConflictRegressionNamespaceAndLabelIsolation changes namespace and label
// one dimension at a time; conflict detection requires BOTH to match.
func TestConflictRegressionNamespaceAndLabelIsolation(t *testing.T) {
	router, _ := newTestRouter(t)

	seedBody := singleRuleBody("iso", "seed", "tier=backend", "ingress", "deny", 80, 100, `{}`)
	seed := mustCreated(t, router, seedBody, "iso/tier=backend ingress deny [80,100]", 1, false)

	// Different namespace, same label and a rule that WOULD clash by the
	// rule-level oracle: namespace isolation must suppress the flag.
	wouldClashAcrossNamespace := expectConflictAgainstHistory(
		oracleRule{"ingress", "allow", [2]int{90, 90}},
		oracleRule{"ingress", "deny", [2]int{80, 100}})
	if !wouldClashAcrossNamespace {
		t.Fatalf("oracle setup wrong: ingress allow [90,90] vs ingress deny [80,100] clash by rules")
	}
	otherNsBody := singleRuleBody("other-ns", "seed", "tier=backend", "ingress", "allow", 90, 90, `{}`)
	otherNs := mustCreated(t, router, otherNsBody,
		"namespace=other-ns label=tier=backend ingress allow [90,90]", 2, false)

	// Same namespace, different label, same rule-level clash: label isolation
	// must suppress the flag just as well.
	otherLabelBody := singleRuleBody("iso", "frontend", "tier=frontend", "ingress", "allow", 90, 90, `{}`)
	otherLabel := mustCreated(t, router, otherLabelBody,
		"namespace=iso label=tier=frontend ingress allow [90,90]", 3, false)

	// Control: same namespace AND same label with a clashing rule is flagged.
	controlBody := singleRuleBody("iso", "control", "tier=backend", "ingress", "allow", 90, 90, `{}`)
	control := mustCreated(t, router, controlBody,
		"namespace=iso label=tier=backend ingress allow [90,90]", 4, true)

	// The seed must be untouched after the later flagged registration.
	items := listItems(t, router, "/v1/net-policies?namespace=iso&label=tier%3Dbackend")
	if want := []map[string]any{seed, control}; !reflect.DeepEqual(items, want) {
		t.Fatalf("isolated query items = %#v, want %#v (seed conflict/order/content unchanged)", items, want)
	}
	if got := listItems(t, router, "/v1/net-policies?namespace=other-ns"); !reflect.DeepEqual(got, []map[string]any{otherNs}) {
		t.Fatalf("other-namespace items = %#v, want %#v", got, []map[string]any{otherNs})
	}
	if got := listItems(t, router, "/v1/net-policies?namespace=iso&label=tier%3Dfrontend"); !reflect.DeepEqual(got, []map[string]any{otherLabel}) {
		t.Fatalf("other-label items = %#v, want %#v", got, []map[string]any{otherLabel})
	}
}

// TestConflictRegressionPluginParamsDoNotAffectDecision verifies that differing
// pluginParams neither create nor suppress a conflict: the flag follows the
// rules only.
func TestConflictRegressionPluginParamsDoNotAffectDecision(t *testing.T) {
	router, _ := newTestRouter(t)

	seedBody := singleRuleBody("plug", "seed", "tier=backend", "ingress", "deny", 80, 100,
		`{"mode": "enforce", "zone": "east"}`)
	seed := mustCreated(t, router, seedBody, `seed params {"mode":"enforce","zone":"east"}`, 1, false)

	// Touching intervals, opposite action, but a different plugin string value:
	// still a conflict.
	clashBody := singleRuleBody("plug", "clash", "tier=backend", "ingress", "allow", 100, 200,
		`{"mode": "audit"}`)
	clash := mustCreated(t, router, clashBody, `clash params {"mode":"audit"}`, 2, true)

	// Disjoint intervals with yet different params: still no conflict.
	disjointBody := singleRuleBody("plug", "disjoint", "tier=backend", "ingress", "allow", 300, 400,
		`{"mode": "inspect", "retries": "9"}`)
	disjoint := mustCreated(t, router, disjointBody,
		`disjoint params {"mode":"inspect","retries":"9"}`, 3, false)

	items := listItems(t, router, "/v1/net-policies?namespace=plug")
	if want := []map[string]any{seed, clash, disjoint}; !reflect.DeepEqual(items, want) {
		t.Fatalf("plugin-param items = %#v, want %#v", items, want)
	}
}

// TestConflictRegressionQueriesMatchExactly verifies namespace, label and
// intersection queries return complete records in ascending order, that a
// miss is 404 NetPolicyNotFoundError, and that adding a flagged record leaves
// the older record's content, order and conflict flag unchanged.
func TestConflictRegressionQueriesMatchExactly(t *testing.T) {
	router, _ := newTestRouter(t)

	r1Body := singleRuleBody("payments", "p1", "tier=backend", "ingress", "deny", 80, 100, `{"mode": "enforce"}`)
	r1 := mustCreated(t, router, r1Body, "payments/p1 tier=backend", 1, false)
	r2Body := singleRuleBody("payments", "p2", "tier=backend", "ingress", "allow", 100, 200, `{"zone": "east"}`)
	r2 := mustCreated(t, router, r2Body, "payments/p2 tier=backend (touch at 100)", 2, true)
	r3Body := singleRuleBody("payments", "p3", "tier=frontend", "egress", "allow", 53, 53, `{}`)
	r3 := mustCreated(t, router, r3Body, "payments/p3 tier=frontend", 3, false)
	r4Body := singleRuleBody("staging", "p4", "tier=backend", "ingress", "allow", 80, 80, `{}`)
	r4 := mustCreated(t, router, r4Body, "staging/p4 tier=backend (different namespace)", 4, false)

	for _, tc := range []struct {
		name   string
		target string
		want   []map[string]any
	}{
		{"namespace", "/v1/net-policies?namespace=payments", []map[string]any{r1, r2, r3}},
		{"label across namespaces", "/v1/net-policies?label=tier%3Dbackend", []map[string]any{r1, r2, r4}},
		{"intersection", "/v1/net-policies?namespace=payments&label=tier%3Dbackend", []map[string]any{r1, r2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			items := listItems(t, router, tc.target)
			if !reflect.DeepEqual(items, tc.want) {
				t.Fatalf("GET %s:\nitems = %#v\n want %#v", tc.target, items, tc.want)
			}
			var prev int64
			for i, item := range items {
				order, _ := item["order"].(float64)
				if int64(order) <= prev && i > 0 {
					t.Fatalf("GET %s items not ascending by order: %#v", tc.target, items)
				}
				prev = int64(order)
			}
		})
	}

	// The older record stays exactly as first registered after the clash.
	items := listItems(t, router, "/v1/net-policies?namespace=payments&label=tier%3Dbackend")
	if !reflect.DeepEqual(items[0], r1) {
		t.Fatalf("older record changed after new registration:\n got %#v\nwant %#v", items[0], r1)
	}

	for _, target := range []string{
		"/v1/net-policies?namespace=missing",
		"/v1/net-policies?label=tier%3Dmissing",
		"/v1/net-policies?namespace=payments&label=tier%3Dmissing",
		"/v1/net-policies?namespace=staging&label=tier%3Dfrontend",
	} {
		recorder := doRequest(router, http.MethodGet, target, "")
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("GET %s: status = %d, want %d; body %s",
				target, recorder.Code, http.StatusNotFound, recorder.Body.String())
		}
		assertExactErrorShape(t, recorder, "NetPolicyNotFoundError")
		assertSafeErrorMessage(t, recorder)
	}
}

// TestConflictRegressionRegistrationBoundaries pins the registration edges:
// 201 first time, 200 with the original on identical retry, 409 on changed rule
// order or a changed plugin string, 400 on out-of-range/inverted ports or an
// illegal direction. Rejected requests and retries neither add rows nor consume
// an order nor touch existing flags; the next legal record takes max order + 1.
func TestConflictRegressionRegistrationBoundaries(t *testing.T) {
	router, _ := newTestRouter(t)

	seedBody := singleRuleBody("payments", "seed", "tier=backend", "ingress", "deny", 80, 100,
		`{"mode": "enforce", "zone": "east"}`)
	seed := mustCreated(t, router, seedBody, "first registration ingress deny [80,100]", 1, false)

	clashBody := singleRuleBody("payments", "clash", "tier=backend", "ingress", "allow", 100, 200,
		`{"zone": "east"}`)
	clash := mustCreated(t, router, clashBody, "second registration ingress allow [100,200]", 2, true)

	// Two egress rules (the history holds only ingress rules, so neither rule
	// can clash); the two egress rules oppose each other on overlapping ports,
	// which must not self-flag because conflict is only assessed against
	// committed records.
	orderedBody := policyWithRules("payments", "ordered", "tier=backend", `[
		{"direction": "egress", "action": "deny",  "ports": [1, 100]},
		{"direction": "egress", "action": "allow", "ports": [53, 53]}
	]`, `{}`)
	ordered := mustCreated(t, router, orderedBody, "two egress rules, history is ingress-only", 3, false)

	// Identical retry: 200 with the original record.
	recorder := doRequest(router, http.MethodPost, "/v1/net-policies", clashBody)
	if recorder.Code != http.StatusOK {
		t.Fatalf("identical retry: status = %d, want %d; body %s",
			recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var retried map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &retried); err != nil {
		t.Fatalf("decode identical retry: %v", err)
	}
	if !reflect.DeepEqual(retried, clash) {
		t.Fatalf("identical retry:\n got %#v\nwant original %#v", retried, clash)
	}

	// Same content with pluginParams members reordered: still 200, same record.
	reorderedParamsBody := singleRuleBody("payments", "seed", "tier=backend", "ingress", "deny", 80, 100,
		`{"zone": "east", "mode": "enforce"}`)
	recorder = doRequest(router, http.MethodPost, "/v1/net-policies", reorderedParamsBody)
	if recorder.Code != http.StatusOK {
		t.Fatalf("reordered-params retry: status = %d, want %d; body %s",
			recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &retried); err != nil {
		t.Fatalf("decode reordered retry: %v", err)
	}
	if !reflect.DeepEqual(retried, seed) {
		t.Fatalf("reordered-params retry:\n got %#v\nwant original %#v", retried, seed)
	}

	// Same identity, rules in a different order: 409.
	swappedRulesBody := policyWithRules("payments", "ordered", "tier=backend", `[
		{"direction": "egress", "action": "allow", "ports": [53, 53]},
		{"direction": "egress", "action": "deny",  "ports": [1, 100]}
	]`, `{}`)
	recorder = doRequest(router, http.MethodPost, "/v1/net-policies", swappedRulesBody)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("changed rule order: status = %d, want %d; body %s",
			recorder.Code, http.StatusConflict, recorder.Body.String())
	}
	assertExactErrorShape(t, recorder, "NetPolicyConflictError")
	assertSafeErrorMessage(t, recorder)

	// Same identity, a changed plugin string value: 409.
	changedParamBody := singleRuleBody("payments", "seed", "tier=backend", "ingress", "deny", 80, 100,
		`{"mode": "audit", "zone": "east"}`)
	recorder = doRequest(router, http.MethodPost, "/v1/net-policies", changedParamBody)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("changed plugin value: status = %d, want %d; body %s",
			recorder.Code, http.StatusConflict, recorder.Body.String())
	}
	assertExactErrorShape(t, recorder, "NetPolicyConflictError")
	assertSafeErrorMessage(t, recorder)

	// Invalid input on fresh identities: 400, published error envelope.
	invalidCases := []struct {
		name string
		body string
	}{
		{"port zero", singleRuleBody("payments", "bad-zero", "tier=backend", "ingress", "allow", 0, 80, `{}`)},
		{"port above 65535", singleRuleBody("payments", "bad-high", "tier=backend", "ingress", "allow", 1, 65536, `{}`)},
		{"inverted interval", policyWithRules("payments", "bad-inverted", "tier=backend",
			`[{"direction": "ingress", "action": "allow", "ports": [443, 80]}]`, `{}`)},
		{"illegal direction", singleRuleBody("payments", "bad-direction", "tier=backend", "sideways", "allow", 80, 80, `{}`)},
	}
	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := doRequest(router, http.MethodPost, "/v1/net-policies", tc.body)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("input %s: status = %d, want %d; body %s",
					tc.body, recorder.Code, http.StatusBadRequest, recorder.Body.String())
			}
			assertExactErrorShape(t, recorder, "InvalidNetPolicyInputError")
			assertSafeErrorMessage(t, recorder)
		})
	}

	// Nothing was added and no committed field, order or flag changed.
	items := listItems(t, router, "/v1/net-policies?namespace=payments")
	if want := []map[string]any{seed, clash, ordered}; !reflect.DeepEqual(items, want) {
		t.Fatalf("registry after rejects/retries:\nitems = %#v\n want %#v", items, want)
	}

	// The next legal new identity continues at the current maximum order + 1.
	// ingress deny [300,400] is disjoint from the ingress allow [100,200]
	// history rule and shares an action with ingress deny [80,100], so it must
	// land conflict-free.
	nextBody := singleRuleBody("payments", "after-boundaries", "tier=backend", "ingress", "deny", 300, 400, `{}`)
	next := mustCreated(t, router, nextBody, "legal ingress deny [300,400] after all rejected attempts", 4, false)
	if next["order"] != float64(4) {
		t.Fatalf("next record order = %v, want 4 (rejects and retries must not consume an order)", next["order"])
	}
}
