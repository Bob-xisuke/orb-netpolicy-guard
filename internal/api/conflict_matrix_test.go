package api

// Exhaustive system regression coverage for the closed-port-interval conflict
// rule, complementing the fixed cases in conflict_test.go.
//
// The coverage set is every legal closed port interval whose two endpoints are
// drawn from {1, 2, 3, 65534, 65535}: 5*(5+1)/2 = 15 intervals. Every ordered
// pair of intervals in the set is compared (an interval paired with itself
// included), every legal combination of the two directions is exercised
// (ingress/ingress, ingress/egress, egress/ingress, egress/egress) and every
// legal combination of the two actions (allow/allow, allow/deny, deny/allow,
// deny/deny): 15*15*4*4 = 3600 cells. Endpoint contact ([1,2] versus [2,3]),
// wide-gap separation ([1,3] versus [65534,65535]), single-point intervals and
// the 1/65535 bounds all appear as concrete cases.
//
// Expected flags are computed in this file from the rule published in
// README.md — same namespace and label, same direction, opposite actions and
// closed intervals sharing at least one port — never read from the store's
// detection function. Every cell registers the old record first and the new
// record through POST /v1/net-policies and then reads both back through
// GET /v1/net-policies (the namespace+label intersection query), so persisted
// conflict flags, order and content are all checked. The whole set runs twice
// against fresh databases: repeating the same set must produce identical
// results. Namespace-only, label-only and 404 query precision for these records
// are covered in conflict_multi_history_test.go.

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/Bob-xisuke/orb-netpolicy-guard/internal/store"
)

// newMatrixRouter builds a router backed by a private in-memory database. The
// matrix performs thousands of registrations; keeping SQLite out of the working
// directory (which may sit on a slow mounted filesystem) lets the exhaustive
// set run quickly without weakening anything — traffic still goes through the
// full HTTP stack and the real store. Every matrix pass gets its own database,
// and cells stay isolated through distinct namespace/label pairs.
func newMatrixRouter(t *testing.T) *gin.Engine {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open in-memory store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return NewRouter(st)
}

// conflictMatrixEndpoints pins the endpoint values required by the regression
// brief; legalClosedIntervals derives the coverage set from them.
var conflictMatrixEndpoints = []int{1, 2, 3, 65534, 65535}

type matrixRule struct {
	direction string
	action    string
	ports     [2]int
}

// matrixCellObservation is everything one comparison cell exposes; comparing
// observations from two independent runs is the determinism check.
type matrixCellObservation struct {
	oldStatus int
	newStatus int

	oldRecord map[string]any
	newRecord map[string]any

	items []map[string]any
}

// legalClosedIntervals returns every interval [lo, hi] with lo <= hi whose
// endpoints are drawn from the given ascending endpoint list. Those are exactly
// the intervals the published contract allows (1..65535, low endpoint no
// greater than high endpoint).
func legalClosedIntervals(endpoints []int) [][2]int {
	intervals := make([][2]int, 0, len(endpoints)*(len(endpoints)+1)/2)
	for i, lo := range endpoints {
		for _, hi := range endpoints[i:] {
			intervals = append(intervals, [2]int{lo, hi})
		}
	}
	return intervals
}

// publishedConflictRule is the test-only oracle restating the contract in
// README.md independently of the store: a conflict requires the same namespace
// and label, the same direction, opposite actions and closed intervals that
// share at least one port. Closed intervals sharing exactly an endpoint
// (new[0] == old[1] or old[0] == new[1]) already overlap.
func publishedConflictRule(sameNamespace, sameLabel bool, oldRule, newRule matrixRule) bool {
	return sameNamespace && sameLabel &&
		oldRule.direction == newRule.direction &&
		oldRule.action != newRule.action &&
		newRule.ports[0] <= oldRule.ports[1] && oldRule.ports[0] <= newRule.ports[1]
}

// matrixCellInput renders one cell's full input for failure messages: both
// directions, actions and intervals plus the scope decision.
func matrixCellInput(ns, label string, oldRule, newRule matrixRule) string {
	return fmt.Sprintf(
		"input: namespace=%q label=%q old={direction:%q action:%q ports:[%d,%d]} new={direction:%q action:%q ports:[%d,%d]}",
		ns, label,
		oldRule.direction, oldRule.action, oldRule.ports[0], oldRule.ports[1],
		newRule.direction, newRule.action, newRule.ports[0], newRule.ports[1])
}

// runConflictMatrixCell performs the two registrations and the verification
// query for one cell and collects every observable result. The old and new
// records deliberately carry different pluginParams values, since plugin
// parameters must not influence the conflict decision. Each cell lives in its
// own namespace/label pair, so cells sharing one database cannot interfere.
func runConflictMatrixCell(t *testing.T, router *gin.Engine, ns, label string, oldRule, newRule matrixRule) matrixCellObservation {
	t.Helper()
	input := matrixCellInput(ns, label, oldRule, newRule)

	oldBody := singleRuleBody(ns, "old-record", label,
		oldRule.direction, oldRule.action, oldRule.ports[0], oldRule.ports[1], `{"mode":"enforce"}`)
	newBody := singleRuleBody(ns, "new-record", label,
		newRule.direction, newRule.action, newRule.ports[0], newRule.ports[1], `{"mode":"audit"}`)

	oldRecorder := doRequest(router, http.MethodPost, "/v1/net-policies", oldBody)
	if oldRecorder.Code != http.StatusCreated {
		t.Fatalf("%s\nold registration status = %d, want %d: %s",
			input, oldRecorder.Code, http.StatusCreated, oldRecorder.Body.String())
	}
	newRecorder := doRequest(router, http.MethodPost, "/v1/net-policies", newBody)
	if newRecorder.Code != http.StatusCreated {
		t.Fatalf("%s\nnew registration status = %d, want %d: %s",
			input, newRecorder.Code, http.StatusCreated, newRecorder.Body.String())
	}

	obs := matrixCellObservation{
		oldStatus: oldRecorder.Code,
		newStatus: newRecorder.Code,
		oldRecord: decodeRecord(t, oldRecorder.Body.Bytes()),
		newRecord: decodeRecord(t, newRecorder.Body.Bytes()),
	}
	target := "/v1/net-policies?namespace=" + url.QueryEscape(ns) + "&label=" + url.QueryEscape(label)
	obs.items = listItems(t, router, target)
	return obs
}

// assertConflictMatrixCell checks one cell against the independently derived
// expectation: the first registration is always 201 with conflict=false, the
// second registration is 201 with the published flag, orders are the two next
// global values, and the verification query returns exactly both complete
// records in ascending order.
func assertConflictMatrixCell(t *testing.T, input string, seq int, want bool, obs matrixCellObservation) {
	t.Helper()

	if obs.oldStatus != http.StatusCreated || obs.newStatus != http.StatusCreated {
		t.Fatalf("%s\nregistration statuses = %d/%d, want %d/%d (first and new record both answer 201)",
			input, obs.oldStatus, obs.newStatus, http.StatusCreated, http.StatusCreated)
	}
	if oldConflict := obs.oldRecord["conflict"]; oldConflict != false {
		t.Fatalf("%s\nold record conflict = %v, want false (no history exists yet)", input, oldConflict)
	}
	if newConflict := obs.newRecord["conflict"]; newConflict != want {
		t.Fatalf("%s\nexpected conflict = %v, actual conflict = %v", input, want, newConflict)
	}

	wantOrders := []float64{float64(2*seq + 1), float64(2*seq + 2)}
	if obs.oldRecord["order"] != wantOrders[0] {
		t.Fatalf("%s\nold record order = %v, want %v", input, obs.oldRecord["order"], wantOrders[0])
	}
	if obs.newRecord["order"] != wantOrders[1] {
		t.Fatalf("%s\nnew record order = %v, want %v", input, obs.newRecord["order"], wantOrders[1])
	}

	wantItems := []map[string]any{obs.oldRecord, obs.newRecord}
	if !reflect.DeepEqual(obs.items, wantItems) {
		t.Fatalf("%s\nsaved items = %v\nwant complete records order-ascending %v", input, obs.items, wantItems)
	}
}

// matrixCell is one precomputed case: its stable name, isolated scope, rules and
// the expectation derived from the published rule.
type matrixCell struct {
	name    string
	ns      string
	label   string
	oldRule matrixRule
	newRule matrixRule
	want    bool
}

// buildConflictMatrixCells enumerates the full set deterministically.
func buildConflictMatrixCells() []matrixCell {
	intervals := legalClosedIntervals(conflictMatrixEndpoints)
	directionPairs := [][2]string{
		{"ingress", "ingress"},
		{"ingress", "egress"},
		{"egress", "ingress"},
		{"egress", "egress"},
	}
	actionPairs := [][2]string{
		{"allow", "allow"},
		{"allow", "deny"},
		{"deny", "allow"},
		{"deny", "deny"},
	}

	cells := make([]matrixCell, 0, len(intervals)*len(intervals)*4*4)
	seq := 0
	for _, oldPorts := range intervals {
		for _, newPorts := range intervals {
			for _, dirs := range directionPairs {
				for _, actions := range actionPairs {
					oldRule := matrixRule{direction: dirs[0], action: actions[0], ports: oldPorts}
					newRule := matrixRule{direction: dirs[1], action: actions[1], ports: newPorts}
					cells = append(cells, matrixCell{
						name: fmt.Sprintf("old[%d,%d]_%s_%s__new[%d,%d]_%s_%s",
							oldPorts[0], oldPorts[1], dirs[0], actions[0],
							newPorts[0], newPorts[1], dirs[1], actions[1]),
						ns:      fmt.Sprintf("cell-%04d", seq),
						label:   fmt.Sprintf("tier=cell-%04d", seq),
						oldRule: oldRule,
						newRule: newRule,
						want:    publishedConflictRule(true, true, oldRule, newRule),
					})
					seq++
				}
			}
		}
	}
	return cells
}

// TestConflictMatrixClosedIntervalPairs runs the exhaustive set twice: first
// with per-cell subtests for precise failure attribution, then as a second
// complete execution against a fresh database whose observations must match
// the first pass cell for cell.
func TestConflictMatrixClosedIntervalPairs(t *testing.T) {
	intervals := legalClosedIntervals(conflictMatrixEndpoints)
	if len(intervals) != 15 {
		t.Fatalf("coverage set has %d intervals, want 15 legal closed intervals from endpoints %v",
			len(intervals), conflictMatrixEndpoints)
	}
	cells := buildConflictMatrixCells()
	if len(cells) != 15*15*4*4 {
		t.Fatalf("matrix has %d cells, want %d (15*15 ordered interval pairs, 4 direction pairs, 4 action pairs)",
			len(cells), 15*15*4*4)
	}

	routerA := newMatrixRouter(t)
	firstPass := make([]matrixCellObservation, len(cells))
	for seq, cell := range cells {
		t.Run(cell.name, func(t *testing.T) {
			input := matrixCellInput(cell.ns, cell.label, cell.oldRule, cell.newRule)
			obs := runConflictMatrixCell(t, routerA, cell.ns, cell.label, cell.oldRule, cell.newRule)
			assertConflictMatrixCell(t, input, seq, cell.want, obs)
			firstPass[seq] = obs
		})
	}

	// Second execution of the same set on a fresh database: expectations hold
	// again and every observation matches the first run, so the set is stable
	// under repetition regardless of enumeration order.
	routerB := newMatrixRouter(t)
	for seq, cell := range cells {
		input := matrixCellInput(cell.ns, cell.label, cell.oldRule, cell.newRule)
		obs := runConflictMatrixCell(t, routerB, cell.ns, cell.label, cell.oldRule, cell.newRule)
		assertConflictMatrixCell(t, input, seq, cell.want, obs)
		if !reflect.DeepEqual(obs, firstPass[seq]) {
			t.Fatalf("cell %q is not deterministic\ninput: %s\nfirst run:  %#v\nsecond run: %#v",
				cell.name, input, firstPass[seq], obs)
		}
	}
}

// An empty history is the negative base case: before the first registration the
// namespace/label queries miss with 404 NetPolicyNotFoundError, the first
// registration answers 201 with order 1 and conflict=false even at the extreme
// legal intervals, and the record is then returned complete by every query.
func TestConflictMatrixFirstRegistrationOnEmptyHistory(t *testing.T) {
	router := newMatrixRouter(t)
	directions := []string{"ingress", "egress"}
	actions := []string{"allow", "deny"}

	for i, ports := range legalClosedIntervals(conflictMatrixEndpoints) {
		ns := fmt.Sprintf("empty-%02d", i)
		label := fmt.Sprintf("tier=empty-%02d", i)
		rule := matrixRule{
			direction: directions[i%len(directions)],
			action:    actions[i%len(actions)],
			ports:     ports,
		}
		t.Run(fmt.Sprintf("%d-%d", ports[0], ports[1]), func(t *testing.T) {
			escNamespace := url.QueryEscape(ns)
			escLabel := url.QueryEscape(label)
			for _, target := range []string{
				"/v1/net-policies?namespace=" + escNamespace,
				"/v1/net-policies?label=" + escLabel,
			} {
				miss := doRequest(router, http.MethodGet, target, "")
				if miss.Code != http.StatusNotFound {
					t.Fatalf("GET %s before registration status = %d, want %d",
						target, miss.Code, http.StatusNotFound)
				}
				assertExactErrorShape(t, miss, "NetPolicyNotFoundError")
			}

			body := singleRuleBody(ns, "only-record", label,
				rule.direction, rule.action, ports[0], ports[1], `{}`)
			record := registerCreated(t, router, body, int64(i+1), false)
			wantItems := []map[string]any{record}
			for _, target := range []string{
				"/v1/net-policies?namespace=" + escNamespace,
				"/v1/net-policies?label=" + escLabel,
				"/v1/net-policies?namespace=" + escNamespace + "&label=" + escLabel,
			} {
				if items := listItems(t, router, target); !reflect.DeepEqual(items, wantItems) {
					t.Fatalf("GET %s items = %v, want %v", target, items, wantItems)
				}
			}
		})
	}
}
