package api

// Concurrent regression tests for the public HTTP surface. Unlike the store
// level concurrency test, these drive a real HTTP server (one service instance
// backed by a healthy on-disk SQLite store) through POST /v1/net-policies and
// GET /v1/net-policies so the assertions cover the externally visible results:
// status codes, response bodies, ordering and the published error shape.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bob-xisuke/orb-netpolicy-guard/internal/store"
)

const (
	clientTimeout = 10 * time.Second
	// roundBudget bounds every wait inside one round (reader startup, the
	// whole write burst, reader shutdown): waiting longer than ten seconds
	// fails the round rather than hanging the suite.
	roundBudget = 10 * time.Second
)

const (
	raceNamespace = "payments"
	raceName      = "race-policy"
	raceLabel     = "tier=backend"
)

// The two racing groups are identical except for one legal plugin string value
// ("mode"); "zone" and the rules stay identical across the groups.
const raceBodyA = `{
	"namespace": "payments",
	"name": "race-policy",
	"label": "tier=backend",
	"rules": [{"direction": "ingress", "action": "deny", "ports": [80, 100]}],
	"pluginParams": {"mode": "enforce", "zone": "east"}
}`

// Equivalent content for group A: top-level members, rule members and
// pluginParams members all appear in a different order.
const raceBodyAReordered = `{
	"pluginParams": {"zone": "east", "mode": "enforce"},
	"rules": [{"ports": [80, 100], "action": "deny", "direction": "ingress"}],
	"label": "tier=backend",
	"name": "race-policy",
	"namespace": "payments"
}`

const raceBodyB = `{
	"namespace": "payments",
	"name": "race-policy",
	"label": "tier=backend",
	"rules": [{"direction": "ingress", "action": "deny", "ports": [80, 100]}],
	"pluginParams": {"mode": "audit", "zone": "east"}
}`

// Equivalent content for group B with object members reordered.
const raceBodyBReordered = `{
	"pluginParams": {"zone": "east", "mode": "audit"},
	"rules": [{"ports": [80, 100], "action": "deny", "direction": "ingress"}],
	"label": "tier=backend",
	"name": "race-policy",
	"namespace": "payments"
}`

// Same identity with a null plugin member racing with the legal submissions:
// always invalid input, regardless of how far the other requests have got.
const raceBodyNullMember = `{
	"namespace": "payments",
	"name": "race-policy",
	"label": "tier=backend",
	"rules": [{"direction": "ingress", "action": "deny", "ports": [80, 100]}],
	"pluginParams": {"zone": "east", "mode": null}
}`

type postOutcome struct {
	kind   string // "A", "B" or "null"
	status int
	body   []byte
	err    error
}

type queryObservation struct {
	target string
	status int
	body   []byte
	err    error
}

// newConcurrentTestServer starts a real HTTP server backed by a fresh SQLite
// file so concurrent clients exercise the genuinely published entry points.
func newConcurrentTestServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	server := httptest.NewServer(NewRouter(st))
	t.Cleanup(func() {
		server.Close()
		st.Close()
	})
	return server, st
}

func clientRequest(client *http.Client, method, target, body string) (int, []byte, error) {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, target, reader)
	if err != nil {
		return 0, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, raw, nil
}

// assertExactErrorBytes is the []byte counterpart of assertExactErrorShape:
// exactly one top-level "error" object holding string code and non-empty
// message, with no other members.
func assertExactErrorBytes(t *testing.T, status int, raw []byte, wantStatus int, wantCode string) {
	t.Helper()
	if status != wantStatus {
		t.Fatalf("status = %d, want %d: %s", status, wantStatus, string(raw))
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if len(top) != 1 {
		t.Fatalf("error body has %d top-level keys, want exactly one (error): %s", len(top), string(raw))
	}
	errRaw, ok := top["error"]
	if !ok {
		t.Fatalf("error body missing top-level error object: %s", string(raw))
	}
	var errObj map[string]json.RawMessage
	if err := json.Unmarshal(errRaw, &errObj); err != nil {
		t.Fatalf("error member is not an object: %v", err)
	}
	if len(errObj) != 2 {
		t.Fatalf("error object has %d members, want exactly code and message: %s", len(errObj), string(raw))
	}
	var code, message string
	if err := json.Unmarshal(errObj["code"], &code); err != nil {
		t.Fatalf("error.code is not a string: %s", string(raw))
	}
	if err := json.Unmarshal(errObj["message"], &message); err != nil {
		t.Fatalf("error.message is not a string: %s", string(raw))
	}
	if code != wantCode {
		t.Fatalf("error.code = %q, want %q (body %s)", code, wantCode, string(raw))
	}
	if message == "" {
		t.Fatalf("error.message is empty: %s", string(raw))
	}
	for _, leak := range []string{"sql", "sqlite", "goroutine", ".go:", "panic", "/", "\\"} {
		if strings.Contains(strings.ToLower(message), leak) {
			t.Fatalf("error.message leaks %q: %s", leak, message)
		}
	}
}

func decodeRecord(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatalf("decode record %s: %v", string(raw), err)
	}
	return record
}

// formatPostOutcomes renders every collected POST result so a failure reports
// the request kind, status, transport error and body the round actually saw.
func formatPostOutcomes(results []postOutcome) string {
	var b strings.Builder
	fmt.Fprintf(&b, "collected %d POST outcome(s):", len(results))
	for i, r := range results {
		fmt.Fprintf(&b, "\n  [%d] kind=%s status=%d err=%v body=%s",
			i, r.kind, r.status, r.err, string(r.body))
	}
	return b.String()
}

// formatQueryObservations renders every GET observation collected during the
// registration burst.
func formatQueryObservations(observations []queryObservation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "collected %d GET observation(s):", len(observations))
	for i, o := range observations {
		fmt.Fprintf(&b, "\n  [%d] target=%s status=%d err=%v body=%s",
			i, o.target, o.status, o.err, string(o.body))
	}
	return b.String()
}

// drainOutcomes snapshots whatever POST outcomes have arrived so far; used to
// report partial results when the burst does not finish inside the round budget.
func drainOutcomes(ch <-chan postOutcome) []postOutcome {
	results := make([]postOutcome, 0, cap(ch))
	for {
		select {
		case r := <-ch:
			results = append(results, r)
		default:
			return results
		}
	}
}

// drainObservations snapshots the GET observations gathered so far.
func drainObservations(ch <-chan queryObservation) []queryObservation {
	observations := make([]queryObservation, 0)
	for {
		select {
		case o := <-ch:
			observations = append(observations, o)
		default:
			return observations
		}
	}
}

// Empty store, same namespace and policy name: two content groups differing in
// one legal plugin string value race to register, each group including
// equivalent submissions with object members reordered, alongside requests
// carrying a null plugin member and queries issued during the burst. Exactly
// one 201 fixes the winning content; the winning group's other requests return
// 200 with that same record, the losing group all 409, and the null requests
// all 400. Queries are proven 404 against the empty store beforehand; during
// the burst every observation is either 404 or 200 carrying the single eventual
// winning record, but observing either state mid-flight is never itself a pass
// condition — all writes are allowed to finish before the next read is
// scheduled. Final state is checked through both filters and their intersection.
func TestConcurrentHTTPSameIdentityRace(t *testing.T) {
	// Repeat against fresh databases: the winning group may differ per round.
	for round := 0; round < 3; round++ {
		t.Run(fmt.Sprintf("round%d", round), func(t *testing.T) {
			server, _ := newConcurrentTestServer(t)
			client := &http.Client{Timeout: clientTimeout}

			// One deadline covers every wait in the round: readers becoming
			// ready, the whole write burst and reader shutdown.
			deadline := time.NewTimer(roundBudget)
			defer deadline.Stop()

			submissions := []struct {
				kind string
				body string
			}{
				{"A", raceBodyA},
				{"A", raceBodyA},
				{"A", raceBodyAReordered},
				{"A", raceBodyAReordered},
				{"B", raceBodyB},
				{"B", raceBodyB},
				{"B", raceBodyBReordered},
				{"B", raceBodyBReordered},
				{"null", raceBodyNullMember},
				{"null", raceBodyNullMember},
			}

			queryTargets := []string{
				server.URL + "/v1/net-policies?namespace=payments",
				server.URL + "/v1/net-policies?label=tier%3Dbackend",
			}
			intersectionTarget := server.URL + "/v1/net-policies?namespace=payments&label=tier%3Dbackend"

			// Deterministic pre-registration check: a query on the empty store
			// is 404 with the published shape, for both filters. The concurrent
			// readers below therefore never need to "happen to" catch 404.
			for _, target := range queryTargets {
				status, body, err := clientRequest(client, http.MethodGet, target, "")
				if err != nil {
					t.Fatalf("pre-registration GET %s failed: %v", target, err)
				}
				assertExactErrorBytes(t, status, body, http.StatusNotFound, "NetPolicyNotFoundError")
			}

			// Readers run while the burst is in flight and stop only once every
			// write has returned. stop runs on every exit path (including a
			// fatal failure) so goroutines and the server are always released.
			stopReaders := make(chan struct{})
			var stopOnce sync.Once
			stop := func() { stopOnce.Do(func() { close(stopReaders) }) }
			t.Cleanup(stop)

			readerReady := make(chan struct{}, 4)
			var readers sync.WaitGroup
			observations := make(chan queryObservation, 65536)
			for i := 0; i < 4; i++ {
				readers.Add(1)
				go func(id int) {
					defer readers.Done()
					ready := false
					for attempts := 0; ; attempts++ {
						select {
						case <-stopReaders:
							return
						default:
						}
						target := queryTargets[(id+attempts)%len(queryTargets)]
						status, body, err := clientRequest(client, http.MethodGet, target, "")
						select {
						case observations <- queryObservation{target: target, status: status, body: body, err: err}:
						default:
						}
						if !ready {
							ready = true
							readerReady <- struct{}{}
						}
						runtime.Gosched()
					}
				}(i)
			}

			// Release writers only after readers are already querying; whether
			// a reader then catches the committed row is left to scheduling.
			for ready := 0; ready < 2; ready++ {
				select {
				case <-readerReady:
				case <-deadline.C:
					t.Fatalf("round timed out before %d readers became ready\n%s",
						2, formatQueryObservations(drainObservations(observations)))
				}
			}

			start := make(chan struct{})
			var writers sync.WaitGroup
			outcomes := make(chan postOutcome, len(submissions))
			for _, submission := range submissions {
				writers.Add(1)
				go func(submission struct {
					kind string
					body string
				}) {
					defer writers.Done()
					<-start
					status, body, err := clientRequest(client, http.MethodPost,
						server.URL+"/v1/net-policies", submission.body)
					outcomes <- postOutcome{kind: submission.kind, status: status, body: body, err: err}
				}(submission)
			}

			close(start)
			writersDone := make(chan struct{})
			go func() {
				writers.Wait()
				close(writersDone)
			}()
			select {
			case <-writersDone:
			case <-deadline.C:
				partial := drainOutcomes(outcomes)
				t.Fatalf("round timed out waiting for the registration burst to finish\n%s\n%s",
					formatPostOutcomes(partial),
					formatQueryObservations(drainObservations(observations)))
			}

			// All writes are allowed to complete before readers wind down:
			// catching 200 during this window is best-effort, never required.
			stop()
			readersDone := make(chan struct{})
			go func() {
				readers.Wait()
				close(readersDone)
			}()
			select {
			case <-readersDone:
			case <-deadline.C:
				t.Fatalf("round timed out stopping readers\n%s\n%s",
					formatPostOutcomes(drainOutcomes(outcomes)),
					formatQueryObservations(drainObservations(observations)))
			}

			results := drainOutcomes(outcomes)
			raceObservations := drainObservations(observations)
			if len(results) != len(submissions) {
				t.Fatalf("collected %d POST results, want %d\n%s",
					len(results), len(submissions), formatPostOutcomes(results))
			}

			for _, result := range results {
				if result.err != nil {
					t.Fatalf("POST %s failed: %v\n%s", result.kind, result.err,
						formatPostOutcomes(results))
				}
			}

			wantByGroup := map[string]map[string]any{
				"A": wantRecord(t, raceBodyA, 1, false),
				"B": wantRecord(t, raceBodyB, 1, false),
			}

			// The single 201 response determines the winner; nothing here
			// prescribes which content wins or relies on arrival order.
			var winner map[string]any
			winnerKind := ""
			created, okStatus, rejected := 0, 0, 0
			for _, result := range results {
				switch result.status {
				case http.StatusCreated:
					created++
					winner = decodeRecord(t, result.body)
				case http.StatusOK:
					okStatus++
				case http.StatusConflict:
				case http.StatusBadRequest:
					rejected++
				default:
					t.Fatalf("unexpected POST status %d for kind %s: %s\n%s",
						result.status, result.kind, string(result.body),
						formatPostOutcomes(results))
				}
			}
			if created != 1 {
				t.Fatalf("created = %d responses, want exactly one 201\n%s",
					created, formatPostOutcomes(results))
			}
			if mode, _ := winner["pluginParams"].(map[string]any)["mode"].(string); mode == "enforce" {
				winnerKind = "A"
			} else if mode == "audit" {
				winnerKind = "B"
			} else {
				t.Fatalf("winning record pluginParams.mode = %v, want enforce or audit\nwinner=%v",
					winner["pluginParams"], winner)
			}
			t.Logf("group %s (mode=%s) won the registration race", winnerKind,
				winner["pluginParams"].(map[string]any)["mode"])
			if !reflect.DeepEqual(winner, wantByGroup[winnerKind]) {
				t.Fatalf("winning record = %v, want the full %s submission with order 1 conflict false",
					winner, winnerKind)
			}
			if winner["order"] != float64(1) || winner["conflict"] != false {
				t.Fatalf("winner order/conflict = %v/%v, want 1/false", winner["order"], winner["conflict"])
			}

			winnerPeers, loserPeers := 0, 0
			for _, result := range results {
				switch result.kind {
				case winnerKind:
					if result.status == http.StatusCreated {
						continue
					}
					// Remaining requests with the winning content are idempotent
					// retries: 200 with the same original record.
					if result.status != http.StatusOK {
						t.Fatalf("winning group peer status = %d, want 200: %s\n%s",
							result.status, string(result.body), formatPostOutcomes(results))
					}
					if got := decodeRecord(t, result.body); !reflect.DeepEqual(got, winner) {
						t.Fatalf("200 record = %v, want the original winning record %v", got, winner)
					}
					winnerPeers++
				case "null":
					assertExactErrorBytes(t, result.status, result.body,
						http.StatusBadRequest, "InvalidNetPolicyInputError")
				default:
					// Every request in the other group loses with 409.
					assertExactErrorBytes(t, result.status, result.body,
						http.StatusConflict, "NetPolicyConflictError")
					loserPeers++
				}
			}
			if winnerPeers != 3 {
				t.Fatalf("winning group 200 peers = %d, want 3\n%s",
					winnerPeers, formatPostOutcomes(results))
			}
			if loserPeers != 4 {
				t.Fatalf("losing group 409 responses = %d, want 4\n%s",
					loserPeers, formatPostOutcomes(results))
			}
			if rejected != 2 || okStatus != 3 {
				t.Fatalf("status counts: 200=%d 400=%d, want 200=3 400=2\n%s",
					okStatus, rejected, formatPostOutcomes(results))
			}

			// Every query observed during the burst is legal: 404, or 200 with
			// exactly one complete record — always the eventual winner, never a
			// duplicate identity, losing content or a field mix. Whether either
			// state was sampled is deliberately irrelevant; all writes may have
			// finished before the next scheduled read.
			for _, observation := range raceObservations {
				if observation.err != nil {
					t.Fatalf("GET %s failed: %v\n%s", observation.target, observation.err,
						formatQueryObservations(raceObservations))
				}
				switch observation.status {
				case http.StatusNotFound:
					assertExactErrorBytes(t, observation.status, observation.body,
						http.StatusNotFound, "NetPolicyNotFoundError")
				case http.StatusOK:
					var body struct {
						Items []map[string]any `json:"items"`
					}
					if err := json.Unmarshal(observation.body, &body); err != nil {
						t.Fatalf("decode items: %v\n%s", err,
							formatQueryObservations(raceObservations))
					}
					if len(body.Items) != 1 {
						t.Fatalf("GET %s returned %d items, want exactly one identity: %s\n%s",
							observation.target, len(body.Items), string(observation.body),
							formatQueryObservations(raceObservations))
					}
					if !reflect.DeepEqual(body.Items[0], winner) {
						t.Fatalf("GET %s item = %v, want the complete winning record %v",
							observation.target, body.Items[0], winner)
					}
				default:
					t.Fatalf("GET during race status = %d for %s: %s\n%s",
						observation.status, observation.target, string(observation.body),
						formatQueryObservations(raceObservations))
				}
			}
			t.Logf("observed %d queries during the burst (%d goroutines)",
				len(raceObservations), 4)

			// Committed state after registration: both filters and their
			// intersection return only the winner, identical in every submitted
			// field plus order and conflict.
			for _, target := range append(queryTargets, intersectionTarget) {
				status, body, err := clientRequest(client, http.MethodGet, target, "")
				if err != nil {
					t.Fatalf("final GET %s: %v", target, err)
				}
				if status != http.StatusOK {
					t.Fatalf("final GET %s status = %d: %s", target, status, string(body))
				}
				var listed struct {
					Items []map[string]any `json:"items"`
				}
				if err := json.Unmarshal(body, &listed); err != nil {
					t.Fatalf("decode final items: %v", err)
				}
				if len(listed.Items) != 1 || !reflect.DeepEqual(listed.Items[0], winner) {
					t.Fatalf("final GET %s items = %v, want exactly %v", target, listed.Items, winner)
				}
			}

			// Failed 409s, 400s and 200 retries consumed no order: the next
			// brand-new identity (egress, so no rule clash with the winner)
			// takes order 2.
			nextBody := singleRuleBody(raceNamespace, "after-race", raceLabel,
				"egress", "allow", 53, 53, `{}`)
			status, body, err := clientRequest(client, http.MethodPost,
				server.URL+"/v1/net-policies", nextBody)
			if err != nil {
				t.Fatalf("POST next: %v", err)
			}
			if status != http.StatusCreated {
				t.Fatalf("next status = %d, want 201: %s", status, string(body))
			}
			if got := decodeRecord(t, body); !reflect.DeepEqual(got, wantRecord(t, nextBody, 2, false)) {
				t.Fatalf("next record = %v, want order 2 (lost and retried requests must not consume order)", got)
			}
		})
	}
}

// Two distinct policy names in one namespace sharing a label register at the
// same time: same direction, opposite actions, closed port intervals touching
// only at one endpoint. Both are 201; the one committed first gets order 1 and
// conflict=false, the other order 2 and conflict=true. Every filter returns
// both complete records in ascending order; retrying the original contents
// gives 200 without touching the flags, and a brand-new identity gets order 3.
func TestConcurrentHTTPTwoPoliciesConflictAndOrdering(t *testing.T) {
	server, _ := newConcurrentTestServer(t)
	client := &http.Client{Timeout: clientTimeout}

	// [80,100] and [100,200] intersect only at the closed endpoint 100.
	denyBody := singleRuleBody("payments", "api-deny", "tier=backend",
		"ingress", "deny", 80, 100, `{"mode": "enforce"}`)
	allowBody := singleRuleBody("payments", "api-allow", "tier=backend",
		"ingress", "allow", 100, 200, `{"mode": "enforce"}`)
	bodyByName := map[string]string{"api-deny": denyBody, "api-allow": allowBody}

	start := make(chan struct{})
	results := make(chan postOutcome, 2)
	for _, body := range []string{denyBody, allowBody} {
		go func(body string) {
			<-start
			status, raw, err := clientRequest(client, http.MethodPost,
				server.URL+"/v1/net-policies", body)
			results <- postOutcome{body: raw, status: status, err: err}
		}(body)
	}
	close(start)

	storedByName := make(map[string]map[string]any, 2)
	var first, second map[string]any
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("concurrent POST failed: %v", result.err)
		}
		if result.status != http.StatusCreated {
			t.Fatalf("status = %d, want 201 for both distinct identities: %s",
				result.status, string(result.body))
		}
		record := decodeRecord(t, result.body)
		name, _ := record["name"].(string)
		storedByName[name] = record
		if first == nil || record["order"].(float64) < first["order"].(float64) {
			second = first
			first = record
		} else {
			second = record
		}
	}

	// Which name commits first is not prescribed; the returned order decides.
	if first["order"] != float64(1) || first["conflict"] != false {
		t.Fatalf("first committed = order %v conflict %v, want 1/false",
			first["order"], first["conflict"])
	}
	if second["order"] != float64(2) || second["conflict"] != true {
		t.Fatalf("second committed = order %v conflict %v, want 2/true",
			second["order"], second["conflict"])
	}
	for order, record := range map[int64]map[string]any{1: first, 2: second} {
		name, _ := record["name"].(string)
		if _, known := bodyByName[name]; !known {
			t.Fatalf("unexpected committed name %q", name)
		}
		want := wantRecord(t, bodyByName[name], order, order == 2)
		if !reflect.DeepEqual(record, want) {
			t.Fatalf("committed %s = %v, want the full submission with order %d and conflict=%v",
				name, record, order, order == 2)
		}
	}

	want := []map[string]any{first, second}
	for _, target := range []string{
		server.URL + "/v1/net-policies?namespace=payments",
		server.URL + "/v1/net-policies?label=tier%3Dbackend",
		server.URL + "/v1/net-policies?namespace=payments&label=tier%3Dbackend",
	} {
		status, raw, err := clientRequest(client, http.MethodGet, target, "")
		if err != nil {
			t.Fatalf("GET %s: %v", target, err)
		}
		if status != http.StatusOK {
			t.Fatalf("GET %s status = %d: %s", target, status, string(raw))
		}
		var body struct {
			Items []map[string]any `json:"items"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("decode items: %v", err)
		}
		if !reflect.DeepEqual(body.Items, want) {
			t.Fatalf("GET %s items = %v, want both complete records ascending by order",
				target, body.Items)
		}
	}

	// Retry the original contents (one with reordered object members): 200 and
	// the stored records, conflict flags included, come back untouched.
	denyRetry := `{
		"pluginParams": {"mode": "enforce"},
		"rules": [{"ports": [80, 100], "action": "deny", "direction": "ingress"}],
		"label": "tier=backend",
		"name": "api-deny",
		"namespace": "payments"
	}`
	for _, retry := range []struct {
		name string
		body string
	}{
		{"api-deny", denyRetry},
		{"api-allow", allowBody},
	} {
		status, raw, err := clientRequest(client, http.MethodPost,
			server.URL+"/v1/net-policies", retry.body)
		if err != nil {
			t.Fatalf("retry POST: %v", err)
		}
		if status != http.StatusOK {
			t.Fatalf("retry status = %d, want 200: %s", status, string(raw))
		}
		if got := decodeRecord(t, raw); !reflect.DeepEqual(got, storedByName[retry.name]) {
			t.Fatalf("retry record = %v, want unchanged original %v", got, storedByName[retry.name])
		}
	}

	// Retries consumed no order: a brand-new identity continues at order 3.
	nextBody := singleRuleBody("payments", "api-next", "tier=backend",
		"egress", "allow", 53, 53, `{}`)
	status, raw, err := clientRequest(client, http.MethodPost,
		server.URL+"/v1/net-policies", nextBody)
	if err != nil {
		t.Fatalf("POST next: %v", err)
	}
	if status != http.StatusCreated {
		t.Fatalf("next status = %d, want 201: %s", status, string(raw))
	}
	if got := decodeRecord(t, raw); !reflect.DeepEqual(got, wantRecord(t, nextBody, 3, false)) {
		t.Fatalf("next record = %v, want full submission with order 3", got)
	}
}
