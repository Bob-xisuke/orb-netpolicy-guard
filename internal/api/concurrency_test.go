package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
)

// asyncResult captures one finished HTTP exchange launched from a goroutine so
// the main test goroutine can assert on it after the race settles. Response
// arrival order is never treated as the effective order.
type asyncResult struct {
	group string
	code  int
	body  string
}

// replay wraps a captured response so the shared error-shape helpers can
// inspect it like a live recorder.
func replay(result asyncResult) *httptest.ResponseRecorder {
	return &httptest.ResponseRecorder{Code: result.code, Body: bytes.NewBufferString(result.body)}
}

func decodeObject(t *testing.T, body string) map[string]any {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return obj
}

// Concurrent registration of one identity against an empty database: two
// content groups differing in exactly one legal plugin string value race
// together with member-reordered equivalent submissions and invalid
// null-member submissions of the same identity. Exactly one 201 may occur and
// its response defines the winning content; the rest of the winning group sees
// 200 with the original record, the other group sees 409, and the null-member
// requests always see 400. Queries during the race see either nothing yet or
// the single complete winning record, and afterwards only the winner remains
// at order 1 with failures and retries having consumed no order.
func TestConcurrentSameIdentityRegistration(t *testing.T) {
	router, _ := newTestRouter(t)

	const (
		ns    = "race"
		name  = "raced"
		label = "tier=backend"
	)
	// Groups A and B carry identical content except for the "mode" value; each
	// group also includes an equivalent submission with object members
	// reordered at both the top level and inside pluginParams.
	groupA := []string{
		policyBody(ns, name, label, `{"mode": "enforce", "zone": "east"}`),
		`{
			"pluginParams": {"zone": "east", "mode": "enforce"},
			"rules": [{"ports": [80, 80], "action": "allow", "direction": "ingress"}],
			"label": "tier=backend",
			"name": "raced",
			"namespace": "race"
		}`,
	}
	groupB := []string{
		policyBody(ns, name, label, `{"mode": "audit", "zone": "east"}`),
		`{
			"pluginParams": {"zone": "east", "mode": "audit"},
			"rules": [{"ports": [80, 80], "action": "allow", "direction": "ingress"}],
			"label": "tier=backend",
			"name": "raced",
			"namespace": "race"
		}`,
	}
	nullMember := policyBody(ns, name, label, `{"mode": null, "zone": "east"}`)

	const perVariant = 4
	var posters sync.WaitGroup
	start := make(chan struct{})
	results := make(chan asyncResult, 2*2*perVariant+perVariant)
	post := func(group, body string) {
		defer posters.Done()
		<-start
		recorder := doRequest(router, http.MethodPost, "/v1/net-policies", body)
		results <- asyncResult{group: group, code: recorder.Code, body: recorder.Body.String()}
	}
	for _, body := range groupA {
		for i := 0; i < perVariant; i++ {
			posters.Add(1)
			go post("A", body)
		}
	}
	for _, body := range groupB {
		for i := 0; i < perVariant; i++ {
			posters.Add(1)
			go post("B", body)
		}
	}
	for i := 0; i < perVariant; i++ {
		posters.Add(1)
		go post("null", nullMember)
	}

	// Pollers observe the registry while the race runs: every observation must
	// be either "no record yet" or the single complete winning record.
	var pollers sync.WaitGroup
	var mu sync.Mutex
	var polls []asyncResult
	stop := make(chan struct{})
	for i := 0; i < 3; i++ {
		pollers.Add(1)
		go func() {
			defer pollers.Done()
			<-start
			for {
				select {
				case <-stop:
					return
				default:
				}
				recorder := doRequest(router, http.MethodGet, "/v1/net-policies?namespace="+ns, "")
				mu.Lock()
				polls = append(polls, asyncResult{code: recorder.Code, body: recorder.Body.String()})
				mu.Unlock()
			}
		}()
	}

	close(start)
	posters.Wait()
	close(stop)
	pollers.Wait()
	close(results)

	var created []asyncResult
	byGroup := map[string][]asyncResult{}
	for result := range results {
		byGroup[result.group] = append(byGroup[result.group], result)
		if result.code == http.StatusCreated {
			created = append(created, result)
		}
	}
	if len(created) != 1 {
		t.Fatalf("201 responses = %d, want exactly 1: %+v", len(created), created)
	}
	winner := decodeObject(t, created[0].body)

	// The 201 response decides which content won; the test presumes neither
	// the group nor any arrival order.
	wantA := wantRecord(t, groupA[0], 1, false)
	wantB := wantRecord(t, groupB[0], 1, false)
	var winnerGroup, loserGroup string
	switch {
	case reflect.DeepEqual(winner, wantA):
		winnerGroup, loserGroup = "A", "B"
	case reflect.DeepEqual(winner, wantB):
		winnerGroup, loserGroup = "B", "A"
	default:
		t.Fatalf("winning record = %v, want %v or %v", winner, wantA, wantB)
	}

	for _, result := range byGroup[winnerGroup] {
		if result.code == http.StatusCreated {
			continue
		}
		if result.code != http.StatusOK {
			t.Fatalf("winner-group status = %d, want 200: %s", result.code, result.body)
		}
		if got := decodeObject(t, result.body); !reflect.DeepEqual(got, winner) {
			t.Fatalf("retry record = %v, want the original %v", got, winner)
		}
	}
	for _, result := range byGroup[loserGroup] {
		if result.code != http.StatusConflict {
			t.Fatalf("loser-group status = %d, want 409: %s", result.code, result.body)
		}
		assertExactErrorShape(t, replay(result), "NetPolicyConflictError")
		assertSafeErrorMessage(t, replay(result))
	}
	for _, result := range byGroup["null"] {
		if result.code != http.StatusBadRequest {
			t.Fatalf("null-member status = %d, want 400: %s", result.code, result.body)
		}
		assertExactErrorShape(t, replay(result), "InvalidNetPolicyInputError")
		assertSafeErrorMessage(t, replay(result))
	}

	for _, poll := range polls {
		switch poll.code {
		case http.StatusNotFound:
			assertExactErrorShape(t, replay(poll), "NetPolicyNotFoundError")
			assertSafeErrorMessage(t, replay(poll))
		case http.StatusOK:
			var body struct {
				Items []map[string]any `json:"items"`
			}
			if err := json.Unmarshal([]byte(poll.body), &body); err != nil {
				t.Fatalf("decode poll %s: %v", poll.body, err)
			}
			if len(body.Items) != 1 {
				t.Fatalf("poll items = %v, want the single record (no duplicate identities)", body.Items)
			}
			if !reflect.DeepEqual(body.Items[0], winner) {
				t.Fatalf("poll record = %v, want the complete winning record %v (no failed content, no field mixing)", body.Items[0], winner)
			}
		default:
			t.Fatalf("poll status = %d, want 404 or 200: %s", poll.code, poll.body)
		}
	}

	// The final queries hit only the winning record, identical to what the
	// successful registration returned, at order 1.
	for _, target := range []string{
		"/v1/net-policies?namespace=" + ns,
		"/v1/net-policies?label=tier%3Dbackend",
		"/v1/net-policies?namespace=" + ns + "&label=tier%3Dbackend",
	} {
		items := listItems(t, router, target)
		if len(items) != 1 || !reflect.DeepEqual(items[0], winner) {
			t.Fatalf("GET %s items = %v, want only the winning record %v", target, items, winner)
		}
	}

	// Conflicts, rejections and retries consumed no order: a brand-new
	// identity after the race takes order 2.
	fresh := policyBody(ns, "fresh-after-race", label, `{}`)
	registerCreated(t, router, fresh, 2, false)
}

// Two different policy names in the same namespace and label race: same
// direction, opposite actions, port intervals touching only at one endpoint.
// Both are committed with orders 1 and 2; the first committed record is
// conflict-free and the second is flagged. Retries of either original content
// then return 200 with the conflict flags untouched, and a brand-new identity
// continues at order 3.
func TestConcurrentDistinctIdentitiesBothCommitted(t *testing.T) {
	router, _ := newTestRouter(t)

	denyBody := singleRuleBody("payments", "deny-web", "tier=backend", "ingress", "deny", 80, 100, `{"mode": "enforce"}`)
	allowBody := singleRuleBody("payments", "allow-web", "tier=backend", "ingress", "allow", 100, 200, `{"mode": "enforce"}`)

	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan asyncResult, 2)
	for _, body := range []string{denyBody, allowBody} {
		wg.Add(1)
		go func(body string) {
			defer wg.Done()
			<-start
			recorder := doRequest(router, http.MethodPost, "/v1/net-policies", body)
			results <- asyncResult{code: recorder.Code, body: recorder.Body.String()}
		}(body)
	}
	close(start)
	wg.Wait()
	close(results)

	records := map[string]map[string]any{}
	for result := range results {
		if result.code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 for both registrations: %s", result.code, result.body)
		}
		record := decodeObject(t, result.body)
		name, _ := record["name"].(string)
		records[name] = record
	}
	deny, ok := records["deny-web"]
	if !ok {
		t.Fatalf("missing deny-web record: %v", records)
	}
	allow, ok := records["allow-web"]
	if !ok {
		t.Fatalf("missing allow-web record: %v", records)
	}

	// Either policy may win the race for order 1; whichever committed first is
	// conflict-free and the one committed second is flagged.
	var first, second map[string]any
	var firstBody, secondBody string
	switch {
	case deny["order"] == float64(1) && allow["order"] == float64(2):
		first, second, firstBody, secondBody = deny, allow, denyBody, allowBody
	case allow["order"] == float64(1) && deny["order"] == float64(2):
		first, second, firstBody, secondBody = allow, deny, allowBody, denyBody
	default:
		t.Fatalf("orders = %v and %v, want 1 and 2", deny["order"], allow["order"])
	}
	if first["conflict"] != false {
		t.Fatalf("first-committed conflict = %v, want false", first["conflict"])
	}
	if second["conflict"] != true {
		t.Fatalf("second-committed conflict = %v, want true", second["conflict"])
	}
	if want := wantRecord(t, firstBody, 1, false); !reflect.DeepEqual(first, want) {
		t.Fatalf("first record = %v, want %v", first, want)
	}
	if want := wantRecord(t, secondBody, 2, true); !reflect.DeepEqual(second, want) {
		t.Fatalf("second record = %v, want %v", second, want)
	}

	// Namespace, label and intersection queries all return both complete
	// records ascending by order.
	wantItems := []map[string]any{first, second}
	for _, target := range []string{
		"/v1/net-policies?namespace=payments",
		"/v1/net-policies?label=tier%3Dbackend",
		"/v1/net-policies?namespace=payments&label=tier%3Dbackend",
	} {
		items := listItems(t, router, target)
		if !reflect.DeepEqual(items, wantItems) {
			t.Fatalf("GET %s items = %v, want %v (ascending by order)", target, items, wantItems)
		}
	}

	// Retrying each original content returns 200 with the committed record,
	// its conflict flag unchanged.
	for _, tc := range []struct {
		body string
		want map[string]any
	}{{denyBody, deny}, {allowBody, allow}} {
		recorder := doRequest(router, http.MethodPost, "/v1/net-policies", tc.body)
		if recorder.Code != http.StatusOK {
			t.Fatalf("retry status = %d, want 200: %s", recorder.Code, recorder.Body.String())
		}
		if got := decodeObject(t, recorder.Body.String()); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("retry record = %v, want unchanged %v", got, tc.want)
		}
	}

	// A brand-new identity after the race continues at order 3.
	nextBody := singleRuleBody("payments", "after-race", "tier=backend", "egress", "allow", 53, 53, `{}`)
	registerCreated(t, router, nextBody, 3, false)
}
