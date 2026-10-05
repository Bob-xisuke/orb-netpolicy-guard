package store

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func samplePolicy(namespace, name string) NetPolicy {
	return NetPolicy{
		Namespace:    namespace,
		Name:         name,
		Label:        "web",
		Rules:        []Rule{{Direction: "ingress", Action: "allow", Ports: [2]int{80, 80}}},
		PluginParams: map[string]string{"mode": "enforce"},
	}
}

func TestRegisterNetPolicyLifecycle(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	in := samplePolicy("team-a", "p1")
	res, err := st.RegisterNetPolicy(ctx, in)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !res.Created || res.Policy.Order != 1 || res.Policy.Conflict {
		t.Fatalf("unexpected create result: %+v", res)
	}

	// Same identity, same content, different pluginParams key order: replay.
	replay := in
	replay.PluginParams = map[string]string{"mode": "enforce"}
	res, err = st.RegisterNetPolicy(ctx, replay)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if res.Created || res.Policy.Order != 1 || res.Policy.Conflict {
		t.Fatalf("replay must return the original record without taking an order, got %+v", res)
	}

	// Different content under the same identity: conflict, old record intact.
	diverged := in
	diverged.Rules = []Rule{{Direction: "egress", Action: "deny", Ports: [2]int{1, 1024}}}
	if _, err := st.RegisterNetPolicy(ctx, diverged); err != ErrNetPolicyConflict {
		t.Fatalf("want ErrNetPolicyConflict, got %v", err)
	}
	res, err = st.RegisterNetPolicy(ctx, in)
	if err != nil || res.Policy.Order != 1 || len(res.Policy.Rules) != 1 {
		t.Fatalf("old record changed after conflict: %+v, err=%v", res, err)
	}

	// A new identity takes the next global order.
	res, err = st.RegisterNetPolicy(ctx, samplePolicy("team-a", "p2"))
	if err != nil || !res.Created || res.Policy.Order != 2 {
		t.Fatalf("second policy order = %+v, err=%v", res, err)
	}
}

func TestRegisterNetPolicyRuleOrderIsSignificant(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	ruleA := Rule{Direction: "ingress", Action: "allow", Ports: [2]int{80, 80}}
	ruleB := Rule{Direction: "egress", Action: "deny", Ports: [2]int{1, 1024}}

	first := NetPolicy{
		Namespace: "ns", Name: "p", Label: "web",
		Rules:        []Rule{ruleA, ruleB},
		PluginParams: map[string]string{},
	}
	if _, err := st.RegisterNetPolicy(ctx, first); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Same rules, same identity, reversed array order: content differs.
	reversed := first
	reversed.Rules = []Rule{ruleB, ruleA}
	if _, err := st.RegisterNetPolicy(ctx, reversed); err != ErrNetPolicyConflict {
		t.Fatalf("reversed rule order must conflict, got %v", err)
	}

	// Same array order replays even when the slice is freshly allocated.
	again := first
	again.Rules = []Rule{
		{Direction: "ingress", Action: "allow", Ports: [2]int{80, 80}},
		{Direction: "egress", Action: "deny", Ports: [2]int{1, 1024}},
	}
	res, err := st.RegisterNetPolicy(ctx, again)
	if err != nil || res.Created {
		t.Fatalf("identical ordered rules must replay, got created=%v err=%v", res.Created, err)
	}
}

func TestRegisterNetPolicyConflictDetection(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name      string
		first     Rule
		second    Rule
		want      bool
		sameLabel bool
	}{
		{"opposite action overlapping ports",
			Rule{Direction: "ingress", Action: "allow", Ports: [2]int{80, 100}},
			Rule{Direction: "ingress", Action: "deny", Ports: [2]int{90, 110}}, true, true},
		{"opposite action touching endpoint",
			Rule{Direction: "ingress", Action: "allow", Ports: [2]int{80, 100}},
			Rule{Direction: "ingress", Action: "deny", Ports: [2]int{100, 120}}, true, true},
		{"opposite action disjoint ports",
			Rule{Direction: "ingress", Action: "allow", Ports: [2]int{80, 100}},
			Rule{Direction: "ingress", Action: "deny", Ports: [2]int{101, 120}}, false, true},
		{"different directions",
			Rule{Direction: "ingress", Action: "allow", Ports: [2]int{80, 100}},
			Rule{Direction: "egress", Action: "deny", Ports: [2]int{90, 100}}, false, true},
		{"same action",
			Rule{Direction: "ingress", Action: "allow", Ports: [2]int{80, 100}},
			Rule{Direction: "ingress", Action: "allow", Ports: [2]int{90, 100}}, false, true},
		{"different label",
			Rule{Direction: "ingress", Action: "allow", Ports: [2]int{80, 100}},
			Rule{Direction: "ingress", Action: "deny", Ports: [2]int{90, 100}}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newTestStore(t)
			first := samplePolicy("ns", "old")
			first.Rules = []Rule{tc.first}
			if _, err := st.RegisterNetPolicy(ctx, first); err != nil {
				t.Fatalf("register first: %v", err)
			}
			second := samplePolicy("ns", "new")
			second.Rules = []Rule{tc.second}
			if !tc.sameLabel {
				second.Label = "other-label"
			}
			res, err := st.RegisterNetPolicy(ctx, second)
			if err != nil {
				t.Fatalf("register second: %v", err)
			}
			if res.Policy.Conflict != tc.want {
				t.Fatalf("conflict = %v, want %v", res.Policy.Conflict, tc.want)
			}
			// Older records must never be mutated.
			old, err := st.RegisterNetPolicy(ctx, first)
			if err != nil || old.Created || old.Policy.Conflict {
				t.Fatalf("old record mutated: created=%v conflict=%v err=%v", old.Created, old.Policy.Conflict, err)
			}
		})
	}
}

func TestRegisterNetPolicyPersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "persist.db")

	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	in := samplePolicy("ns", "p")
	in.PluginParams = map[string]string{"x": "y"}
	if _, err := st.RegisterNetPolicy(ctx, in); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	got, err := reopened.ListNetPolicies(ctx, strPtr("ns"), nil)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].Order != 1 || got[0].PluginParams["x"] != "y" {
		t.Fatalf("record did not survive reopen: %+v", got)
	}
	// Re-registration after reopen is still an idempotent replay.
	res, err := reopened.RegisterNetPolicy(ctx, in)
	if err != nil || res.Created {
		t.Fatalf("replay after reopen: created=%v err=%v", res.Created, err)
	}
}

func TestConcurrentRegisterSameIdentity(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	const n = 16
	var wg sync.WaitGroup
	start := make(chan struct{})
	creates := make(chan bool, n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			res, err := st.RegisterNetPolicy(ctx, samplePolicy("ns", "same"))
			if err != nil {
				errs <- err
				return
			}
			creates <- res.Created
		}()
	}
	close(start)
	wg.Wait()
	close(creates)
	close(errs)

	for err := range errs {
		t.Fatalf("concurrent register error: %v", err)
	}
	createdCount := 0
	for created := range creates {
		if created {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Fatalf("created count = %d, want exactly 1", createdCount)
	}
	got, err := st.ListNetPolicies(ctx, strPtr("ns"), nil)
	if err != nil || len(got) != 1 {
		t.Fatalf("exactly one record must exist, got %d, err=%v", len(got), err)
	}
}

func TestConcurrentRegisterDistinctIdentitiesGetUniqueOrders(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	const n = 24
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, n)
	orders := make(chan int64, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			res, err := st.RegisterNetPolicy(ctx, samplePolicy("ns", fmt.Sprintf("p-%d", i)))
			if err != nil {
				errs <- err
				return
			}
			orders <- res.Policy.Order
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	close(orders)
	for err := range errs {
		t.Fatalf("concurrent register error: %v", err)
	}
	seen := map[int64]bool{}
	for o := range orders {
		if seen[o] {
			t.Fatalf("duplicate order %d", o)
		}
		seen[o] = true
	}
	if len(seen) != n {
		t.Fatalf("got %d distinct orders, want %d", len(seen), n)
	}
}

func TestListNetPoliciesFiltersAndOrder(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	mk := func(ns, name, label string, rule Rule) NetPolicy {
		p := samplePolicy(ns, name)
		p.Label = label
		p.Rules = []Rule{rule}
		return p
	}
	allow := func(dir string) Rule { return Rule{Direction: dir, Action: "allow", Ports: [2]int{1, 2}} }

	if _, err := st.RegisterNetPolicy(ctx, mk("a", "1", "red", allow("ingress"))); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RegisterNetPolicy(ctx, mk("a", "2", "blue", allow("ingress"))); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RegisterNetPolicy(ctx, mk("b", "3", "red", allow("ingress"))); err != nil {
		t.Fatal(err)
	}

	byNamespace, err := st.ListNetPolicies(ctx, strPtr("a"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(byNamespace) != 2 || byNamespace[0].Name != "1" || byNamespace[1].Name != "2" {
		t.Fatalf("namespace filter/order wrong: %+v", byNamespace)
	}

	byLabel, err := st.ListNetPolicies(ctx, nil, strPtr("red"))
	if err != nil || len(byLabel) != 2 {
		t.Fatalf("label filter wrong: %+v err=%v", byLabel, err)
	}

	intersection, err := st.ListNetPolicies(ctx, strPtr("a"), strPtr("red"))
	if err != nil || len(intersection) != 1 || intersection[0].Name != "1" {
		t.Fatalf("intersection wrong: %+v err=%v", intersection, err)
	}

	none, err := st.ListNetPolicies(ctx, strPtr("missing"), nil)
	if err != nil || len(none) != 0 {
		t.Fatalf("empty result wrong: %+v err=%v", none, err)
	}
}

func TestContentComparisonKeyOrderIrrelevant(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	p := NetPolicy{
		Namespace: "ns", Name: "p", Label: "l",
		Rules:        []Rule{{Direction: "ingress", Action: "allow", Ports: [2]int{80, 80}}},
		PluginParams: map[string]string{"a": "1", "b": "2", "c": "3"},
	}
	if _, err := st.RegisterNetPolicy(ctx, p); err != nil {
		t.Fatal(err)
	}
	// Same content with keys inserted in a different order still replays.
	p2 := p
	p2.PluginParams = map[string]string{}
	for _, k := range []string{"c", "a", "b"} {
		p2.PluginParams[k] = p.PluginParams[k]
	}
	res, err := st.RegisterNetPolicy(ctx, p2)
	if err != nil || res.Created {
		t.Fatalf("key order must not matter: created=%v err=%v", res.Created, err)
	}
}

func TestRulesConflictIsSymmetric(t *testing.T) {
	allow := Rule{Direction: "ingress", Action: "allow", Ports: [2]int{80, 90}}
	deny := Rule{Direction: "ingress", Action: "deny", Ports: [2]int{85, 95}}
	if !rulesConflict(allow, deny) || !rulesConflict(deny, allow) {
		t.Fatal("rule conflict should be symmetric")
	}
}

func strPtr(s string) *string { return &s }
