package store

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

func TestOpenCreatesUsableStore(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	if err := st.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

func sampleRecord() Record {
	return Record{
		Namespace: "payments",
		Name:      "default-deny",
		Label:     "tier=backend",
		Rules: []Rule{
			{Direction: "ingress", Action: "deny", Ports: [2]int{1, 65535}},
		},
		PluginParams: map[string]string{"mode": "enforce"},
	}
}

func TestRegisterAssignsSequentialOrder(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	first := sampleRecord()
	stored, created, err := st.Register(first)
	if err != nil {
		t.Fatalf("register first: %v", err)
	}
	if !created || stored.Order != 1 || stored.Conflict {
		t.Fatalf("first = %+v created=%v, want order 1, created, no conflict", stored, created)
	}

	second := sampleRecord()
	second.Name = "allow-dns"
	second.Label = "tier=infra"
	second.Rules = []Rule{{Direction: "egress", Action: "allow", Ports: [2]int{53, 53}}}
	stored, created, err = st.Register(second)
	if err != nil {
		t.Fatalf("register second: %v", err)
	}
	if !created || stored.Order != 2 {
		t.Fatalf("second = %+v created=%v, want order 2, created", stored, created)
	}
}

func TestRegisterRetryReturnsOriginalWithoutConsumingOrder(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if _, _, err := st.Register(sampleRecord()); err != nil {
		t.Fatalf("register: %v", err)
	}
	retry, created, err := st.Register(sampleRecord())
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if created || retry.Order != 1 {
		t.Fatalf("retry = %+v created=%v, want original order 1, not created", retry, created)
	}

	other := sampleRecord()
	other.Name = "next"
	stored, _, err := st.Register(other)
	if err != nil {
		t.Fatalf("register next: %v", err)
	}
	if stored.Order != 2 {
		t.Fatalf("order after retry = %d, want 2 (retry must not consume order)", stored.Order)
	}
}

func TestRegisterSameIdentityDifferentContentConflicts(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if _, _, err := st.Register(sampleRecord()); err != nil {
		t.Fatalf("register: %v", err)
	}
	changed := sampleRecord()
	changed.PluginParams = map[string]string{"mode": "audit"}
	if _, _, err := st.Register(changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed params err = %v, want ErrConflict", err)
	}

	changed = sampleRecord()
	changed.Rules = []Rule{
		{Direction: "egress", Action: "deny", Ports: [2]int{1, 65535}},
		{Direction: "ingress", Action: "deny", Ports: [2]int{1, 65535}},
	}
	if _, _, err := st.Register(changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("reordered rules err = %v, want ErrConflict (rule order is significant)", err)
	}
}

func TestRegisterConflictDetection(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	cases := []struct {
		name        string
		seedRules   []Rule
		candidate   func(*Record)
		candidateNS string // empty means same namespace as the seed
		conflict    bool
	}{
		{
			name:      "opposite action overlapping ports",
			seedRules: []Rule{{Direction: "ingress", Action: "deny", Ports: [2]int{1, 65535}}},
			candidate: func(r *Record) {
				r.Rules = []Rule{{Direction: "ingress", Action: "allow", Ports: [2]int{80, 443}}}
			},
			conflict: true,
		},
		{
			name:      "opposite action disjoint ports",
			seedRules: []Rule{{Direction: "ingress", Action: "deny", Ports: [2]int{100, 200}}},
			candidate: func(r *Record) {
				r.Rules = []Rule{{Direction: "ingress", Action: "allow", Ports: [2]int{300, 400}}}
			},
			conflict: false,
		},
		{
			name:      "same action is not a conflict",
			seedRules: []Rule{{Direction: "ingress", Action: "deny", Ports: [2]int{1, 65535}}},
			candidate: func(r *Record) {
				r.Rules = []Rule{{Direction: "ingress", Action: "deny", Ports: [2]int{80, 80}}}
			},
			conflict: false,
		},
		{
			name:      "opposite direction is not a conflict",
			seedRules: []Rule{{Direction: "ingress", Action: "deny", Ports: [2]int{1, 65535}}},
			candidate: func(r *Record) {
				r.Rules = []Rule{{Direction: "egress", Action: "allow", Ports: [2]int{80, 80}}}
			},
			conflict: false,
		},
		{
			name:      "different label is not a conflict",
			seedRules: []Rule{{Direction: "ingress", Action: "deny", Ports: [2]int{1, 65535}}},
			candidate: func(r *Record) {
				r.Label = "tier=frontend"
				r.Rules = []Rule{{Direction: "ingress", Action: "allow", Ports: [2]int{80, 80}}}
			},
			conflict: false,
		},
		{
			name:      "different namespace is not a conflict",
			seedRules: []Rule{{Direction: "ingress", Action: "deny", Ports: [2]int{1, 65535}}},
			candidate: func(r *Record) {
				r.Rules = []Rule{{Direction: "ingress", Action: "allow", Ports: [2]int{80, 80}}}
			},
			candidateNS: "other-namespace",
			conflict:    false,
		},
	}
	for i, tc := range cases {
		seedNS := "seed-ns-" + tc.name
		seed := sampleRecord()
		seed.Namespace = seedNS
		seed.Name = "seed"
		seed.Rules = tc.seedRules
		if _, _, err := st.Register(seed); err != nil {
			t.Fatalf("case %d (%s): register seed: %v", i, tc.name, err)
		}

		candidate := sampleRecord()
		candidate.Namespace = seedNS
		candidate.Name = "candidate"
		if tc.candidateNS != "" {
			candidate.Namespace = tc.candidateNS
		}
		tc.candidate(&candidate)
		stored, _, err := st.Register(candidate)
		if err != nil {
			t.Fatalf("case %d (%s): register candidate: %v", i, tc.name, err)
		}
		if stored.Conflict != tc.conflict {
			t.Fatalf("case %d (%s): conflict = %v, want %v", i, tc.name, stored.Conflict, tc.conflict)
		}
	}
}

func TestRegisterConcurrentSameIdentityStoresOneRow(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := st.Register(sampleRecord())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent register: %v", err)
		}
	}

	records, err := st.List("payments", "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(records) != 1 || records[0].Order != 1 {
		t.Fatalf("records = %+v, want a single row with order 1", records)
	}
}

func TestRegisterPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, _, err := st.Register(sampleRecord()); err != nil {
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
	records, err := reopened.List("payments", "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(records) != 1 || records[0].Name != "default-deny" || records[0].Order != 1 {
		t.Fatalf("records after reopen = %+v", records)
	}
}

func TestListFiltersAndSorts(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	seed := []Record{
		{Namespace: "a", Name: "one", Label: "x", Rules: sampleRecord().Rules, PluginParams: map[string]string{}},
		{Namespace: "a", Name: "two", Label: "y", Rules: sampleRecord().Rules, PluginParams: map[string]string{}},
		{Namespace: "b", Name: "three", Label: "x", Rules: sampleRecord().Rules, PluginParams: map[string]string{}},
	}
	for _, rec := range seed {
		if _, _, err := st.Register(rec); err != nil {
			t.Fatalf("register %s/%s: %v", rec.Namespace, rec.Name, err)
		}
	}

	byNamespace, err := st.List("a", "")
	if err != nil {
		t.Fatalf("list namespace: %v", err)
	}
	if len(byNamespace) != 2 || byNamespace[0].Name != "one" || byNamespace[1].Name != "two" {
		t.Fatalf("by namespace = %+v", byNamespace)
	}

	byLabel, err := st.List("", "x")
	if err != nil {
		t.Fatalf("list label: %v", err)
	}
	if len(byLabel) != 2 || byLabel[0].Name != "one" || byLabel[1].Name != "three" {
		t.Fatalf("by label = %+v", byLabel)
	}

	intersection, err := st.List("a", "x")
	if err != nil {
		t.Fatalf("list intersection: %v", err)
	}
	if len(intersection) != 1 || intersection[0].Name != "one" {
		t.Fatalf("intersection = %+v", intersection)
	}
}
