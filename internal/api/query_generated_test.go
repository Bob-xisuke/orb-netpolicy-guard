package api

// Generative, fixed-seed property tests for GET /v1/net-policies.
//
// The inputs are produced by a small deterministic generator: no math/rand
// is used and the seed is a compile-time constant, so the same run reproduces.
// The registered sample set covers same-label records across namespaces,
// several labels in one namespace, and non-blank namespace/label values built
// from Chinese characters, "+", ";", "&", "%" and surrounding spaces.
//
// Every query decides its own expectation independently from its conditions
// and the seeded samples: hits are checked against the complete records,
// ordered by "order" ascending (never by comparing two query responses to
// each other), misses expect 404 NetPolicyNotFoundError, and malformed query
// strings expect 400 InvalidNetPolicyInputError. Legal fragment reordering,
// added legal unknown parameters or empty fragments, and changing the hex
// case of percent escapes must keep the result. On failure the message
// carries the original query string plus the expected and actual responses.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// queryGeneratorSeed is fixed on purpose and chosen as a multiple of the
// genValue pool length (so genValue(seed) is the plain-ASCII "payments"
// value): the generated registrations and every expected result below
// must reproduce from run to run.
const queryGeneratorSeed = int64(20261004)

// genValue renders the v-th deterministic, legal non-blank value. The values
// stay valid UTF-8 and intentionally carry the characters the contract
// treats as significant.
func genValue(v int64) string {
	pool := []string{
		"payments",         // plain ASCII
		"华北支付",             // Chinese
		"a+b;c&d",          // plus, semicolon and ampersand inside a value
		"50%_off",          // percent and underscore
		"  padded value  ", // leading and trailing spaces
		"Staging 环境",       // mixed case, Chinese and an interior space
	}
	return pool[((v%int64(len(pool)))+int64(len(pool)))%int64(len(pool))]
}

// escapeQueryValueLower percent-encodes a value once using lowercase hex
// (url.QueryEscape uses uppercase). Spaces become "+", the in-value special
// characters become %2b/%3b/%26/%25, and every other byte — including
// multibyte UTF-8 — passes through verbatim. The replacer is single-pass,
// so the "%" it emits is never re-escaped.
func escapeQueryValueLower(s string) string {
	return strings.NewReplacer(
		"+", "%2b",
		";", "%3b",
		"&", "%26",
		"%", "%25",
		" ", "+",
	).Replace(s)
}

// queryCell identifies an intersection of a namespace and a label.
type queryCell struct {
	namespace string
	label     string
}

// decodeGETItems runs a query, demands 200 and returns the items.
func decodeGETItems(t *testing.T, router http.Handler, rawQuery string) []map[string]any {
	t.Helper()
	recorder := doRequest(router, http.MethodGet, "/v1/net-policies?"+rawQuery, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET ?%s status = %d, want %d: %s",
			rawQuery, recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var body struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode items for ?%s: %v", rawQuery, err)
	}
	return body.Items
}

// expectedQueryItems intersects the per-cell records with the requested
// conditions and returns the complete matching records sorted by order.
func expectedQueryItems(byCell map[queryCell][]map[string]any, namespace, label string, hasNS, hasLabel bool) []map[string]any {
	var want []map[string]any
	for cell, records := range byCell {
		if hasNS && cell.namespace != namespace {
			continue
		}
		if hasLabel && cell.label != label {
			continue
		}
		want = append(want, records...)
	}
	sort.SliceStable(want, func(i, j int) bool {
		return want[i]["order"].(float64) < want[j]["order"].(float64)
	})
	return want
}

// assertItemsEqual fails with the raw query and both bodies when the observed
// items differ from the independently derived expectation.
func assertItemsEqual(t *testing.T, rawQuery string, got, want []map[string]any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.Marshal(got)
		wantJSON, _ := json.Marshal(want)
		t.Fatalf("GET ?%s items mismatch:\n got %s\nwant %s", rawQuery, gotJSON, wantJSON)
	}
}

// assertQuery404 demands the published 404 shape and a message free of
// internals, quoting the original query on failure.
func assertQuery404(t *testing.T, router http.Handler, rawQuery string) {
	t.Helper()
	recorder := doRequest(router, http.MethodGet, "/v1/net-policies?"+rawQuery, "")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("GET ?%s status = %d, want %d: %s",
			rawQuery, recorder.Code, http.StatusNotFound, recorder.Body.String())
	}
	assertExactErrorShape(t, recorder, "NetPolicyNotFoundError")
	assertSafeErrorMessage(t, recorder)
}

// assertQuery400 demands the published 400 shape before any record is
// returned, quoting the original query on failure.
func assertQuery400(t *testing.T, router http.Handler, rawQuery string) {
	t.Helper()
	recorder := doRequest(router, http.MethodGet, "/v1/net-policies?"+rawQuery, "")
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("GET ?%s status = %d, want %d: %s",
			rawQuery, recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	assertExactErrorShape(t, recorder, "InvalidNetPolicyInputError")
	assertSafeErrorMessage(t, recorder)
}

// alternatingAction gives the seeded records alternating actions without
// importing math/rand, keeping the generator deterministic.
func alternatingAction(i int) string {
	if i%2 == 0 {
		return "allow"
	}
	return "deny"
}

// TestGetNetPoliciesGeneratedFiltering is the fixed-seed property test:
// registrations are generated deterministically, and each legal query's
// expected record set is derived independently from the conditions and the
// samples (full records, order ascending) rather than from another response.
func TestGetNetPoliciesGeneratedFiltering(t *testing.T) {
	t.Logf("generating samples with fixed seed %d", queryGeneratorSeed)
	router, _ := newTestRouter(t)

	// Seven generated identities. Records inside one (namespace,label) cell
	// share the closed port interval [7000,7000] and alternate actions by
	// global index: the first record in a cell is conflict-free and every
	// later one clashes with the opposite-action record before it.
	type seed struct {
		cell        queryCell
		name        string
		paramsValue string
	}
	nsA := genValue(queryGeneratorSeed)
	nsB := genValue(queryGeneratorSeed + 1)
	specs := []seed{
		{queryCell{nsA, genValue(2)}, "np-0", genValue(0)},
		{queryCell{nsA, genValue(2)}, "np-1", genValue(1)}, // same label, same namespace
		{queryCell{nsA, genValue(3)}, "np-2", genValue(2)}, // same namespace, different label
		{queryCell{nsB, genValue(2)}, "np-3", genValue(3)}, // same label, different namespace
		{queryCell{nsB, genValue(4)}, "np-4", genValue(4)},
		{queryCell{genValue(5), genValue(6)}, "np-5", genValue(5)},
		{queryCell{genValue(5), genValue(2)}, "np-6", genValue(6)}, // label shared across namespaces
	}

	byCell := map[queryCell][]map[string]any{}
	for i, sp := range specs {
		body := singleRuleBody(sp.cell.namespace, sp.name, sp.cell.label,
			"ingress", alternatingAction(i), 7000, 7000,
			`{"m": `+jsonStringLiteral(t, sp.paramsValue)+`}`)
		localIndex := len(byCell[sp.cell])
		record := registerCreated(t, router, body, int64(i+1), localIndex > 0)
		byCell[sp.cell] = append(byCell[sp.cell], record)
	}

	// Resolve the concrete cells the conditions refer to.
	cellBoth := queryCell{nsA, genValue(2)} // holds np-0 and np-1

	// ---- Namespace filter, label filter and their intersection. Every
	// expectation is derived independently and compared as full records
	// in ascending order. ----
	filterCases := []struct {
		name      string
		rawQuery  string
		namespace string
		label     string
		hasNS     bool
		hasLabel  bool
	}{
		{
			name: "namespace only", rawQuery: "namespace=" + url.QueryEscape(nsA),
			namespace: nsA, hasNS: true,
		},
		{
			name: "label only crosses namespaces", rawQuery: "label=" + url.QueryEscape(genValue(2)),
			label: genValue(2), hasLabel: true,
		},
		{
			name:      "namespace and label intersect",
			rawQuery:  "namespace=" + url.QueryEscape(nsA) + "&label=" + url.QueryEscape(genValue(2)),
			namespace: nsA, label: genValue(2), hasNS: true, hasLabel: true,
		},
		{
			name: "other namespace only", rawQuery: "namespace=" + url.QueryEscape(nsB),
			namespace: nsB, hasNS: true,
		},
	}
	for _, fc := range filterCases {
		t.Run(fc.name, func(t *testing.T) {
			want := expectedQueryItems(byCell, fc.namespace, fc.label, fc.hasNS, fc.hasLabel)
			if len(want) == 0 {
				t.Fatalf("internal: filter %q generated no expected samples", fc.rawQuery)
			}
			got := decodeGETItems(t, router, fc.rawQuery)
			assertItemsEqual(t, fc.rawQuery, got, want)
		})
	}

	// The intersection returns exactly the two same-namespace records and
	// must not include the third namespace sharing only the label.
	intersectionQuery := "label=" + url.QueryEscape(genValue(2)) + "&namespace=" + url.QueryEscape(nsA)
	got := decodeGETItems(t, router, intersectionQuery)
	want := expectedQueryItems(byCell, nsA, genValue(2), true, true)
	assertItemsEqual(t, intersectionQuery, got, want)
	if len(want) != len(byCell[cellBoth]) {
		t.Fatalf("intersection len = %d, want the %d records of the shared cell only",
			len(want), len(byCell[cellBoth]))
	}

	// ---- Every legal transformation keeps the result: reordered fragments,
	// legal unknown parameters, empty fragments, equivalent plus/percent
	// encodings of spaces, and lowercase hex escapes. Each class carries
	// both a fixed hitting seed (full ordered records) and a fixed miss
	// seed (a value differing by a trailing tab returns 404). ----
	t.Run("legal transformations preserve the result", func(t *testing.T) {
		nsEsc := url.QueryEscape(nsA)
		labelEsc := url.QueryEscape(genValue(2))
		base := "namespace=" + nsEsc + "&label=" + labelEsc
		baseWant := expectedQueryItems(byCell, nsA, genValue(2), true, true)

		// Close-looking but never equal: same conditions plus a trailing tab.
		missQuery := "namespace=" + nsEsc + "&label=" + url.QueryEscape(genValue(2)+"\t")

		variants := []struct {
			name  string
			query string
			hits  []map[string]any
		}{
			{"fragments reordered", "label=" + labelEsc + "&namespace=" + nsEsc, baseWant},
			{"unknown parameter first", "verbose=true&" + base, baseWant},
			{"unknown parameter middle",
				"namespace=" + nsEsc + "&verbose=true&label=" + labelEsc, baseWant},
			{"unknown parameter last", base + "&verbose=true", baseWant},
			{"legal unknown carries encoded specials",
				"namespace=" + nsEsc + "&unknown=" + url.QueryEscape("+; &%") + "&label=" + labelEsc, baseWant},
			{"leading empty fragment", "&" + base, baseWant},
			{"trailing empty fragment", base + "&", baseWant},
			{"double empty fragment", "namespace=" + nsEsc + "&&label=" + labelEsc, baseWant},
			{"lowercase hex escapes",
				"namespace=" + escapeQueryValueLower(nsA) + "&label=" + escapeQueryValueLower(genValue(2)),
				baseWant},
		}
		for _, v := range variants {
			t.Run(v.name, func(t *testing.T) {
				got := decodeGETItems(t, router, v.query)
				assertItemsEqual(t, v.query, got, v.hits)
				assertQuery404(t, router, missQuery)
			})
		}

		// "+" and "%20" are equivalent encodings of a space: both find the
		// nsB records (genValue(seed+1) is the padded value). The fixed
		// miss seed carries an extra trailing tab.
		spaceWant := expectedQueryItems(byCell, nsB, "", true, false)
		for _, q := range []string{
			"namespace=" + strings.ReplaceAll(url.QueryEscape(nsB), "%20", "+"),
			"namespace=" + url.QueryEscape(nsB),
		} {
			got := decodeGETItems(t, router, q)
			assertItemsEqual(t, q, got, spaceWant)
		}
		assertQuery404(t, router, "namespace="+url.QueryEscape(nsB+"\t")+"&label=x")

		// A bare query and empty fragments carry no known condition and are
		// rejected uniformly; they never match a record by accident.
		for _, raw := range []string{"", "&", "&&"} {
			assertQuery400(t, router, raw)
		}
	})

	// ---- Values decode exactly once: "+" is a space in a value while
	// %2B/%3B/%26 stay literal, and %252B stays the text "%2B" instead of
	// becoming a plus on a second decode. Fixed hit and miss seeds each. ----
	t.Run("values decode exactly once", func(t *testing.T) {
		specialLabel := genValue(2) // "a+b;c&d"
		type hitCase struct {
			query            string
			namespace, label string
			hasNS, hasLabel  bool
		}
		hitCases := []hitCase{
			{"label=" + url.QueryEscape(specialLabel), "", specialLabel, false, true},
			{"label=" + escapeQueryValueLower(specialLabel), "", specialLabel, false, true},
			{"namespace=" + url.QueryEscape(nsA) + "&label=" + url.QueryEscape(specialLabel),
				nsA, specialLabel, true, true},
		}
		for _, hc := range hitCases {
			want := expectedQueryItems(byCell, hc.namespace, hc.label, hc.hasNS, hc.hasLabel)
			got := decodeGETItems(t, router, hc.query)
			assertItemsEqual(t, hc.query, got, want)
		}

		oneDecodeMisses := map[string]string{
			"raw plus decodes to space":  "label=a%2Bb+x",
			"raw ampersand splits query": "label=a%2Bb&junk=x",
			"double encoded stays text":  "label=a%252Bb%253Bc%2526d",
			"literal percent text":       "label=" + url.QueryEscape("a%2Bb%3Bc%26d"),
		}
		for name, q := range oneDecodeMisses {
			t.Run(name, func(t *testing.T) {
				assertQuery404(t, router, q)
			})
		}
	})

	// ---- Non-blank values match verbatim: values differing only in case or
	// in surrounding spaces are distinct and must not hit. Fixed miss seeds.
	t.Run("near values do not match", func(t *testing.T) {
		nearMisses := []string{
			"namespace=" + url.QueryEscape(strings.ToUpper(nsA)),
			"namespace=" + url.QueryEscape(nsA+" "),
			"namespace=" + url.QueryEscape(" "+nsA),
			"label=" + url.QueryEscape(strings.ToUpper(genValue(2))),
			"label=" + url.QueryEscape(genValue(2)+" "),
			"namespace=" + url.QueryEscape(nsA) + "&label=" + url.QueryEscape(genValue(2)+" "),
			"label=" + url.QueryEscape(genValue(1)), // registered only as a namespace, never as a label
		}
		for _, q := range nearMisses {
			assertQuery404(t, router, q)
		}
		assertQuery404(t, router, "namespace="+url.QueryEscape("未登记 命名空间"))
	})

	// ---- Malformed queries reject uniformly with 400 whether the bad
	// fragment is first, middle or last, sits in a parameter name or value,
	// or belongs to an unknown parameter — even when the known conditions
	// would have matched. The committed content, order and conflict flags
	// stay unchanged after every group. ----
	t.Run("malformed queries reject uniformly", func(t *testing.T) {
		goodNS := url.QueryEscape(nsA)
		goodLabel := url.QueryEscape(genValue(2))
		base := "namespace=" + goodNS + "&label=" + goodLabel

		var illegal []string
		for _, bad := range []string{"%ZZ", "%", "%2", "41%", "a%GG", "x;y"} {
			illegal = append(illegal,
				"junk="+bad+"&"+base, // first, unknown parameter
				base+"&junk="+bad,    // last, unknown parameter
				"namespace="+goodNS+"&junk="+bad+"&label="+goodLabel, // middle, unknown parameter
				"namespace="+bad,         // bad value of a known condition
				"namespace=x&label="+bad, // bad label value
			)
		}
		illegal = append(illegal,
			// Bad escape or semicolon in a parameter name.
			"%ZZ=x",
			"na%2=x",
			"name;space=x",
			// Known parameters duplicated after a single decode.
			base+"&namespace="+goodNS,
			"namespace="+goodNS+"&%6Eamespace="+goodNS,
			"label="+goodLabel+"&%6Cabel=x",
			// Known condition present but blank or whitespace-only.
			"namespace=",
			"namespace=%20%20",
			"namespace=+",
			"label=",
			"namespace="+goodNS+"&label=",
			"namespace=&namespace="+goodNS, // first occurrence wins and is blank
			// No known condition at all, with and without a present unknown value.
			"junk=x",
			"junk=",
			"junk=%ZZ", // unknown and malformed: still 400
		)

		for i, q := range illegal {
			t.Run("illegal-"+strconv.Itoa(i), func(t *testing.T) {
				assertQuery400(t, router, q)
			})
		}

		// None of the rejected queries changed the registry: every seeded
		// cell still returns exactly its records, content/order/conflict
		// intact, sorted by order ascending.
		for cell, records := range byCell {
			q := "namespace=" + url.QueryEscape(cell.namespace) +
				"&label=" + url.QueryEscape(cell.label)
			got := decodeGETItems(t, router, q)
			assertItemsEqual(t, q, got, records)
		}
	})

	// None of the rejected queries consumed an order. Independently, the
	// next brand-new identity takes the original maximum order plus one.
	freshBody := singleRuleBody("other", "after-generated", "plain-label",
		"egress", "allow", 53, 53, `{}`)
	registerCreated(t, router, freshBody, int64(len(specs)+1), false)
}
