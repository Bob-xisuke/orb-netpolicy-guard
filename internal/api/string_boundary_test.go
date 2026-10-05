package api

// String-boundary regression tests: identities and labels built from Chinese,
// supplementary-plane characters, surrounding spaces, single quotes, percent
// signs, underscores and NUL (expressed through a JSON escape) are preserved
// verbatim across registration, idempotent retry, query and store reopen.
// Different legal JSON encodings of the same string share one identity, while
// near-strings (case, spaces, Unicode combining forms, separator lookalikes)
// stay strictly isolated. Every expectation comes from the published contract
// in README.md, never from the service's own responses.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/Bob-xisuke/orb-netpolicy-guard/internal/store"
)

// boundaryRules is a single legal deny rule shared by the boundary tests.
const boundaryRules = `[{"direction": "ingress", "action": "deny", "ports": [80, 100]}]`

// rawPolicyBody builds a registration body from raw JSON fragments so a test
// controls the exact encoding of every string (Go %q quoting could not express
// e.g. NUL as a JSON escape).
func rawPolicyBody(nsRaw, nameRaw, labelRaw, rulesRaw, paramsRaw string) string {
	return fmt.Sprintf(`{
		"namespace": %s,
		"name": %s,
		"label": %s,
		"rules": %s,
		"pluginParams": %s
	}`, nsRaw, nameRaw, labelRaw, rulesRaw, paramsRaw)
}

// boundaryStrings are legal non-blank strings exercising the encoding edges,
// each paired with one concrete JSON encoding of it.
var boundaryStrings = []struct {
	name  string
	value string
	json  string
}{
	{"chinese", "拦截", `"拦截"`},
	{"supplementary plane", "𝄞", `"𝄞"`},
	{"surrounding spaces", "  padded  ", `"  padded  "`},
	{"single quote", "it's", `"it's"`},
	{"percent sign", "100%", `"100%"`},
	{"underscore", "under_score", `"under_score"`},
	{"nul via json escape", "a\x00b", `"a\u0000b"`},
}

// Each boundary string survives the round trip verbatim: registration echoes
// it, and a legally percent-encoded query by namespace and by label returns
// exactly the registered record with every field intact.
func TestStringBoundaryValuesPreservedVerbatim(t *testing.T) {
	for _, tc := range boundaryStrings {
		t.Run(tc.name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			body := rawPolicyBody(tc.json, `"edge"`, tc.json, boundaryRules, `{}`)
			created := registerCreated(t, router, body, 1, false)
			if created["namespace"] != tc.value || created["label"] != tc.value {
				t.Fatalf("POST %s: response namespace/label = %q/%q, want verbatim %q",
					body, created["namespace"], created["label"], tc.value)
			}

			for _, target := range []string{
				"/v1/net-policies?namespace=" + url.QueryEscape(tc.value),
				"/v1/net-policies?label=" + url.QueryEscape(tc.value),
			} {
				items := listItems(t, router, target)
				if len(items) != 1 || !reflect.DeepEqual(items[0], created) {
					t.Fatalf("GET %s items = %v, want exactly the registered record %v", target, items, created)
				}
			}
		})
	}
}

// Different legal JSON encodings of the same string are the same content: the
// first registration returns 201, a retry spelled with another encoding
// returns 200 with a response identical in every submitted field, order and
// conflict — and neither adds a record nor consumes an order.
func TestStringBoundaryEquivalentJsonEncodingsShareIdentity(t *testing.T) {
	pairs := []struct{ name, encA, encB string }{
		{"chinese", `"拦截"`, `"\u62e6\u622a"`},
		{"supplementary plane", `"𝄞"`, `"\ud834\udd1e"`},
		{"space", `"a b"`, `"a\u0020b"`},
		{"single quote", `"it's"`, `"it\u0027s"`},
		{"percent sign", `"100%"`, `"100\u0025"`},
		{"underscore", `"a_b"`, `"a\u005fb"`},
	}
	for _, tc := range pairs {
		t.Run(tc.name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			firstBody := rawPolicyBody(tc.encA, `"edge"`, tc.encA, boundaryRules, `{}`)
			created := registerCreated(t, router, firstBody, 1, false)

			retryBody := rawPolicyBody(tc.encB, `"edge"`, tc.encB, boundaryRules, `{}`)
			recorder := doRequest(router, http.MethodPost, "/v1/net-policies", retryBody)
			if recorder.Code != http.StatusOK {
				t.Fatalf("POST %s status = %d, want %d: %s",
					retryBody, recorder.Code, http.StatusOK, recorder.Body.String())
			}
			var retried map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &retried); err != nil {
				t.Fatalf("decode retry: %v", err)
			}
			if !reflect.DeepEqual(retried, created) {
				t.Fatalf("retry of %s with alternate encoding = %v, want identical to first registration %v",
					retryBody, retried, created)
			}

			// The retry added no record and consumed no order.
			target := "/v1/net-policies?namespace=" + url.QueryEscape(created["namespace"].(string))
			if items := listItems(t, router, target); len(items) != 1 {
				t.Fatalf("GET %s items = %v, want the single original record", target, items)
			}
			nextBody := rawPolicyBody(`"fresh"`, `"fresh"`, `"fresh"`, boundaryRules, `{}`)
			registerCreated(t, router, nextBody, 2, false)
		})
	}
}

// Near-strings are strictly isolated: case-only, space-only and Unicode
// combining-form differences each produce their own record, and
// namespace/name combinations built from the same separator characters never
// merge into one identity.
func TestStringBoundaryNearStringsStaySeparate(t *testing.T) {
	router, _ := newTestRouter(t)
	entries := []struct{ name, jsonEnc, value string }{
		{"base", `"payments"`, "payments"},
		{"different case", `"Payments"`, "Payments"},
		{"leading space", `" payments"`, " payments"},
		{"trailing space", `"payments "`, "payments "},
		{"inner space", `"pay ments"`, "pay ments"},
		{"precomposed accent", `"caf\u00e9"`, "caf\u00e9"},
		{"combining accent", `"cafe\u0301"`, "cafe\u0301"},
	}
	records := make([]map[string]any, 0, len(entries))
	for i, tc := range entries {
		t.Run(tc.name, func(t *testing.T) {
			body := rawPolicyBody(tc.jsonEnc, fmt.Sprintf(`"n-%d"`, i), `"tier=backend"`, boundaryRules, `{}`)
			records = append(records, registerCreated(t, router, body, int64(i+1), false))
		})
	}
	for i, tc := range entries {
		target := "/v1/net-policies?namespace=" + url.QueryEscape(tc.value)
		items := listItems(t, router, target)
		if len(items) != 1 || !reflect.DeepEqual(items[0], records[i]) {
			t.Fatalf("GET %s items = %v, want exactly the record registered for %q", target, items, tc.value)
		}
	}

	// Identities sharing separator characters stay distinct: (a-b, c) and
	// (a, b-c) are two records, and a retry of one returns its own.
	first := registerCreated(t, router,
		rawPolicyBody(`"a-b"`, `"c"`, `"tier=backend"`, boundaryRules, `{}`), 8, false)
	second := registerCreated(t, router,
		rawPolicyBody(`"a"`, `"b-c"`, `"tier=backend"`, boundaryRules, `{}`), 9, false)

	retry := doRequest(router, http.MethodPost, "/v1/net-policies",
		rawPolicyBody(`"a-b"`, `"c"`, `"tier=backend"`, boundaryRules, `{}`))
	if retry.Code != http.StatusOK {
		t.Fatalf("retry of (a-b, c) status = %d, want %d: %s", retry.Code, http.StatusOK, retry.Body.String())
	}
	var retried map[string]any
	if err := json.Unmarshal(retry.Body.Bytes(), &retried); err != nil {
		t.Fatalf("decode retry: %v", err)
	}
	if !reflect.DeepEqual(retried, first) {
		t.Fatalf("retry of (a-b, c) = %v, want the original record %v", retried, first)
	}
	if items := listItems(t, router, "/v1/net-policies?namespace=a-b"); len(items) != 1 || !reflect.DeepEqual(items[0], first) {
		t.Fatalf("namespace a-b items = %v, want exactly %v", items, first)
	}
	if items := listItems(t, router, "/v1/net-policies?namespace=a"); len(items) != 1 || !reflect.DeepEqual(items[0], second) {
		t.Fatalf("namespace a items = %v, want exactly %v", items, second)
	}
}

// Re-posting an existing identity with only the label changed is a content
// conflict: 409 NetPolicyConflictError, the original record stays untouched,
// and the rejected request consumes no order.
func TestStringBoundaryLabelChangeOnSameIdentityConflicts(t *testing.T) {
	router, _ := newTestRouter(t)
	seedBody := rawPolicyBody(`"拦截"`, `"edge"`, `"tier=backend"`, boundaryRules, `{}`)
	seed := registerCreated(t, router, seedBody, 1, false)

	changedBody := rawPolicyBody(`"拦截"`, `"edge"`, `"tier=frontend"`, boundaryRules, `{}`)
	recorder := doRequest(router, http.MethodPost, "/v1/net-policies", changedBody)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("POST %s status = %d, want %d: %s",
			changedBody, recorder.Code, http.StatusConflict, recorder.Body.String())
	}
	assertExactErrorShape(t, recorder, "NetPolicyConflictError")
	assertSafeErrorMessage(t, recorder)

	target := "/v1/net-policies?namespace=" + url.QueryEscape("拦截")
	items := listItems(t, router, target)
	if len(items) != 1 || !reflect.DeepEqual(items[0], seed) {
		t.Fatalf("GET %s after 409 items = %v, want the unchanged original %v", target, items, seed)
	}

	// The 409 consumed no order: the next new identity takes max order + 1.
	nextBody := rawPolicyBody(`"拦截"`, `"next"`, `"tier=backend"`, boundaryRules, `{}`)
	registerCreated(t, router, nextBody, 2, false)
}

// The conflict flag requires the namespace and the label to be exactly equal
// to an existing record's: a label differing only by case or a namespace
// differing only by a space leaves the new record's flag false even with
// overlapping ports, the same direction and the opposite action. An exact
// match flags the new record, and the earlier record's flag is not rewritten.
func TestStringBoundaryConflictFlagNeedsExactNamespaceAndLabel(t *testing.T) {
	router, _ := newTestRouter(t)
	allowRule := `[{"direction": "ingress", "action": "allow", "ports": [90, 90]}]`

	seed := registerCreated(t, router,
		rawPolicyBody(`"pay ments"`, `"seed"`, `"tier=backend"`, boundaryRules, `{}`), 1, false)
	// Label differs only by case: no conflict despite the clashing rule.
	caseLabel := registerCreated(t, router,
		rawPolicyBody(`"pay ments"`, `"case-label"`, `"Tier=backend"`, allowRule, `{}`), 2, false)
	// Namespace differs only by the inner space: no conflict.
	registerCreated(t, router,
		rawPolicyBody(`"payments"`, `"other-ns"`, `"tier=backend"`, allowRule, `{}`), 3, false)
	// Exact namespace and label, opposite action, overlapping port: conflict.
	flagged := registerCreated(t, router,
		rawPolicyBody(`"pay ments"`, `"flagged"`, `"tier=backend"`, allowRule, `{}`), 4, true)

	items := listItems(t, router, "/v1/net-policies?namespace=pay+ments")
	if want := []map[string]any{seed, caseLabel, flagged}; !reflect.DeepEqual(items, want) {
		t.Fatalf("namespace pay+ments items = %v, want %v (seed and case-label keep conflict=false)", items, want)
	}
}

// Legal query encodings retrieve boundary strings exactly: + and %20 are the
// same space, literal + and % in stored values are not decoded a second time,
// % and _ are not matching wildcards, namespace+label intersects, items come
// back in ascending order with complete fields, and unregistered near-values
// report 404 NetPolicyNotFoundError.
func TestStringBoundaryQueryEncoding(t *testing.T) {
	router, _ := newTestRouter(t)
	spaced := registerCreated(t, router,
		rawPolicyBody(`"pay ments"`, `"spaced"`, `"spaced-label"`, boundaryRules, `{}`), 1, false)
	plus := registerCreated(t, router,
		rawPolicyBody(`"plus-ns"`, `"plus"`, `"a+b"`, boundaryRules, `{}`), 2, false)
	pct := registerCreated(t, router,
		rawPolicyBody(`"pct-ns"`, `"pct"`, `"100%"`, boundaryRules, `{}`), 3, false)
	under := registerCreated(t, router,
		rawPolicyBody(`"a_b"`, `"under"`, `"u"`, boundaryRules, `{}`), 4, false)
	other := registerCreated(t, router,
		rawPolicyBody(`"axb"`, `"other"`, `"u"`, boundaryRules, `{}`), 5, false)
	pctNs := registerCreated(t, router,
		rawPolicyBody(`"a%b"`, `"pctns"`, `"p"`, boundaryRules, `{}`), 6, false)
	axxb := registerCreated(t, router,
		rawPolicyBody(`"aXXb"`, `"axxb"`, `"p"`, boundaryRules, `{}`), 7, false)

	// + and %20 are the same space.
	for _, target := range []string{
		"/v1/net-policies?namespace=pay+ments",
		"/v1/net-policies?namespace=pay%20ments",
	} {
		items := listItems(t, router, target)
		if len(items) != 1 || !reflect.DeepEqual(items[0], spaced) {
			t.Fatalf("GET %s items = %v, want exactly %v", target, items, spaced)
		}
	}

	// A literal + in a stored value is matched via %2B; a raw + decodes to a
	// space and must not match it.
	if items := listItems(t, router, "/v1/net-policies?label=a%2Bb"); len(items) != 1 || !reflect.DeepEqual(items[0], plus) {
		t.Fatalf("label a%%2Bb items = %v, want exactly %v", items, plus)
	}
	assertNotFound(t, router, "/v1/net-policies?label=a+b")

	// A literal % in a stored value is matched via %25; the double-encoded
	// form decodes once to the text "100%25" and must not match "100%".
	if items := listItems(t, router, "/v1/net-policies?label=100%25"); len(items) != 1 || !reflect.DeepEqual(items[0], pct) {
		t.Fatalf("label 100%%25 items = %v, want exactly %v", items, pct)
	}
	assertNotFound(t, router, "/v1/net-policies?label=100%2525")

	// _ and % are ordinary characters, not wildcards: each query returns only
	// the record whose namespace is exactly the decoded value.
	if items := listItems(t, router, "/v1/net-policies?namespace=a_b"); len(items) != 1 || !reflect.DeepEqual(items[0], under) {
		t.Fatalf("namespace a_b items = %v, want exactly %v (not axb)", items, under)
	}
	if items := listItems(t, router, "/v1/net-policies?namespace=a%25b"); len(items) != 1 || !reflect.DeepEqual(items[0], pctNs) {
		t.Fatalf("namespace a%%25b items = %v, want exactly %v (not aXXb)", items, pctNs)
	}

	// namespace and label together intersect.
	if items := listItems(t, router, "/v1/net-policies?namespace=plus-ns&label=a%2Bb"); len(items) != 1 || !reflect.DeepEqual(items[0], plus) {
		t.Fatalf("intersection items = %v, want exactly %v", items, plus)
	}
	assertNotFound(t, router, "/v1/net-policies?namespace=plus-ns&label=spaced-label")

	// Items sharing a label come back in ascending order with every field.
	if items := listItems(t, router, "/v1/net-policies?label=u"); !reflect.DeepEqual(items, []map[string]any{under, other}) {
		t.Fatalf("label u items = %v, want %v in ascending order", items, []map[string]any{under, other})
	}
	if items := listItems(t, router, "/v1/net-policies?label=p"); !reflect.DeepEqual(items, []map[string]any{pctNs, axxb}) {
		t.Fatalf("label p items = %v, want %v in ascending order", items, []map[string]any{pctNs, axxb})
	}

	// Unregistered near-values are 404, never matches.
	for _, target := range []string{
		"/v1/net-policies?namespace=pay+ment",   // missing suffix
		"/v1/net-policies?namespace=Pay+Ments",  // case differs
		"/v1/net-policies?namespace=pay++ments", // one more space
		"/v1/net-policies?label=a%2B",           // prefix of a+b
		"/v1/net-policies?label=100",            // prefix of 100%
	} {
		assertNotFound(t, router, target)
	}
}

// An incomplete percent escape anywhere in the query rejects the whole
// request with 400 InvalidNetPolicyInputError — no partial hit leaks — and
// the rejections neither change committed data nor consume an order.
func TestStringBoundaryMalformedPercentQueryRejected(t *testing.T) {
	router, _ := newTestRouter(t)
	seed := registerCreated(t, router,
		rawPolicyBody(`"pay ments"`, `"seed"`, `"tier=backend"`, boundaryRules, `{}`), 1, false)

	for _, target := range []string{
		"/v1/net-policies?namespace=pay%",
		"/v1/net-policies?namespace=pay%2",
		"/v1/net-policies?namespace=%2G",
		"/v1/net-policies?namespace=pay+ments&label=%",
		"/v1/net-policies?junk=%zz&namespace=pay+ments",
	} {
		recorder := doRequest(router, http.MethodGet, target, "")
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("GET %s status = %d, want %d: %s",
				target, recorder.Code, http.StatusBadRequest, recorder.Body.String())
		}
		assertExactErrorShape(t, recorder, "InvalidNetPolicyInputError")
		assertSafeErrorMessage(t, recorder)
	}

	// The rejected queries changed nothing and consumed no order.
	items := listItems(t, router, "/v1/net-policies?namespace=pay+ments")
	if len(items) != 1 || !reflect.DeepEqual(items[0], seed) {
		t.Fatalf("items after rejected queries = %v, want the unchanged %v", items, seed)
	}
	registerCreated(t, router,
		rawPolicyBody(`"pay ments"`, `"next"`, `"tier=backend"`, boundaryRules, `{}`), 2, false)
}

// Boundary strings survive a close/reopen of the same database file: the same
// legally encoded queries return the original records, a retry spelled with a
// different JSON encoding still returns 200 with the stored record, and the
// next fresh identity continues at max order + 1.
func TestStringBoundarySurvivesStoreReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "service.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	router := NewRouter(st)

	first := registerCreated(t, router,
		rawPolicyBody(`"拦截"`, `"edge"`, `"a\u0000b"`, boundaryRules, `{}`), 1, false)
	second := registerCreated(t, router,
		rawPolicyBody(`"𝄞"`, `"music"`, `"100%"`, boundaryRules, `{}`), 2, false)

	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	reopened, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { reopened.Close() })
	router = NewRouter(reopened)

	// The same queries return the original records, NUL label included.
	if items := listItems(t, router, "/v1/net-policies?label="+url.QueryEscape("a\x00b")); len(items) != 1 || !reflect.DeepEqual(items[0], first) {
		t.Fatalf("NUL label query after reopen = %v, want exactly %v", items, first)
	}
	if items := listItems(t, router, "/v1/net-policies?namespace="+url.QueryEscape("𝄞")); len(items) != 1 || !reflect.DeepEqual(items[0], second) {
		t.Fatalf("supplementary namespace query after reopen = %v, want exactly %v", items, second)
	}

	// A retry with a different legal encoding of the same strings is still
	// the same identity: 200 with the stored record.
	retryBody := rawPolicyBody(`"\u62e6\u622a"`, `"edge"`, `"a\u0000b"`, boundaryRules, `{}`)
	recorder := doRequest(router, http.MethodPost, "/v1/net-policies", retryBody)
	if recorder.Code != http.StatusOK {
		t.Fatalf("POST %s after reopen status = %d, want %d: %s",
			retryBody, recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var retried map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &retried); err != nil {
		t.Fatalf("decode retry: %v", err)
	}
	if !reflect.DeepEqual(retried, first) {
		t.Fatalf("retry after reopen = %v, want the original %v", retried, first)
	}

	// The retry consumed no order: the next new identity takes max order + 1.
	registerCreated(t, router,
		rawPolicyBody(`"fresh"`, `"fresh"`, `"fresh"`, boundaryRules, `{}`), 3, false)
}

// assertNotFound demands 404 NetPolicyNotFoundError for a query.
func assertNotFound(t *testing.T, router *gin.Engine, target string) {
	t.Helper()
	recorder := doRequest(router, http.MethodGet, target, "")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("GET %s status = %d, want %d: %s",
			target, recorder.Code, http.StatusNotFound, recorder.Body.String())
	}
	assertExactErrorShape(t, recorder, "NetPolicyNotFoundError")
}
