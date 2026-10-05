package api

// String boundary regression tests: identities and labels carrying legal but
// unusual characters (Chinese, supplementary-plane characters, padding spaces,
// single quotes, percent signs, underscores, NUL via JSON escape) must keep
// their verbatim identity through registration, idempotent retry, querying and
// a database reopen, while near-miss strings stay strictly separate. Every
// expectation below is derived from the public contract in README.md, never
// from observed service output.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/Bob-xisuke/orb-netpolicy-guard/internal/store"
)

// rawBoundaryBody builds a registration body from raw JSON fragments so the
// test controls the exact wire encoding of every string field.
func rawBoundaryBody(nsJSON, nameJSON, labelJSON, rulesJSON, paramsJSON string) string {
	return fmt.Sprintf(`{
		"namespace": %s,
		"name": %s,
		"label": %s,
		"rules": %s,
		"pluginParams": %s
	}`, nsJSON, nameJSON, labelJSON, rulesJSON, paramsJSON)
}

// jsonStringLiteral renders s as a JSON string literal with the standard
// encoder: control characters (including NUL) become \u00XX escapes while
// printable non-ASCII stays as UTF-8.
func jsonStringLiteral(t *testing.T, s string) string {
	t.Helper()
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("encode %q: %v", s, err)
	}
	return string(raw)
}

// jsonEscapeNonASCII renders s as a JSON string literal with every non-ASCII
// character written as \uXXXX (a surrogate pair beyond the basic plane): a
// different legal wire encoding of the same string.
func jsonEscapeNonASCII(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20:
			fmt.Fprintf(&b, `\u%04x`, r)
		case r < 0x80:
			b.WriteRune(r)
		case r > 0xFFFF:
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&b, `\u%04x\u%04x`, hi, lo)
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// Legal non-blank strings at the boundary — Chinese, supplementary-plane
// characters, leading/trailing spaces, single quotes, percent signs,
// underscores and a NUL written as JSON \u0000 — are stored verbatim as label
// values, returned byte-for-byte on registration, and can be queried back
// exactly through legal percent/plus encoding.
func TestStringBoundarySpecialLabelsRoundTrip(t *testing.T) {
	router, _ := newTestRouter(t)
	rules := `[{"direction": "ingress", "action": "allow", "ports": [80, 80]}]`
	cases := []struct {
		name  string
		label string
	}{
		{"chinese", "华北支付"},
		{"supplementary plane", "扩展𠀀😀"},
		{"padded spaces", "  padded  "},
		{"single quote", "it's"},
		{"percent and underscore", "50%_off"},
		{"nul via json escape", "nul\x00byte"},
	}

	var want []map[string]any
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := rawBoundaryBody(
				`"boundary"`,
				jsonStringLiteral(t, fmt.Sprintf("case-%d", i)),
				jsonStringLiteral(t, tc.label),
				rules, `{}`)
			record := registerCreated(t, router, body, int64(i+1), false)
			want = append(want, record)

			// The legal percent/plus encoding of the exact label finds the
			// record and nothing else.
			items := listItems(t, router, "/v1/net-policies?label="+url.QueryEscape(tc.label))
			if len(items) != 1 || !reflect.DeepEqual(items[0], record) {
				t.Fatalf("GET label=%q items = %v, want exactly %v", tc.label, items, record)
			}
		})
	}

	// The namespace query returns every record, order ascending, fields intact.
	items := listItems(t, router, "/v1/net-policies?namespace=boundary")
	if !reflect.DeepEqual(items, want) {
		t.Fatalf("namespace items = %v, want %v", items, want)
	}
}

// The same legal string written with different JSON encodings (literal UTF-8
// versus \uXXXX escapes, including a surrogate pair and escaped ASCII
// punctuation) is the same content: the first registration returns 201, the
// re-encoded retry returns 200 with the identical record — same submitted
// fields, order and conflict — and consumes neither a record nor an order.
func TestStringBoundaryEquivalentJSONEncodingsAreSameContent(t *testing.T) {
	router, _ := newTestRouter(t)
	deny := `[{"direction": "ingress", "action": "deny", "ports": [80, 100]}]`

	// Identity and label carrying Chinese and a supplementary-plane character.
	literal := rawBoundaryBody(`"华北"`, `"策略𠀀"`, `"tier=后端"`, deny, `{"mode": "enforce"}`)
	seed := registerCreated(t, router, literal, 1, false)

	escaped := rawBoundaryBody(
		jsonEscapeNonASCII("华北"), jsonEscapeNonASCII("策略𠀀"), jsonEscapeNonASCII("tier=后端"),
		deny, `{"mode": "enforce"}`)
	retry := doRequest(router, http.MethodPost, "/v1/net-policies", escaped)
	if retry.Code != http.StatusOK {
		t.Fatalf("escaped retry status = %d, want %d: %s", retry.Code, http.StatusOK, retry.Body.String())
	}
	var retryRecord map[string]any
	if err := json.Unmarshal(retry.Body.Bytes(), &retryRecord); err != nil {
		t.Fatalf("decode retry: %v", err)
	}
	if !reflect.DeepEqual(retryRecord, seed) {
		t.Fatalf("escaped retry record = %v, want identical to %v", retryRecord, seed)
	}

	// Escaped ASCII punctuation: "it's" written with a \u0027 escape and
	// "50%_off" with \u0025 are the same strings as the literal spellings.
	plain := rawBoundaryBody(`"quoted"`, `"it's"`, `"50%_off"`, deny, `{}`)
	seed2 := registerCreated(t, router, plain, 2, false)
	escapedPunct := rawBoundaryBody(`"quoted"`, `"it\u0027s"`, `"50\u0025_off"`, deny, `{}`)
	retry2 := doRequest(router, http.MethodPost, "/v1/net-policies", escapedPunct)
	if retry2.Code != http.StatusOK {
		t.Fatalf("escaped punctuation retry status = %d, want %d: %s", retry2.Code, http.StatusOK, retry2.Body.String())
	}
	var retry2Record map[string]any
	if err := json.Unmarshal(retry2.Body.Bytes(), &retry2Record); err != nil {
		t.Fatalf("decode retry: %v", err)
	}
	if !reflect.DeepEqual(retry2Record, seed2) {
		t.Fatalf("escaped punctuation retry record = %v, want identical to %v", retry2Record, seed2)
	}

	// Neither retry consumed an order: the next brand-new identity takes 3.
	next := rawBoundaryBody(`"华北"`, `"next"`, `"tier=后端"`, deny, `{}`)
	registerCreated(t, router, next, 3, false)

	// Both retries added no record: the namespace holds exactly the seed and
	// the fresh record.
	items := listItems(t, router, "/v1/net-policies?namespace="+url.QueryEscape("华北"))
	if len(items) != 2 || !reflect.DeepEqual(items[0], seed) {
		t.Fatalf("namespace items = %v, want seed plus the fresh record", items)
	}
}

// Identities differing only in letter case, surrounding spaces or Unicode
// combining form are stored as separate records, and namespace/name pairs that
// merely share a separator character are not merged.
func TestStringBoundaryNearIdentitiesStaySeparate(t *testing.T) {
	router, _ := newTestRouter(t)
	rules := `[{"direction": "ingress", "action": "allow", "ports": [80, 80]}]`
	identities := []struct {
		ns, name, label string
	}{
		{"payments", "default-deny", "l-base"},
		{"payments", "Default-Deny", "l-case"},   // case only
		{"payments", "default-deny ", "l-space"}, // trailing space
		{"payments", "café", "l-nfc"},            // NFC composed
		{"payments", "café", "l-nfd"},   // NFD decomposed
		{"a/b", "c", "l-sep-1"},                  // separator inside namespace
		{"a", "b/c", "l-sep-2"},                  // separator inside name
	}
	records := make(map[string]map[string]any, len(identities))
	for i, id := range identities {
		body := rawBoundaryBody(
			jsonStringLiteral(t, id.ns), jsonStringLiteral(t, id.name), jsonStringLiteral(t, id.label),
			rules, `{}`)
		records[id.label] = registerCreated(t, router, body, int64(i+1), false)
	}

	// Each label query returns exactly its own record: the near strings did
	// not collapse onto one another.
	for label, record := range records {
		items := listItems(t, router, "/v1/net-policies?label="+url.QueryEscape(label))
		if len(items) != 1 || !reflect.DeepEqual(items[0], record) {
			t.Fatalf("GET label=%s items = %v, want exactly %v", label, items, record)
		}
	}

	// The separator pairs stay apart on namespace queries.
	items := listItems(t, router, "/v1/net-policies?namespace=a%2Fb")
	if want := []map[string]any{records["l-sep-1"]}; !reflect.DeepEqual(items, want) {
		t.Fatalf("namespace a/b items = %v, want %v", items, want)
	}
	items = listItems(t, router, "/v1/net-policies?namespace=a")
	if want := []map[string]any{records["l-sep-2"]}; !reflect.DeepEqual(items, want) {
		t.Fatalf("namespace a items = %v, want %v", items, want)
	}

	// Unregistered near values miss cleanly: different case, extra space or
	// the other combining form are 404 NetPolicyNotFoundError, never a match.
	for _, target := range []string{
		"/v1/net-policies?namespace=PAYMENTS",
		"/v1/net-policies?namespace=payments+",
		"/v1/net-policies?label=L-BASE",
		"/v1/net-policies?label=+l-base",
		"/v1/net-policies?namespace=a%2Fb+",
	} {
		recorder := doRequest(router, http.MethodGet, target, "")
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("GET %s status = %d, want %d: %s", target, recorder.Code, http.StatusNotFound, recorder.Body.String())
		}
		assertExactErrorShape(t, recorder, "NetPolicyNotFoundError")
	}
}

// Re-posting an existing identity with only the label changed — even by mere
// case or an extra space — is a content conflict: 409 NetPolicyConflictError,
// the original record untouched, and no order consumed.
func TestStringBoundaryLabelOnlyChangeConflicts(t *testing.T) {
	router, _ := newTestRouter(t)
	rules := `[{"direction": "ingress", "action": "allow", "ports": [80, 80]}]`
	seed := registerCreated(t, router,
		rawBoundaryBody(`"payments"`, `"quoted"`, `"50%_off"`, rules, `{}`), 1, false)

	for name, labelJSON := range map[string]string{
		"case changed":    `"50%_OFF"`,
		"trailing space":  `"50%_off "`,
		"combining added": `"50%_off́"`,
	} {
		t.Run(name, func(t *testing.T) {
			changed := rawBoundaryBody(`"payments"`, `"quoted"`, labelJSON, rules, `{}`)
			recorder := doRequest(router, http.MethodPost, "/v1/net-policies", changed)
			if recorder.Code != http.StatusConflict {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusConflict, recorder.Body.String())
			}
			assertExactErrorShape(t, recorder, "NetPolicyConflictError")
			assertSafeErrorMessage(t, recorder)
		})
	}

	// The rejections changed nothing and consumed no order.
	items := listItems(t, router, "/v1/net-policies?label=50%25_off")
	if want := []map[string]any{seed}; !reflect.DeepEqual(items, want) {
		t.Fatalf("items after 409 rejections = %v, want unchanged %v", items, want)
	}
	registerCreated(t, router,
		rawBoundaryBody(`"payments"`, `"next"`, `"50%_off"`, rules, `{}`), 2, false)
}

// A rule clash (same direction, opposite action, overlapping ports) flags the
// new record only when namespace and label match verbatim; a label or
// namespace differing by case or a trailing space leaves conflict=false, and
// the earlier records' flags are not rewritten by later commits.
func TestStringBoundaryConflictFlagNeedsExactMatch(t *testing.T) {
	router, _ := newTestRouter(t)
	deny := `[{"direction": "ingress", "action": "deny", "ports": [80, 100]}]`
	allow := `[{"direction": "ingress", "action": "allow", "ports": [100, 200]}]`

	seed := registerCreated(t, router, rawBoundaryBody(`"华北"`, `"seed"`, `"tier=后端"`, deny, `{}`), 1, false)
	// Exact namespace and label: the opposite-action overlap is flagged.
	clash := registerCreated(t, router, rawBoundaryBody(`"华北"`, `"clash"`, `"tier=后端"`, allow, `{}`), 2, true)
	// Same clashing rule but label or namespace off by case/space: not flagged.
	caseLabel := registerCreated(t, router, rawBoundaryBody(`"华北"`, `"case-label"`, `"Tier=后端"`, allow, `{}`), 3, false)
	spacedLabel := registerCreated(t, router, rawBoundaryBody(`"华北"`, `"spaced-label"`, `"tier=后端 "`, allow, `{}`), 4, false)
	spacedNs := registerCreated(t, router, rawBoundaryBody(`"华北 "`, `"spaced-ns"`, `"tier=后端"`, allow, `{}`), 5, false)

	// Every record committed in namespace 华北 keeps its original flag.
	items := listItems(t, router, "/v1/net-policies?namespace="+url.QueryEscape("华北"))
	if want := []map[string]any{seed, clash, caseLabel, spacedLabel}; !reflect.DeepEqual(items, want) {
		t.Fatalf("items = %v, want %v (earlier conflict flags unchanged)", items, want)
	}
	items = listItems(t, router, "/v1/net-policies?namespace="+url.QueryEscape("华北 "))
	if want := []map[string]any{spacedNs}; !reflect.DeepEqual(items, want) {
		t.Fatalf("spaced namespace items = %v, want %v", items, want)
	}
}

// Query decoding is exact and single-pass: + and %20 both mean space, a
// literal + or % in a stored value needs its escape, escapes decode once, and
// % and _ are ordinary characters rather than wildcards. Namespace and label
// together intersect, and items come back order-ascending with every field.
func TestStringBoundaryQueryEncodingSemantics(t *testing.T) {
	router, _ := newTestRouter(t)
	rules := `[{"direction": "ingress", "action": "allow", "ports": [80, 80]}]`

	spaced := registerCreated(t, router, rawBoundaryBody(`"pay ments"`, `"a"`, `"spaced"`, rules, `{}`), 1, false)
	plus := registerCreated(t, router, rawBoundaryBody(`"literal"`, `"plus"`, `"a+b"`, rules, `{}`), 2, false)
	percent := registerCreated(t, router, rawBoundaryBody(`"literal"`, `"percent"`, `"a%b"`, rules, `{}`), 3, false)
	under := registerCreated(t, router, rawBoundaryBody(`"literal"`, `"under"`, `"a_b"`, rules, `{}`), 4, false)
	plain := registerCreated(t, router, rawBoundaryBody(`"literal"`, `"plain"`, `"axb"`, rules, `{}`), 5, false)
	encoded := registerCreated(t, router, rawBoundaryBody(`"literal"`, `"encoded"`, `"a%2Bb"`, rules, `{}`), 6, false)

	// A stored space is found by + and by %20 alike.
	for _, target := range []string{
		"/v1/net-policies?namespace=pay+ments",
		"/v1/net-policies?namespace=pay%20ments",
	} {
		items := listItems(t, router, target)
		if want := []map[string]any{spaced}; !reflect.DeepEqual(items, want) {
			t.Fatalf("GET %s items = %v, want %v", target, items, want)
		}
	}

	// A literal + in the stored label needs %2B; a raw + decodes to a space
	// and misses.
	items := listItems(t, router, "/v1/net-policies?label=a%2Bb")
	if want := []map[string]any{plus}; !reflect.DeepEqual(items, want) {
		t.Fatalf("label a%%2Bb items = %v, want %v", items, want)
	}
	recorder := doRequest(router, http.MethodGet, "/v1/net-policies?label=a+b", "")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("label a+b status = %d, want %d (raw + decodes to a space)", recorder.Code, http.StatusNotFound)
	}
	assertExactErrorShape(t, recorder, "NetPolicyNotFoundError")

	// % and _ are literal characters, not wildcards: each matches only its own
	// record, never the "axb" record.
	items = listItems(t, router, "/v1/net-policies?label=a%25b")
	if want := []map[string]any{percent}; !reflect.DeepEqual(items, want) {
		t.Fatalf("label a%%25b items = %v, want %v (%% must not act as a wildcard)", items, want)
	}
	items = listItems(t, router, "/v1/net-policies?label=a_b")
	if want := []map[string]any{under}; !reflect.DeepEqual(items, want) {
		t.Fatalf("label a_b items = %v, want %v (_ must not act as a wildcard)", items, want)
	}

	// Escapes decode exactly once: %252B is the literal text "%2B" and finds
	// the record storing that text, not the "a+b" record.
	items = listItems(t, router, "/v1/net-policies?label=a%252Bb")
	if want := []map[string]any{encoded}; !reflect.DeepEqual(items, want) {
		t.Fatalf("label a%%252Bb items = %v, want %v (parameters decode once)", items, want)
	}

	// Namespace and label together intersect.
	items = listItems(t, router, "/v1/net-policies?namespace=literal&label=a%2Bb")
	if want := []map[string]any{plus}; !reflect.DeepEqual(items, want) {
		t.Fatalf("intersection items = %v, want %v", items, want)
	}

	// Unregistered near values miss: decoded space, wrong case, extra space.
	for _, target := range []string{
		"/v1/net-policies?label=a%20b",
		"/v1/net-policies?namespace=Literal",
		"/v1/net-policies?label=a%2Bb+",
	} {
		recorder := doRequest(router, http.MethodGet, target, "")
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("GET %s status = %d, want %d", target, recorder.Code, http.StatusNotFound)
		}
		assertExactErrorShape(t, recorder, "NetPolicyNotFoundError")
	}

	// The full namespace listing comes back order-ascending, fields complete.
	items = listItems(t, router, "/v1/net-policies?namespace=literal")
	if want := []map[string]any{plus, percent, under, plain, encoded}; !reflect.DeepEqual(items, want) {
		t.Fatalf("namespace items = %v, want %v", items, want)
	}
}

// A query carrying an incomplete or non-hex percent escape is rejected as 400
// InvalidNetPolicyInputError even when another condition would have matched a
// committed record: no partial hit leaks, and the registry is untouched.
func TestStringBoundaryMalformedQueryLeaksNothing(t *testing.T) {
	router, _ := newTestRouter(t)
	rules := `[{"direction": "ingress", "action": "allow", "ports": [80, 80]}]`
	seed := registerCreated(t, router,
		rawBoundaryBody(`"boundary"`, `"rec"`, `"50%_off"`, rules, `{}`), 1, false)

	cases := map[string]string{
		"incomplete escape at value end":     "/v1/net-policies?label=50%",
		"incomplete escape mid value":        "/v1/net-policies?label=50%2",
		"non-hex escape in value":            "/v1/net-policies?namespace=boundar%GG",
		"lone percent in name":               "/v1/net-policies?lab%el=x",
		"bad escape after matching label":    "/v1/net-policies?label=50%25_off&junk=%2",
		"bad escape before matching label":   "/v1/net-policies?junk=%&label=50%25_off",
		"bad escape with non-matching value": "/v1/net-policies?label=missing&junk=%XY",
	}
	for name, target := range cases {
		t.Run(name, func(t *testing.T) {
			recorder := doRequest(router, http.MethodGet, target, "")
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("GET %s status = %d, want %d: %s",
					target, recorder.Code, http.StatusBadRequest, recorder.Body.String())
			}
			assertExactErrorShape(t, recorder, "InvalidNetPolicyInputError")
			assertSafeErrorMessage(t, recorder)
		})
	}

	// The rejected queries leaked nothing and changed nothing: the record is
	// still returned exactly, and the next identity takes the next order.
	items := listItems(t, router, "/v1/net-policies?label=50%25_off")
	if want := []map[string]any{seed}; !reflect.DeepEqual(items, want) {
		t.Fatalf("items after rejected queries = %v, want unchanged %v", items, want)
	}
	registerCreated(t, router,
		rawBoundaryBody(`"boundary"`, `"next"`, `"50%_off"`, rules, `{}`), 2, false)
}

// Special-string records survive a close/reopen of the same database file:
// the same encoded queries return the original records, an idempotent retry
// in a different JSON encoding still returns 200 with the stored record (the
// old conflict flag is not recomputed), a changed label is still 409, and the
// next new identity continues at max order + 1.
func TestStringBoundarySurvivesReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "service.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	router := NewRouter(st)

	deny := `[{"direction": "ingress", "action": "deny", "ports": [80, 100]}]`
	allow := `[{"direction": "ingress", "action": "allow", "ports": [100, 200]}]`
	nulLabel := jsonStringLiteral(t, "nul\x00byte")

	seed := registerCreated(t, router,
		rawBoundaryBody(`"华北"`, `"deny"`, nulLabel, deny, `{"mode": "enforce"}`), 1, false)
	sup := registerCreated(t, router,
		rawBoundaryBody(`"华北"`, `"sup"`, `"扩展𠀀😀"`, deny, `{}`), 2, false)
	clash := registerCreated(t, router,
		rawBoundaryBody(`"华北"`, `"clash"`, nulLabel, allow, `{}`), 3, true)

	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	reopened, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { reopened.Close() })
	router = NewRouter(reopened)

	// The same encoded queries return the original records, order ascending.
	items := listItems(t, router, "/v1/net-policies?namespace="+url.QueryEscape("华北"))
	if want := []map[string]any{seed, sup, clash}; !reflect.DeepEqual(items, want) {
		t.Fatalf("namespace items after reopen = %v, want %v", items, want)
	}
	items = listItems(t, router, "/v1/net-policies?label="+url.QueryEscape("nul\x00byte"))
	if want := []map[string]any{seed, clash}; !reflect.DeepEqual(items, want) {
		t.Fatalf("nul label items after reopen = %v, want %v", items, want)
	}

	// Idempotent retry in the escaped encoding: 200 with the stored record,
	// conflict flag not recomputed even though the clashing record exists.
	retry := doRequest(router, http.MethodPost, "/v1/net-policies",
		rawBoundaryBody(jsonEscapeNonASCII("华北"), `"deny"`, nulLabel, deny, `{"mode": "enforce"}`))
	if retry.Code != http.StatusOK {
		t.Fatalf("retry after reopen status = %d, want %d: %s", retry.Code, http.StatusOK, retry.Body.String())
	}
	var retryRecord map[string]any
	if err := json.Unmarshal(retry.Body.Bytes(), &retryRecord); err != nil {
		t.Fatalf("decode retry: %v", err)
	}
	if !reflect.DeepEqual(retryRecord, seed) {
		t.Fatalf("retry after reopen = %v, want the original %v", retryRecord, seed)
	}

	// A changed label on the same identity is still 409 after the reopen.
	changed := doRequest(router, http.MethodPost, "/v1/net-policies",
		rawBoundaryBody(`"华北"`, `"deny"`, `"changed"`, deny, `{"mode": "enforce"}`))
	if changed.Code != http.StatusConflict {
		t.Fatalf("changed label status = %d, want %d: %s", changed.Code, http.StatusConflict, changed.Body.String())
	}
	assertExactErrorShape(t, changed, "NetPolicyConflictError")

	// Neither the retry nor the 409 consumed an order.
	registerCreated(t, router,
		rawBoundaryBody(`"华北"`, `"after-reopen"`, `"tier=后端"`, deny, `{}`), 4, false)
}
