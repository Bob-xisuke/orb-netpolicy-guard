package api

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Bob-xisuke/orb-netpolicy-guard/internal/store"
)

// The whole query string must be valid before any record is returned. A
// malformed fragment — incomplete or non-hex percent escape, or a literal
// semicolon — invalidates the request whether it sits first, in the middle or
// last, and whether it belongs to a known or an unknown parameter. A matching
// payments record must not change the verdict.
func TestGetNetPoliciesMalformedFragmentRejectsWholeQuery(t *testing.T) {
	router, _ := newTestRouter(t)
	if rec := doRequest(router, http.MethodPost, "/v1/net-policies", validPolicy); rec.Code != http.StatusCreated {
		t.Fatalf("seed status = %d: %s", rec.Code, rec.Body.String())
	}

	cases := map[string]string{
		"non-hex escape on known value":                     "namespace=payments&namespace=%ZZ",
		"non-hex escape lowercase letters":                  "namespace=%zz",
		"non-hex escape invalid hex digit":                  "namespace=%2G",
		"lone trailing percent":                             "namespace=payments%",
		"lone percent as value":                             "x=%",
		"incomplete escape one hex digit":                   "namespace=%2",
		"incomplete escape after valid byte":                "x=%41%",
		"bad escape in known parameter name":                "namespa%ZZ=payments",
		"bad escape first in unknown parameter":             "x=%ZZ&namespace=payments",
		"bad escape last in unknown parameter":              "namespace=payments&x=%ZZ",
		"bad escape in unknown parameter name":              "ba%ZZd=1&namespace=payments",
		"bad key fragment before known parameter":           "%ZZ=&namespace=payments",
		"bad fragment at start and end":                     "%2&namespace=payments&x=%",
		"raw semicolon between fragments":                   "namespace=payments;x=y",
		"raw semicolon before known parameter":              "a=b;namespace=payments",
		"raw semicolon after known parameter":               "namespace=payments&x=a;b",
		"raw semicolon as the whole query":                  ";",
		"raw semicolon in known value":                      "namespace=a;b",
		"raw semicolon in parameter name":                   "a;b=c",
		"raw semicolon in unknown value first":              "x=a;b&namespace=payments",
		"raw semicolon fragment then valid tail":            "namespace=payments&a=b;&x=y",
		"encoded semicolon value plus raw semicolon":        "label=a%3Bb;c",
		"raw semicolon in namespace alongside matching one": "namespace=payments&namespace=a;b",
	}
	for name, query := range cases {
		t.Run(name, func(t *testing.T) {
			recorder := doRequest(router, http.MethodGet, "/v1/net-policies?"+query, "")
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("GET ?%s status = %d, want %d (body %s)",
					query, recorder.Code, http.StatusBadRequest, recorder.Body.String())
			}
			// The matching payments record must never be returned as items.
			assertExactErrorShape(t, recorder, "InvalidNetPolicyInputError")
			assertSafeErrorMessage(t, recorder)
		})
	}
}

// After successful decoding, the known parameters namespace and label are
// recognized by their decoded names: namespace and %6Eamespace are the same
// parameter, equal repeated values are still repetitions, and empty or
// whitespace-only values are invalid. At least one condition must remain.
func TestGetNetPoliciesDecodedDuplicateAndBlankKnownParams(t *testing.T) {
	router, _ := newTestRouter(t)
	if rec := doRequest(router, http.MethodPost, "/v1/net-policies", validPolicy); rec.Code != http.StatusCreated {
		t.Fatalf("seed status = %d: %s", rec.Code, rec.Body.String())
	}

	cases := map[string]string{
		"no query at all":              "",
		"only empty fragments":         "&&",
		"unknown parameter only":       "unknown=value",
		"empty unknown and no known":   "unknown=",
		"empty namespace":              "namespace=",
		"blank namespace spaces":       "namespace=%20%20",
		"blank label plus signs":       "label=+++",
		"blank label tab":              "label=%09",
		"blank label newline":          "label=%0A",
		"both known empty":             "namespace=&label=",
		"duplicate known different":    "namespace=a&namespace=b",
		"duplicate known identical":    "namespace=a&namespace=a",
		"duplicate decoded identical":  "namespace=payments&namespace=%70ayments",
		"literal and encoded name":     "namespace=a&%6Eamespace=b",
		"encoded then literal name":    "%6Eamespace=a&namespace=b",
		"duplicate label encoded name": "label=x&%6Cabel=y",
		"duplicate label identical":    "label=x&label=x",
		"valid plus blank duplicate":   "namespace=payments&namespace=%20",
		"blank then valid duplicate":   "namespace=%20&namespace=payments",
	}
	for name, query := range cases {
		t.Run(name, func(t *testing.T) {
			recorder := doRequest(router, http.MethodGet, "/v1/net-policies?"+query, "")
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("GET ?%s status = %d, want %d (body %s)",
					query, recorder.Code, http.StatusBadRequest, recorder.Body.String())
			}
			assertExactErrorShape(t, recorder, "InvalidNetPolicyInputError")
			assertSafeErrorMessage(t, recorder)
		})
	}
}

// parseNetPolicyQuery decodes exactly once: "+" is a space while %2B, %3B and
// %26 become literal "+", ";" and "&" inside values, and %25 is a literal
// percent (so %2541 stays the three characters %41 rather than decoding
// twice). Unknown parameters survive decoding but are ignored.
func TestParseNetPolicyQueryDecoding(t *testing.T) {
	legal := []struct {
		name      string
		rawQuery  string
		namespace string
		label     string
	}{
		{"plus is space", "label=a+b", "", "a b"},
		{"encoded space", "label=a%20b", "", "a b"},
		{"encoded plus", "label=a%2Bb", "", "a+b"},
		{"encoded semicolon", "label=a%3Bb", "", "a;b"},
		{"encoded ampersand", "label=a%26b", "", "a&b"},
		{"single decode of percent", "label=a%2541", "", "a%41"},
		{"encoded equals sign", "label=tier%3Dbackend", "", "tier=backend"},
		{"unknown parameter ignored", "namespace=payments&unknown=ignored", "payments", ""},
		{"unknown empty value ignored", "namespace=payments&unknown=", "payments", ""},
		{"unknown encoded punctuation ignored", "unknown=%2B%3B%26&namespace=payments", "payments", ""},
		{"both conditions decoded", "namespace=a+b&label=c%2Bd", "a b", "c+d"},
	}
	for _, tc := range legal {
		t.Run(tc.name, func(t *testing.T) {
			filters, err := parseNetPolicyQuery(tc.rawQuery)
			if err != nil {
				t.Fatalf("parseNetPolicyQuery(%q) err = %v, want nil", tc.rawQuery, err)
			}
			if filters.namespace != tc.namespace || filters.label != tc.label {
				t.Fatalf("filters = (%q, %q), want (%q, %q)",
					filters.namespace, filters.label, tc.namespace, tc.label)
			}
		})
	}

	illegal := []string{
		"",
		"&&",
		"unknown=value",
		"namespace=",
		"namespace=%20",
		"namespace=a&namespace=a",
		"namespace=a&%6Eamespace=b",
		"x=%ZZ",
		"namespace=payments&x=%",
		"a=b;c=d",
		"namespace=payments&%ZZ=x",
	}
	for _, rawQuery := range illegal {
		t.Run("illegal/"+rawQuery, func(t *testing.T) {
			if filters, err := parseNetPolicyQuery(rawQuery); err == nil {
				t.Fatalf("parseNetPolicyQuery(%q) = %+v, want error", rawQuery, filters)
			}
		})
	}
}

// Legal encodings match stored values verbatim after the single decode:
// records whose label contains a literal "+", ";", "&", "%" or space are found
// only through the matching encoding, never confused with the separator or
// with each other. Values are exact after decoding — no trimming or case
// folding.
func TestGetNetPoliciesLegalEncodingMatchesExactValues(t *testing.T) {
	router, _ := newTestRouter(t)
	specials := []struct {
		name  string
		label string
	}{
		{"plus", "a+b"},
		{"semi", "a;b"},
		{"amp", "a&b"},
		{"pct", "a%41"},
		{"space", "a b"},
	}
	for _, item := range specials {
		body := policyBody("payments", item.name, item.label, `{}`)
		if rec := doRequest(router, http.MethodPost, "/v1/net-policies", body); rec.Code != http.StatusCreated {
			t.Fatalf("seed %s status = %d: %s", item.name, rec.Code, rec.Body.String())
		}
	}
	// A record in a namespace containing a literal ampersand and semicolon.
	if rec := doRequest(router, http.MethodPost, "/v1/net-policies",
		policyBody("a&b;c", "other", "l", `{}`)); rec.Code != http.StatusCreated {
		t.Fatalf("seed special namespace status = %d: %s", rec.Code, rec.Body.String())
	}

	matches := []struct {
		name   string
		query  string
		wantNS string
		want   string // expected record name
	}{
		{"literal plus via %2B", "label=a%2Bb", "payments", "plus"},
		{"literal semicolon via %3B", "label=a%3Bb", "payments", "semi"},
		{"literal ampersand via %26", "label=a%26b", "payments", "amp"},
		{"literal percent via %25 once", "label=a%2541", "payments", "pct"},
		{"space via plus sign", "label=a+b", "payments", "space"},
		{"space via %20", "label=a%20b", "payments", "space"},
		{"special namespace via %26 and %3B", "namespace=a%26b%3Bc&label=l", "a&b;c", "other"},
		{"intersection with encoded label", "namespace=payments&label=a%2Bb", "payments", "plus"},
		{"encoded namespace name %6Eamespace", "%6Eamespace=payments&label=a%2Bb", "payments", "plus"},
		{"encoded label name %6Cabel alone", "%6Cabel=a%3Bb", "payments", "semi"},
	}
	for _, tc := range matches {
		t.Run(tc.name, func(t *testing.T) {
			items := listItems(t, router, "/v1/net-policies?"+tc.query)
			if len(items) != 1 || items[0]["name"] != tc.want {
				t.Fatalf("items = %v, want exactly the %q record", items, tc.want)
			}
			if items[0]["namespace"] != tc.wantNS {
				t.Fatalf("namespace = %v, want %q", items[0]["namespace"], tc.wantNS)
			}
		})
	}

	// "+" means space: it must not also match the literal-plus record.
	items := listItems(t, router, "/v1/net-policies?label=a+b")
	if len(items) != 1 || items[0]["name"] != "space" {
		t.Fatalf("plus-decoded items = %v, want only the space record", items)
	}

	// Exact matching after decode: no trimming and no case folding.
	for _, query := range []string{
		"namespace=%20payments",
		"namespace=payments%20",
		"namespace=PAYMENTS",
		"namespace=payments&label=%20a%2Bb",
	} {
		t.Run("no match/"+query, func(t *testing.T) {
			recorder := doRequest(router, http.MethodGet, "/v1/net-policies?"+query, "")
			if recorder.Code != http.StatusNotFound {
				t.Fatalf("GET ?%s status = %d, want %d: %s",
					query, recorder.Code, http.StatusNotFound, recorder.Body.String())
			}
			assertErrorCode(t, recorder, "NetPolicyNotFoundError")
		})
	}
}

// Empty fragments and a trailing "&" carry no parameter and must not change
// the existing result; legal unknown parameters (including punctuation-heavy
// decoded values) are ignored.
func TestGetNetPoliciesEmptyFragmentsAndUnknownParams(t *testing.T) {
	router, _ := newTestRouter(t)
	if rec := doRequest(router, http.MethodPost, "/v1/net-policies", validPolicy); rec.Code != http.StatusCreated {
		t.Fatalf("seed status = %d: %s", rec.Code, rec.Body.String())
	}

	legal := []string{
		"namespace=payments&",
		"&namespace=payments",
		"namespace=payments&&",
		"namespace=payments&unknown=value",
		"namespace=payments&unknown=",
		"namespace=payments&unknown=%2B%3B%26",
		"unknown=1&&namespace=payments&",
		"namespace=payments&a=1&b=2&",
	}
	for _, query := range legal {
		t.Run(query, func(t *testing.T) {
			items := listItems(t, router, "/v1/net-policies?"+query)
			if len(items) != 1 || items[0]["name"] != "default-deny" {
				t.Fatalf("items = %v, want the single payments record", items)
			}
		})
	}

	for _, query := range []string{"", "&&", "unknown=value", "unknown="} {
		t.Run("missing condition/"+query, func(t *testing.T) {
			recorder := doRequest(router, http.MethodGet, "/v1/net-policies?"+query, "")
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("GET ?%s status = %d, want %d", query, recorder.Code, http.StatusBadRequest)
			}
			assertErrorCode(t, recorder, "InvalidNetPolicyInputError")
		})
	}
}

// Input validation happens before storage access: a legal query against an
// unavailable store returns 503 storage_unavailable, while an illegal query
// still returns 400 InvalidNetPolicyInputError even though the store is down.
func TestGetNetPoliciesInvalidInputWinsOverStorageFailure(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "service.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	router := NewRouter(st)
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	recorder := doRequest(router, http.MethodGet, "/v1/net-policies?namespace=payments", "")
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("legal query status = %d, want %d: %s",
			recorder.Code, http.StatusServiceUnavailable, recorder.Body.String())
	}
	assertExactErrorShape(t, recorder, "storage_unavailable")
	assertSafeErrorMessage(t, recorder)

	for _, query := range []string{
		"namespace=payments&namespace=%ZZ",
		"x=%ZZ",
		"a=b;c=d",
		"namespace=payments&x=a;b",
	} {
		t.Run(query, func(t *testing.T) {
			recorder := doRequest(router, http.MethodGet, "/v1/net-policies?"+query, "")
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("GET ?%s against down store status = %d, want %d: %s",
					query, recorder.Code, http.StatusBadRequest, recorder.Body.String())
			}
			assertExactErrorShape(t, recorder, "InvalidNetPolicyInputError")
			assertSafeErrorMessage(t, recorder)
		})
	}
}

// Queries — whether they hit (200), miss (404) or are invalid (400) — never
// alter committed record content, order or conflict flags, and consume no
// order values.
func TestGetNetPolicysQueriesDoNotMutateRegistry(t *testing.T) {
	router, _ := newTestRouter(t)
	denyBody := singleRuleBody("payments", "deny-web", "tier=backend",
		"ingress", "deny", 80, 100, `{"mode": "enforce"}`)
	seed := registerCreated(t, router, denyBody, 1, false)
	clashBody := singleRuleBody("payments", "allow-web", "tier=backend",
		"ingress", "allow", 100, 200, `{"mode": "enforce"}`)
	clash := registerCreated(t, router, clashBody, 2, true)

	for _, query := range []string{
		"namespace=payments",
		"label=tier%3Dbackend",
		"namespace=payments&label=tier%3Dbackend",
		"label=missing",
		"namespace=payments&unknown=x",
		"namespace=payments&",
		"namespace=payments&namespace=%ZZ",
		"x=%ZZ&namespace=payments",
		"a=b;c=d",
		"namespace=payments&%6Eamespace=other",
	} {
		recorder := doRequest(router, http.MethodGet, "/v1/net-policies?"+query, "")
		switch recorder.Code {
		case http.StatusOK, http.StatusNotFound, http.StatusBadRequest:
		default:
			t.Fatalf("GET ?%s unexpected status %d: %s", query, recorder.Code, recorder.Body.String())
		}
	}

	items := listItems(t, router, "/v1/net-policies?namespace=payments")
	if want := []map[string]any{seed, clash}; !reflect.DeepEqual(items, want) {
		t.Fatalf("records changed after queries:\n got %v\nwant %v", items, want)
	}
	if items[0]["order"] != float64(1) || items[0]["conflict"] != false {
		t.Fatalf("seed metadata changed: %v", items[0])
	}
	if items[1]["order"] != float64(2) || items[1]["conflict"] != true {
		t.Fatalf("clash metadata changed: %v", items[1])
	}

	// Same-content retry still returns the original record untouched.
	retry := doRequest(router, http.MethodPost, "/v1/net-policies", clashBody)
	if retry.Code != http.StatusOK {
		t.Fatalf("retry status = %d: %s", retry.Code, retry.Body.String())
	}
	var retryRecord map[string]any
	if err := json.Unmarshal(retry.Body.Bytes(), &retryRecord); err != nil {
		t.Fatalf("decode retry: %v", err)
	}
	if !reflect.DeepEqual(retryRecord, clash) {
		t.Fatalf("retry record = %v, want unchanged %v", retryRecord, clash)
	}

	// The queries consumed no order: the next brand-new identity takes order 3
	// and, having no opposite-action overlap, carries conflict=false.
	nextBody := singleRuleBody("payments", "after-queries", "tier=egress",
		"egress", "allow", 53, 53, `{}`)
	registerCreated(t, router, nextBody, 3, false)
}

// Over a real HTTP connection the headline regression still holds: with a
// payments record committed, namespace=payments&namespace=%ZZ must answer 400
// InvalidNetPolicyInputError rather than returning the payments record, for
// every position the bad fragment can take. This guards the transport layer
// too (the raw query must reach the handler intact).
func TestGetNetPoliciesMalformedQueryOverRealHTTP(t *testing.T) {
	server, _ := newConcurrentTestServer(t)
	client := &http.Client{Timeout: clientTimeout}

	status, body, err := clientRequest(client, http.MethodPost, server.URL+"/v1/net-policies", validPolicy)
	if err != nil || status != http.StatusCreated {
		t.Fatalf("seed: status=%d err=%v body=%s", status, err, string(body))
	}

	for _, target := range []string{
		"/v1/net-policies?namespace=payments&namespace=%ZZ",
		"/v1/net-policies?%ZZ=&namespace=payments",
		"/v1/net-policies?namespace=payments&unknown=%ZZ",
		"/v1/net-policies?namespace=payments&a=b;c",
	} {
		status, body, err := clientRequest(client, http.MethodGet, server.URL+target, "")
		if err != nil {
			t.Fatalf("GET %s: %v", target, err)
		}
		assertExactErrorBytes(t, status, body, http.StatusBadRequest, "InvalidNetPolicyInputError")
	}

	// The legal query over the same connection still returns the payments
	// record, proving the bad requests changed nothing.
	status, body, err = clientRequest(client, http.MethodGet,
		server.URL+"/v1/net-policies?namespace=payments", "")
	if err != nil {
		t.Fatalf("legal GET: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("legal query status = %d: %s", status, string(body))
	}
	var listed struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatalf("decode items: %v", err)
	}
	if len(listed.Items) != 1 || listed.Items[0]["name"] != "default-deny" {
		t.Fatalf("items = %v, want the single payments record", listed.Items)
	}
}

// Sanity check that GET /healthz and POST /v1/net-policies keep their
// published behaviour alongside the stricter query parsing.
func TestQueryHardeningLeavesOtherEndpointsUntouched(t *testing.T) {
	router, _ := newTestRouter(t)

	health := doRequest(router, http.MethodGet, "/healthz", "")
	if health.Code != http.StatusOK || health.Body.String() != `{"database":"ok","status":"ok"}` {
		t.Fatalf("healthz = %d %s", health.Code, health.Body.String())
	}

	created := doRequest(router, http.MethodPost, "/v1/net-policies", validPolicy)
	if created.Code != http.StatusCreated {
		t.Fatalf("POST status = %d: %s", created.Code, created.Body.String())
	}
	var rec map[string]any
	if err := json.Unmarshal(created.Body.Bytes(), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec["order"] != float64(1) || rec["conflict"] != false {
		t.Fatalf("created metadata = order %v conflict %v, want 1/false", rec["order"], rec["conflict"])
	}

	// Invalid POST bodies still return the same 400 contract.
	bad := doRequest(router, http.MethodPost, "/v1/net-policies", `{"namespace":`)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("bad POST status = %d: %s", bad.Code, bad.Body.String())
	}
	assertExactErrorShape(t, bad, "InvalidNetPolicyInputError")
}
