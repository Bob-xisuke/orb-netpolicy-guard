package api

// Strict query parsing regression tests for GET /v1/net-policies: the whole
// query string must validate before any record is returned, legal encodings
// keep the original matching semantics, and queries never mutate the registry.

import (
	"net/http"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Bob-xisuke/orb-netpolicy-guard/internal/store"
)

// A malformed fragment rejects the whole query no matter where it sits —
// first, middle or last segment, in a name or a value, in a known or an
// unknown parameter — and no matter whether the remaining conditions would
// have matched committed records. The committed records, their order and
// their conflict flags stay untouched.
func TestGetNetPoliciesRejectsMalformedQuerySegments(t *testing.T) {
	router, _ := newTestRouter(t)
	deny := registerCreated(t, router,
		singleRuleBody("payments", "default-deny", "tier=backend", "ingress", "deny", 80, 100, `{"mode": "enforce"}`),
		1, false)
	allow := registerCreated(t, router,
		singleRuleBody("payments", "allow-web", "tier=backend", "ingress", "allow", 100, 200, `{"mode": "enforce"}`),
		2, true)

	cases := map[string]string{
		// The headline case: a matching record exists, yet the bad escape
		// in the repeated parameter must not return it.
		"bad escape after matching namespace": "/v1/net-policies?namespace=payments&namespace=%ZZ",
		"bad escape in first segment":         "/v1/net-policies?namespace=%ZZ&namespace=payments",
		"bad escape in middle segment":        "/v1/net-policies?namespace=payments&junk=%2&label=tier%3Dbackend",
		"bad escape in last segment":          "/v1/net-policies?namespace=payments&junk=%",
		"incomplete escape at end of value":   "/v1/net-policies?namespace=paymen%7",
		"lone percent in value":               "/v1/net-policies?namespace=pay%ments",
		"non-hex escape in value":             "/v1/net-policies?namespace=pay%GGments",
		"bad escape in unknown param name":    "/v1/net-policies?%ZZ=x&namespace=payments",
		"bad escape in unknown param value":   "/v1/net-policies?junk=%ZZ&namespace=payments",
		"bad escape with non-matching filter": "/v1/net-policies?namespace=missing&junk=%ZZ",
		"semicolon in value":                  "/v1/net-policies?namespace=payments;extra",
		"semicolon in unknown param":          "/v1/net-policies?namespace=payments&junk=a;b",
		"semicolon in name":                   "/v1/net-policies?name;space=payments",
		"semicolon only segment":              "/v1/net-policies?namespace=payments&;",
		"duplicate identical value":           "/v1/net-policies?namespace=payments&namespace=payments",
		"duplicate via encoded name":          "/v1/net-policies?namespace=payments&%6Eamespace=payments",
		"duplicate label identical value":     "/v1/net-policies?label=tier%3Dbackend&label=tier%3Dbackend",
		"empty value":                         "/v1/net-policies?namespace=",
		"whitespace value from plus":          "/v1/net-policies?namespace=+",
		"whitespace value from escape":        "/v1/net-policies?namespace=%20",
		"no condition, only unknown param":    "/v1/net-policies?junk=x",
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

	// The rejected queries changed nothing: both committed records come back
	// untouched — content, order and conflict flags included.
	items := listItems(t, router, "/v1/net-policies?namespace=payments")
	if want := []map[string]any{deny, allow}; !reflect.DeepEqual(items, want) {
		t.Fatalf("items after rejected queries = %v, want unchanged %v", items, want)
	}
}

// Legal queries keep the original matching semantics: + means space, %2B/%3B/%26
// are literal +, ; and & inside values rather than separators or illegal input,
// parameters decode exactly once, and the decoded value matches verbatim —
// surrounding spaces and letter case are significant. Legal unknown parameters
// are ignored, and empty segments (including a trailing &) change nothing.
func TestGetNetPoliciesLegalEncodingSemantics(t *testing.T) {
	router, _ := newTestRouter(t)

	spaced := registerCreated(t, router,
		singleRuleBody("pay ments", "spaced", "tier=backend", "ingress", "allow", 80, 80, `{}`), 1, false)
	special := registerCreated(t, router,
		singleRuleBody("payments", "special", "a+b;c&d", "ingress", "allow", 80, 80, `{}`), 2, false)
	plain := registerCreated(t, router,
		singleRuleBody("payments", "plain", "tier=backend", "ingress", "allow", 80, 80, `{}`), 3, false)

	// + decodes to a space.
	items := listItems(t, router, "/v1/net-policies?namespace=pay+ments")
	if len(items) != 1 || !reflect.DeepEqual(items[0], spaced) {
		t.Fatalf("plus-as-space items = %v, want %v", items, spaced)
	}

	// %2B, %3B and %26 are literal characters inside a value, not separators.
	items = listItems(t, router, "/v1/net-policies?label=a%2Bb%3Bc%26d")
	if len(items) != 1 || !reflect.DeepEqual(items[0], special) {
		t.Fatalf("escaped-separator items = %v, want %v", items, special)
	}

	// The escaped & and ; above did not split parameters: intersecting with a
	// namespace condition still works on the decoded value.
	items = listItems(t, router, "/v1/net-policies?namespace=payments&label=a%2Bb%3Bc%26d")
	if len(items) != 1 || !reflect.DeepEqual(items[0], special) {
		t.Fatalf("intersection items = %v, want %v", items, special)
	}

	// Parameters decode exactly once: %252B is the literal text "%2B", not "+".
	miss := doRequest(router, http.MethodGet, "/v1/net-policies?label=a%252Bb%253Bc%2526d", "")
	if miss.Code != http.StatusNotFound {
		t.Fatalf("double-encoded status = %d, want %d", miss.Code, http.StatusNotFound)
	}
	assertErrorCode(t, miss, "NetPolicyNotFoundError")

	// Decoded values match verbatim: no trimming, no case folding.
	for _, target := range []string{
		"/v1/net-policies?namespace=+payments", // leading space is significant
		"/v1/net-policies?namespace=payments+", // trailing space is significant
		"/v1/net-policies?namespace=Payments",  // case is significant
	} {
		recorder := doRequest(router, http.MethodGet, target, "")
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("GET %s status = %d, want %d", target, recorder.Code, http.StatusNotFound)
		}
		assertErrorCode(t, recorder, "NetPolicyNotFoundError")
	}

	// Legal unknown parameters are ignored; empty segments and a trailing &
	// do not change the result.
	want := []map[string]any{special, plain}
	for _, target := range []string{
		"/v1/net-policies?namespace=payments&verbose=true&empty=",
		"/v1/net-policies?namespace=payments&unknown=%2B%3B%26",
		"/v1/net-policies?&namespace=payments&&",
		"/v1/net-policies?namespace=payments&",
	} {
		if items := listItems(t, router, target); !reflect.DeepEqual(items, want) {
			t.Fatalf("GET %s items = %v, want %v", target, items, want)
		}
	}
}

// With the storage layer down a well-formed query reports 503
// storage_unavailable, while a malformed query is still rejected with 400
// before any storage access.
func TestGetNetPoliciesStorageUnavailable(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
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

	recorder = doRequest(router, http.MethodGet, "/v1/net-policies?namespace=payments&namespace=%ZZ", "")
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("illegal query status = %d, want %d: %s",
			recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	assertExactErrorShape(t, recorder, "InvalidNetPolicyInputError")
	assertSafeErrorMessage(t, recorder)
}
