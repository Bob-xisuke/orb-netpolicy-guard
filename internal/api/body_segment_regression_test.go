package api

// Regression coverage for request bodies that arrive in several write segments
// and for requests whose body ends before the JSON document is complete (or
// keeps carrying bytes after it). The decoder is a streaming one, so the wire
// segmentation must be invisible: a legal body split at any byte boundary —
// inside a UTF-8 multibyte sequence, inside a JSON escape, between port digits,
// inside a pluginParams member — commits exactly as the same body sent at once,
// while a truncated stream, a non-EOF read failure or trailing junk fails with
// the same 400 InvalidNetPolicyInputError a single-shot malformed body gets.
//
// Tests drive only the published HTTP surface. Segmented delivery uses a real
// httptest server over an io.Pipe (a pipe Write cannot return before the
// server has consumed those bytes, so the decoder genuinely sees a stream that
// runs dry mid-document); the visibility tests hold a genuinely open TCP
// connection with the complete object already delivered and query the registry
// while the handler is parked reading the rest of the body.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

// errBodyReadFailed stands in for a transport failure while reading the body:
// it is deliberately not io.EOF, so the decoder must treat it like any other
// read failure rather than a clean end of input.
var errBodyReadFailed = errors.New("simulated transport failure while reading request body")

// failingReader returns the sentinel non-EOF error on every read.
type failingReader struct{}

func (failingReader) Read(p []byte) (int, error) { return 0, errBodyReadFailed }

// segmentedBody is the shared legal submission. It deliberately concentrates
// every boundary kind the suite splits across: multibyte UTF-8 in the identity
// and label ("策略", "后端"), a literal multibyte rune immediately followed by a
// JSON \uXXXX escape ("华" then the raw text backslash-u-5-3-1-7), the two
// integer ports, and two pluginParams members.
const segmentedBody = `{"namespace":"payments","name":"segment-策略","label":"tier=后端","rules":[{"direction":"ingress","action":"allow","ports":[8080,9090]}],"pluginParams":{"mode":"enforce","zone":"华\u5317"}}`

// segmentedClashSeed clashes with segmentedBody: same namespace and label,
// ingress deny touching the candidate's ingress allow at port 8080.
const segmentedClashSeed = `{"namespace":"payments","name":"segment-clash-seed","label":"tier=后端","rules":[{"direction":"ingress","action":"deny","ports":[8080,8080]}],"pluginParams":{}}`

// postInChunks sends body to the live server, splitting it at every byte offset
// in cuts (offsets relative to the start of body, strictly increasing and
// within the body). Each segment is written separately to an io.Pipe; a pipe
// Write only returns once the server has read the bytes, so when the suffix is
// written the decoder has necessarily been offered — and is usually parked on
// — a stream ending exactly at the cut.
func postInChunks(t *testing.T, server *httptest.Server, body string, cuts ...int) (int, []byte) {
	t.Helper()
	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/net-policies", pr)
	if err != nil {
		t.Fatalf("build chunked request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	type result struct {
		status int
		raw    []byte
		err    error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- result{err: err}
			return
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		done <- result{status: resp.StatusCode, raw: raw, err: err}
	}()

	prev := 0
	for _, cut := range cuts {
		if cut <= prev || cut >= len(body) {
			t.Fatalf("cut %d is not strictly inside (prev=%d, len=%d)", cut, prev, len(body))
		}
		if _, err := pw.Write([]byte(body[prev:cut])); err != nil {
			t.Fatalf("write segment: %v", err)
		}
		prev = cut
	}
	if _, err := pw.Write([]byte(body[prev:])); err != nil {
		t.Fatalf("write final segment: %v", err)
	}
	if err := pw.Close(); err != nil {
		t.Fatalf("close body: %v", err)
	}

	res := <-done
	if res.err != nil {
		t.Fatalf("chunked request failed: %v", res.err)
	}
	return res.status, res.raw
}

// mustCutAt returns the byte offset marker+offset, requiring it to fall inside
// body, so split points are described by readable substrings instead of magic
// numbers.
func mustCutAt(t *testing.T, body, marker string, offset int) int {
	t.Helper()
	idx := strings.Index(body, marker)
	if idx < 0 {
		t.Fatalf("marker %q not found in body", marker)
	}
	cut := idx + offset
	if cut <= 0 || cut >= len(body) {
		t.Fatalf("cut %d for marker %q+%d falls outside body of length %d", cut, marker, offset, len(body))
	}
	return cut
}

// postExpectCreated posts a complete body over ordinary transport and demands
// the full record with the expected order and conflict flag.
func postExpectCreated(t *testing.T, server *httptest.Server, body string, order int64, conflict bool) map[string]any {
	t.Helper()
	status, raw, err := clientRequest(http.DefaultClient, http.MethodPost,
		server.URL+"/v1/net-policies", body)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	if status != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", status, string(raw))
	}
	got := decodeRecord(t, raw)
	if want := wantRecord(t, body, order, conflict); !reflect.DeepEqual(got, want) {
		t.Fatalf("record = %v, want %v", got, want)
	}
	return got
}

// clientListItems GETs a target path on the live server, demands 200 and
// returns the decoded items.
func clientListItems(t *testing.T, server *httptest.Server, target string) []map[string]any {
	t.Helper()
	status, raw, err := clientRequest(http.DefaultClient, http.MethodGet, server.URL+target, "")
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	if status != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200: %s", target, status, string(raw))
	}
	var body struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode items: %v", err)
	}
	return body.Items
}

// doPostReader drives the handler with an arbitrary body reader.
func doPostReader(router http.Handler, body io.Reader) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/net-policies", body)
	router.ServeHTTP(recorder, request)
	return recorder
}

// Sending one complete body first (201, order 2, conflict=true against the
// seed) and then re-sending the SAME bytes split at EVERY byte offset
// 1..len-1 must always be an idempotent retry: 200 with the original record,
// never 201, 400 or 409. The exhaustive sweep crosses every UTF-8
// lead/continuation byte, every byte of the \uXXXX escape, every port digit
// and every pluginParams member boundary, so segmentation cannot depend on
// where the cut lands. None of the split retries adds a row or consumes an
// order.
func TestChunkedRegistrationEquivalentAtEveryByteBoundary(t *testing.T) {
	server, _ := newConcurrentTestServer(t)

	// The clash seed is the first record (order 1, no conflict of its own).
	postExpectCreated(t, server, segmentedClashSeed, 1, false)

	// Whole body first: order 2, conflict true against the seed.
	status, raw, err := clientRequest(http.DefaultClient, http.MethodPost,
		server.URL+"/v1/net-policies", segmentedBody)
	if err != nil {
		t.Fatalf("whole-body post: %v", err)
	}
	if status != http.StatusCreated {
		t.Fatalf("whole-body status = %d, want 201: %s", status, string(raw))
	}
	want := wantRecord(t, segmentedBody, 2, true)
	if got := decodeRecord(t, raw); !reflect.DeepEqual(got, want) {
		t.Fatalf("whole-body record = %v, want %v", got, want)
	}

	for cut := 1; cut < len(segmentedBody); cut++ {
		status, raw := postInChunks(t, server, segmentedBody, cut)
		if status != http.StatusOK {
			t.Fatalf("cut at byte %d: status = %d, want 200 (same-content retry): %s",
				cut, status, string(raw))
		}
		if got := decodeRecord(t, raw); !reflect.DeepEqual(got, want) {
			t.Fatalf("cut at byte %d: record = %v, want the original %v", cut, got, want)
		}
	}

	// None of the split retries added a row or consumed an order: the namespace
	// holds exactly the seed and the one record, and a fresh identity takes 3.
	items := clientListItems(t, server, "/v1/net-policies?namespace=payments")
	if len(items) != 2 {
		t.Fatalf("items = %v, want exactly two records after the split sweep", items)
	}
	nextBody := singleRuleBody("payments", "segment-after-sweep", "tier=other",
		"egress", "allow", 53, 53, `{}`)
	postExpectCreated(t, server, nextBody, 3, false)
}

// A first-ever registration whose body is split at a representative interior
// boundary returns 201 with the same fields, order 1 and conflict flag the
// whole body would produce; a segmented same-content retry then returns 200
// with that record, and the next fresh identity takes order 2. A separate
// seeded case checks order 2 / conflict=true parity.
func TestChunkedRegistrationFirstCommitAcrossBoundaryKinds(t *testing.T) {
	cases := []struct {
		name   string
		marker string
		offset int
	}{
		{"field name mid name token", `"name"`, 3},
		{"utf8 inside first byte pair of 策略", "策略", 1},
		{"utf8 between 策 and 略", "策略", 3},
		{"utf8 inside label 后端", "后端", 2},
		{"multibyte rune directly before escape", "华", 1},
		{"json escape right after backslash", `\u5317`, 1},
		{"json escape right after backslash-u", `\u5317`, 2},
		{"json escape inside hex digits", `\u5317`, 4},
		{"json escape right after the escape", `\u5317`, 6},
		{"first port after first digit", `8080`, 1},
		{"first port between digits", `8080`, 2},
		{"second port between digits", `9090`, 3},
		{"rules array right after opening bracket", `"rules":[`, len(`"rules":[`)},
		{"rules inside the rule object", `{"direction"`, 1},
		{"top-level comma before rules", `,"rules"`, 1},
		{"plugin member between key and value", `"mode":"enforce"`, len(`"mode":`)},
		{"plugin member inside string value", `"mode":"enforce"`, len(`"mode":"enf`)},
		{"plugin members between two members", `"enforce","zone"`, len(`"enforce",`)},
		{"plugin member name mid token", `"zone"`, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := newConcurrentTestServer(t)
			cut := mustCutAt(t, segmentedBody, tc.marker, tc.offset)

			status, raw := postInChunks(t, server, segmentedBody, cut)
			if status != http.StatusCreated {
				t.Fatalf("status = %d, want 201 for the first split registration: %s",
					status, string(raw))
			}
			want := wantRecord(t, segmentedBody, 1, false)
			if got := decodeRecord(t, raw); !reflect.DeepEqual(got, want) {
				t.Fatalf("split record = %v, want %v", got, want)
			}

			// Querying it back returns the same complete record.
			items := clientListItems(t, server, "/v1/net-policies?label=tier%3D%E5%90%8E%E7%AB%AF")
			if len(items) != 1 || !reflect.DeepEqual(items[0], want) {
				t.Fatalf("stored items = %v, want %v", items, want)
			}

			// A segmented same-content retry returns 200 with the same record.
			status, raw = postInChunks(t, server, segmentedBody, cut)
			if status != http.StatusOK {
				t.Fatalf("split retry status = %d, want 200: %s", status, string(raw))
			}
			if got := decodeRecord(t, raw); !reflect.DeepEqual(got, want) {
				t.Fatalf("split retry record = %v, want %v", got, want)
			}

			// The retry added nothing: a brand-new identity continues at order 2.
			nextBody := singleRuleBody("payments", "segment-next", "tier=other",
				"egress", "allow", 53, 53, `{}`)
			postExpectCreated(t, server, nextBody, 2, false)
		})
	}

	// Conflict and order parity against a committed clash: splitting the body
	// inside a UTF-8 value still yields order 2 and conflict=true, exactly like
	// sending the bytes at once.
	t.Run("conflict and order parity", func(t *testing.T) {
		server, _ := newConcurrentTestServer(t)
		postExpectCreated(t, server, segmentedClashSeed, 1, false)
		cut := mustCutAt(t, segmentedBody, "策略", 1)
		status, raw := postInChunks(t, server, segmentedBody, cut)
		if status != http.StatusCreated {
			t.Fatalf("status = %d, want 201: %s", status, string(raw))
		}
		want := wantRecord(t, segmentedBody, 2, true)
		if got := decodeRecord(t, raw); !reflect.DeepEqual(got, want) {
			t.Fatalf("split clashing record = %v, want %v", got, want)
		}
		items := clientListItems(t, server, "/v1/net-policies?namespace=payments")
		if len(items) != 2 || items[1]["conflict"] != true || items[1]["order"] != float64(2) {
			t.Fatalf("items = %v, want the clash seed plus an order-2 conflict record", items)
		}
		// A segmented retry keeps 200 and the original conflict flag.
		status, raw = postInChunks(t, server, segmentedBody, cut)
		if status != http.StatusOK || !reflect.DeepEqual(decodeRecord(t, raw), want) {
			t.Fatalf("retry status = %d record = %v, want 200 %v", status, decodeRecord(t, raw), want)
		}
	})
}

// A stream that ends before the JSON document is complete — a field name cut
// mid token, a string left open (including inside a multibyte run and inside a
// JSON escape), a rules array or rule object left open, a pluginParams object
// left open, or the top-level object left open with every field complete — is
// 400 InvalidNetPolicyInputError with the published envelope, writes nothing
// and consumes no order.
func TestChunkedBodyPrematureEndRejected(t *testing.T) {
	multibyteCut := segmentedBody[:mustCutAt(t, segmentedBody, "策略", 1)]
	cases := map[string]string{
		"empty body":                           ``,
		"opening brace only":                   `{`,
		"field name not closed":                `{"namespace":"n","nam`,
		"string value not closed":              `{"namespace":"n","name":"ab`,
		"string cut inside json escape":        `{"namespace":"n","name":"ab\u004`,
		"string cut inside utf8":               multibyteCut,
		"rules array opened only":              `{"namespace":"n","name":"a","label":"l","rules":[`,
		"rule complete but array open":         `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[1,2]}`,
		"rules value not closed":               `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress"`,
		"pluginParams object open":             `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[1,2]}],"pluginParams":{"mode":"enforce"`,
		"pluginParams field with no value":     `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[1,2]}],"pluginParams":`,
		"top object open with all fields done": `{"namespace":"n","name":"a","label":"l","rules":[{"direction":"ingress","action":"allow","ports":[1,2]}],"pluginParams":{}`,
	}
	for name, prefix := range cases {
		t.Run(name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			recorder := doRequest(router, http.MethodPost, "/v1/net-policies", prefix)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body.String())
			}
			assertExactErrorShape(t, recorder, "InvalidNetPolicyInputError")
			assertSafeErrorMessage(t, recorder)

			// Nothing was written for a brand-new identity...
			miss := doRequest(router, http.MethodGet, "/v1/net-policies?namespace=n", "")
			if miss.Code != http.StatusNotFound {
				t.Fatalf("namespace query status = %d, want 404", miss.Code)
			}
			assertErrorCode(t, miss, "NetPolicyNotFoundError")

			// ...and the failed request consumed no order.
			registerCreated(t, router, policyBody("n", "ok", "l", `{}`), 1, false)
		})
	}
}

// A non-EOF error while reading the body is InvalidNetPolicyInputError just
// like a clean truncation: the error before any token, the error arriving only
// after the complete object has been read (the trailing-value probe), the
// error after trailing JSON whitespace, and the error mid-document all return
// 400, leak nothing through the message, write no row and consume no order.
func TestChunkedBodyNonEOFReadErrorRejected(t *testing.T) {
	complete := policyBody("n", "a", "l", `{"mode":"enforce"}`)
	truncated := `{"namespace":"n","name":"a","label":"l","rules":[`
	cases := map[string]io.Reader{
		"error before any token":      failingReader{},
		"error after complete object": io.MultiReader(strings.NewReader(complete), failingReader{}),
		"error after trailing whitespace": io.MultiReader(
			strings.NewReader(complete+" \t\r\n"), failingReader{}),
		"error mid document": io.MultiReader(strings.NewReader(truncated), failingReader{}),
	}
	for name, reader := range cases {
		t.Run(name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			recorder := doPostReader(router, reader)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body.String())
			}
			assertExactErrorShape(t, recorder, "InvalidNetPolicyInputError")
			assertSafeErrorMessage(t, recorder)

			miss := doRequest(router, http.MethodGet, "/v1/net-policies?namespace=n", "")
			if miss.Code != http.StatusNotFound {
				t.Fatalf("namespace query status = %d, want 404", miss.Code)
			}
			assertErrorCode(t, miss, "NetPolicyNotFoundError")
			registerCreated(t, router, policyBody("n", "ok", "l", `{}`), 1, false)
		})
	}
}

// JSON whitespace after the complete object is part of a normal end of input
// (201), while a second JSON value or any non-whitespace garbage — even when it
// follows whitespace — is the same 400 InvalidNetPolicyInputError, with no row
// and no order consumed.
func TestChunkedBodyTrailingWhitespaceAcceptedGarbageRejected(t *testing.T) {
	t.Run("trailing whitespace accepted", func(t *testing.T) {
		router, _ := newTestRouter(t)
		clean := policyBody("n", "spaced", "l", `{}`)
		recorder := doRequest(router, http.MethodPost, "/v1/net-policies", clean+" \t\r\n  ")
		if recorder.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201: %s", recorder.Code, recorder.Body.String())
		}
		want := wantRecord(t, clean, 1, false)
		if got := decodeRecord(t, recorder.Body.Bytes()); !reflect.DeepEqual(got, want) {
			t.Fatalf("record = %v, want %v", got, want)
		}
		items := listItems(t, router, "/v1/net-policies?namespace=n")
		if len(items) != 1 || !reflect.DeepEqual(items[0], want) {
			t.Fatalf("items = %v, want %v", items, want)
		}
	})

	complete := policyBody("n", "a", "l", `{"mode":"enforce"}`)
	cases := map[string]string{
		"second json object":       complete + " {}",
		"second json scalar":       complete + " 1",
		"second json null":         complete + " null",
		"plain garbage":            complete + " oops",
		"garbage after whitespace": complete + "   x",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			recorder := doRequest(router, http.MethodPost, "/v1/net-policies", body)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body.String())
			}
			assertExactErrorShape(t, recorder, "InvalidNetPolicyInputError")
			assertSafeErrorMessage(t, recorder)

			miss := doRequest(router, http.MethodGet, "/v1/net-policies?namespace=n", "")
			if miss.Code != http.StatusNotFound {
				t.Fatalf("namespace query status = %d, want 404", miss.Code)
			}
			assertErrorCode(t, miss, "NetPolicyNotFoundError")
			registerCreated(t, router, policyBody("n", "ok", "l", `{}`), 1, false)
		})
	}
}

// Segmentation must not change pluginParams validation. An illegal member value
// split across the chunk boundary stays illegal even when a later legal string
// with the same decoded member name follows; all-string duplicates keep the
// last value; member names are matched after JSON unescaping; and an illegal
// chunked retry against an existing identity is 400 (never 200 or 409) and
// leaves the committed record, its order and its conflict flag untouched.
func TestChunkedPluginParamsValidationAcrossBoundaries(t *testing.T) {
	t.Run("illegal value split across boundary rejected on new identity", func(t *testing.T) {
		params := `{"mode":null,"mode":"enforce"}`
		body := policyBody("payments", "chunk-null", "tier=backend", params)
		cases := map[string]int{
			"inside the null token":   mustCutAt(t, body, `null`, 2),
			"between the two members": mustCutAt(t, body, `,"mode":`, 1),
			"inside the legal string": mustCutAt(t, body, `"enforce"`, 4),
			"after null before comma": mustCutAt(t, body, `null`, 4),
		}
		for name, cut := range cases {
			t.Run(name, func(t *testing.T) {
				server, _ := newConcurrentTestServer(t)
				status, raw := postInChunks(t, server, body, cut)
				assertExactErrorBytes(t, status, raw, http.StatusBadRequest, "InvalidNetPolicyInputError")
				for _, target := range []string{
					"/v1/net-policies?namespace=payments",
					"/v1/net-policies?label=tier%3Dbackend",
				} {
					st, miss, err := clientRequest(http.DefaultClient, http.MethodGet, server.URL+target, "")
					if err != nil {
						t.Fatalf("GET %s: %v", target, err)
					}
					assertExactErrorBytes(t, st, miss, http.StatusNotFound, "NetPolicyNotFoundError")
				}
				// The rejected chunked request must not consume an order.
				postExpectCreated(t, server,
					policyBody("payments", "chunk-null", "tier=backend", `{"mode":"enforce"}`), 1, false)
			})
		}
	})

	t.Run("null token alone split mid token", func(t *testing.T) {
		server, _ := newConcurrentTestServer(t)
		body := policyBody("payments", "chunk-null2", "tier=backend", `{"mode":null}`)
		cut := mustCutAt(t, body, `null`, 2)
		status, raw := postInChunks(t, server, body, cut)
		assertExactErrorBytes(t, status, raw, http.StatusBadRequest, "InvalidNetPolicyInputError")
		postExpectCreated(t, server,
			policyBody("payments", "chunk-null2", "tier=backend", `{}`), 1, false)
	})

	t.Run("all string duplicates split still take last value", func(t *testing.T) {
		body := policyBody("payments", "chunk-dup", "tier=backend",
			`{"mode":"audit","mode":"enforce"}`)
		for name, cut := range map[string]int{
			"between the occurrences": mustCutAt(t, body, `,"mode":`, 1),
			"inside first value":      mustCutAt(t, body, `"audit"`, 3),
			"inside second value":     mustCutAt(t, body, `"enforce"`, 3),
		} {
			t.Run(name, func(t *testing.T) {
				// A fresh server per cut so every split is a first registration.
				server, _ := newConcurrentTestServer(t)
				status, raw := postInChunks(t, server, body, cut)
				if status != http.StatusCreated {
					t.Fatalf("status = %d, want 201: %s", status, string(raw))
				}
				got := decodeRecord(t, raw)
				if !reflect.DeepEqual(got["pluginParams"], map[string]any{"mode": "enforce"}) {
					t.Fatalf("pluginParams = %v, want last value {mode:enforce}", got["pluginParams"])
				}
				items := clientListItems(t, server, "/v1/net-policies?namespace=payments")
				if len(items) != 1 || !reflect.DeepEqual(items[0]["pluginParams"], map[string]any{"mode": "enforce"}) {
					t.Fatalf("stored items = %v, want one record with last-value params", items)
				}
			})
		}
	})

	t.Run("escaped member name split still recognized", func(t *testing.T) {
		// The member name is written with a JSON escape for 'm' (the raw text
		// backslash-u-0-0-6-d-o-d-e); names match after JSON decoding, so the
		// escape split across the chunk boundary is still the member "mode" and
		// keeps its legal string value.
		body := policyBody("payments", "chunk-escaped", "tier=backend",
			"{\"\\u006dode\":\"enforce\"}")
		escapedName := "\\u006dode"
		for name, cut := range map[string]int{
			"right after backslash":   mustCutAt(t, body, escapedName, 1),
			"right after backslash-u": mustCutAt(t, body, escapedName, 2),
			"inside the hex digits":   mustCutAt(t, body, escapedName, 4),
		} {
			t.Run(name, func(t *testing.T) {
				// A fresh server per cut so every split is a first registration.
				server, _ := newConcurrentTestServer(t)
				status, raw := postInChunks(t, server, body, cut)
				if status != http.StatusCreated {
					t.Fatalf("status = %d, want 201: %s", status, string(raw))
				}
				got := decodeRecord(t, raw)
				if !reflect.DeepEqual(got["pluginParams"], map[string]any{"mode": "enforce"}) {
					t.Fatalf("pluginParams = %v, want decoded-name {mode:enforce}", got["pluginParams"])
				}
			})
		}
	})

	t.Run("illegal chunked retry against existing identity changes nothing", func(t *testing.T) {
		server, _ := newConcurrentTestServer(t)
		// A clash first so the target record genuinely carries conflict=true.
		postExpectCreated(t, server, policyWithRules("payments", "chunk-clash", "tier=backend",
			`[{"direction":"ingress","action":"deny","ports":[80,80]}]`, `{}`), 1, false)
		seed := postExpectCreated(t, server,
			policyBody("payments", "chunk-existing", "tier=backend", `{"mode":"enforce"}`), 2, true)

		bad := policyBody("payments", "chunk-existing", "tier=backend",
			`{"mode":null,"mode":"enforce"}`)
		cut := mustCutAt(t, bad, `,"mode":`, 1)
		status, raw := postInChunks(t, server, bad, cut)
		assertExactErrorBytes(t, status, raw, http.StatusBadRequest, "InvalidNetPolicyInputError")

		items := clientListItems(t, server, "/v1/net-policies?namespace=payments")
		if len(items) != 2 {
			t.Fatalf("items = %v, want the two original records", items)
		}
		var original map[string]any
		for _, item := range items {
			if item["name"] == "chunk-existing" {
				original = item
			}
		}
		if !reflect.DeepEqual(original, seed) {
			t.Fatalf("record changed after rejected chunked retry:\n got %v\nwant %v", original, seed)
		}

		// A completed different-content retry still conflicts, and a fresh
		// identity continues at order 3.
		st, conflict, err := clientRequest(http.DefaultClient, http.MethodPost, server.URL+"/v1/net-policies",
			policyBody("payments", "chunk-existing", "tier=backend", `{"mode":"audit"}`))
		if err != nil {
			t.Fatalf("conflict post: %v", err)
		}
		assertExactErrorBytes(t, st, conflict, http.StatusConflict, "NetPolicyConflictError")
		// Egress cannot clash with the ingress deny seed, so this cleanly takes
		// the unconsumed order 3 with conflict=false.
		postExpectCreated(t, server,
			singleRuleBody("payments", "chunk-after", "tier=backend",
				"egress", "allow", 53, 53, `{}`), 3, false)
	})
}

// --- Held-request visibility over a genuinely open TCP connection ---

// heldPOST is an HTTP/1.1 request whose headers and an initial prefix have been
// written but whose body is deliberately left unfinished. The caller decides
// when (and whether) the rest of the body arrives.
type heldPOST struct {
	conn net.Conn
	br   *bufio.Reader
}

func startHeldPOST(t *testing.T, server *httptest.Server, prefix string, contentLength int) *heldPOST {
	t.Helper()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	var head strings.Builder
	_, _ = io.WriteString(&head, "POST /v1/net-policies HTTP/1.1\r\n")
	_, _ = fmt.Fprintf(&head, "Host: %s\r\n", u.Host)
	_, _ = io.WriteString(&head, "Content-Type: application/json\r\n")
	_, _ = fmt.Fprintf(&head, "Content-Length: %d\r\n", contentLength)
	_, _ = io.WriteString(&head, "Connection: close\r\n\r\n")
	if _, err := conn.Write([]byte(head.String())); err != nil {
		t.Fatalf("write headers: %v", err)
	}
	if _, err := conn.Write([]byte(prefix)); err != nil {
		t.Fatalf("write prefix: %v", err)
	}
	return &heldPOST{conn: conn, br: bufio.NewReader(conn)}
}

// finish sends the remaining bytes and reads the complete HTTP response.
func (h *heldPOST) finish(t *testing.T, suffix string) (int, []byte) {
	t.Helper()
	if _, err := io.WriteString(h.conn, suffix); err != nil {
		t.Fatalf("write suffix: %v", err)
	}
	return h.readResponse(t)
}

// failRead closes the write side of the connection with bytes still missing
// from the advertised Content-Length: the server's next body read fails with a
// non-EOF "unexpected EOF" while the read side stays open for the response.
func (h *heldPOST) failRead(t *testing.T) (int, []byte) {
	t.Helper()
	tcp, ok := h.conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("held connection is not TCP: %T", h.conn)
	}
	if err := tcp.CloseWrite(); err != nil {
		t.Fatalf("close write: %v", err)
	}
	return h.readResponse(t)
}

func (h *heldPOST) readResponse(t *testing.T) (int, []byte) {
	t.Helper()
	resp, err := http.ReadResponse(h.br, nil)
	if err != nil {
		t.Fatalf("read held response: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read held response body: %v", err)
	}
	return resp.StatusCode, raw
}

func (h *heldPOST) close() { _ = h.conn.Close() }

// splitFinalBrace splits a body ending in '}' (plus optional trailing
// whitespace) into prefix (everything up to but excluding the final top-level
// '}') and suffix (the '}' plus any trailing whitespace), so a held normal
// completion restores the exact original bytes.
func splitFinalBrace(body string) (prefix, suffix string) {
	trimmed := strings.TrimRight(body, " \t\r\n")
	closeIndex := len(trimmed) - 1
	if trimmed[closeIndex] != '}' {
		panic("body does not end with '}'")
	}
	return body[:closeIndex], body[closeIndex:]
}

// settleWhileOpen gives the server time to consume the delivered prefix and
// park on the unread rest of the body. The visibility assertions that follow
// are valid at every instant of this window (before consumption the candidate
// obviously does not exist; after consumption the handler is parked without
// having registered anything), so they are simply repeated across the window.
func settleWhileOpen(t *testing.T, check func()) {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		check()
		time.Sleep(25 * time.Millisecond)
	}
}

// While a brand-new identity's body is open with the complete object already
// delivered, queries see only previously committed records. The candidate
// appears only after the body ends normally; appending non-whitespace junk or
// failing the trailing read keeps it invisible forever and returns 400.
func TestChunkedBodyCandidateInvisibleUntilNormalEnd(t *testing.T) {
	server, _ := newConcurrentTestServer(t)
	client := &http.Client{Timeout: clientTimeout}

	// Two committed records in the same namespace, each with its own label.
	priorA := singleRuleBody("hold", "prior-a", "l-prior-a", "egress", "allow", 53, 53, `{}`)
	priorB := singleRuleBody("hold", "prior-b", "l-prior-b", "egress", "allow", 53, 53, `{}`)
	postExpectCreated(t, server, priorA, 1, false)
	postExpectCreated(t, server, priorB, 2, false)
	priors := []map[string]any{
		wantRecord(t, priorA, 1, false),
		wantRecord(t, priorB, 2, false),
	}

	candidateBody := singleRuleBody("hold", "candidate", "l-candidate",
		"egress", "allow", 53, 53, `{}`)
	candidateWant := wantRecord(t, candidateBody, 3, false)

	assertOnlyPriors := func() {
		t.Helper()
		items := clientListItems(t, server, "/v1/net-policies?namespace=hold")
		if !reflect.DeepEqual(items, priors) {
			t.Fatalf("namespace items while body open = %v, want only prior records %v", items, priors)
		}
		status, raw, err := clientRequest(client, http.MethodGet,
			server.URL+"/v1/net-policies?label=l-candidate", "")
		if err != nil {
			t.Fatalf("candidate label query: %v", err)
		}
		assertExactErrorBytes(t, status, raw, http.StatusNotFound, "NetPolicyNotFoundError")
	}

	// 1) Complete object held open, then normal end: 201, visible only after.
	prefix, suffix := splitFinalBrace(candidateBody)
	held := startHeldPOST(t, server, prefix, len(candidateBody))
	settleWhileOpen(t, assertOnlyPriors)
	status, raw := held.finish(t, suffix)
	if status != http.StatusCreated {
		t.Fatalf("normal completion status = %d, want 201: %s", status, string(raw))
	}
	if got := decodeRecord(t, raw); !reflect.DeepEqual(got, candidateWant) {
		t.Fatalf("candidate = %v, want %v", got, candidateWant)
	}
	held.close()

	committed := append(append([]map[string]any{}, priors...), candidateWant)
	if items := clientListItems(t, server, "/v1/net-policies?namespace=hold"); !reflect.DeepEqual(items, committed) {
		t.Fatalf("items after normal end = %v, want %v", items, committed)
	}

	// 2) A second new identity: complete object held, then non-whitespace junk.
	garbageBody := singleRuleBody("hold", "candidate-junk", "l-junk",
		"egress", "allow", 53, 53, `{}`)
	obj := strings.TrimRight(garbageBody, " \t\r\n")
	held = startHeldPOST(t, server, obj, len(obj)+2)
	settleWhileOpen(t, func() {
		items := clientListItems(t, server, "/v1/net-policies?namespace=hold")
		if !reflect.DeepEqual(items, committed) {
			t.Fatalf("namespace items while junk pending = %v, want %v", items, committed)
		}
		status, raw, err := clientRequest(client, http.MethodGet,
			server.URL+"/v1/net-policies?label=l-junk", "")
		if err != nil {
			t.Fatalf("junk label query: %v", err)
		}
		assertExactErrorBytes(t, status, raw, http.StatusNotFound, "NetPolicyNotFoundError")
	})
	status, raw = held.finish(t, " x")
	assertExactErrorBytes(t, status, raw, http.StatusBadRequest, "InvalidNetPolicyInputError")
	held.close()
	if items := clientListItems(t, server, "/v1/net-policies?namespace=hold"); !reflect.DeepEqual(items, committed) {
		t.Fatalf("items after junk = %v, want unchanged %v", items, committed)
	}

	// 3) A third new identity: complete object held, then the connection fails
	// with bytes still missing from Content-Length: same 400, stays invisible.
	failedBody := singleRuleBody("hold", "candidate-failed", "l-failed",
		"egress", "allow", 53, 53, `{}`)
	obj = strings.TrimRight(failedBody, " \t\r\n")
	held = startHeldPOST(t, server, obj, len(obj)+5)
	settleWhileOpen(t, func() {
		items := clientListItems(t, server, "/v1/net-policies?namespace=hold")
		if !reflect.DeepEqual(items, committed) {
			t.Fatalf("namespace items while read failure pending = %v, want %v", items, committed)
		}
		status, raw, err := clientRequest(client, http.MethodGet,
			server.URL+"/v1/net-policies?label=l-failed", "")
		if err != nil {
			t.Fatalf("failed label query: %v", err)
		}
		assertExactErrorBytes(t, status, raw, http.StatusNotFound, "NetPolicyNotFoundError")
	})
	status, raw = held.failRead(t)
	assertExactErrorBytes(t, status, raw, http.StatusBadRequest, "InvalidNetPolicyInputError")
	held.close()
	if items := clientListItems(t, server, "/v1/net-policies?namespace=hold"); !reflect.DeepEqual(items, committed) {
		t.Fatalf("items after read failure = %v, want unchanged %v", items, committed)
	}
}

// Failed requests against an existing identity — trailing junk after an
// otherwise identical object, trailing junk after a would-be conflicting
// object, or a failed trailing read — return 400 (never 200 or 409), neither
// write nor overwrite nor reorder anything, and the next legal registration
// takes the next sequence. The read-only contract is anchored afterwards:
// namespace/label/intersection listings carry complete fields ascending, a
// filter with no hit is 404, a completed different-content retry is 409 and
// GET /healthz keeps its healthy shape.
func TestChunkedBodyFailedHeldRequestsLeaveCommittedStateAndAnchors(t *testing.T) {
	server, _ := newConcurrentTestServer(t)
	client := &http.Client{Timeout: clientTimeout}

	// deny at 80 first so the existing allow-at-80 record carries conflict=true.
	denyBody := singleRuleBody("hold", "existing-deny", "l-existing",
		"ingress", "deny", 80, 80, `{}`)
	existingBody := singleRuleBody("hold", "existing", "l-existing",
		"ingress", "allow", 80, 80, `{"mode":"enforce"}`)
	postExpectCreated(t, server, denyBody, 1, false)
	existing := postExpectCreated(t, server, existingBody, 2, true)
	priorA := postExpectCreated(t, server,
		singleRuleBody("hold", "prior-a", "l-prior-a", "egress", "allow", 53, 53, `{}`), 3, false)
	candidate := postExpectCreated(t, server,
		singleRuleBody("hold", "candidate", "l-candidate", "egress", "allow", 53, 53, `{}`), 4, false)

	committed := []map[string]any{
		wantRecord(t, denyBody, 1, false),
		existing,
		priorA,
		candidate,
	}

	assertExistingUntouched := func(stage string) {
		t.Helper()
		items := clientListItems(t, server, "/v1/net-policies?namespace=hold")
		if !reflect.DeepEqual(items, committed) {
			t.Fatalf("%s: items = %v, want unchanged %v", stage, items, committed)
		}
		var got map[string]any
		for _, item := range items {
			if item["name"] == "existing" {
				got = item
			}
		}
		if !reflect.DeepEqual(got, existing) {
			t.Fatalf("%s: existing record = %v, want untouched %v", stage, got, existing)
		}
	}

	// 1) Identical content, complete object held, then junk: 400, untouched.
	obj := strings.TrimRight(existingBody, " \t\r\n")
	held := startHeldPOST(t, server, obj, len(obj)+2)
	settleWhileOpen(t, func() { assertExistingUntouched("while identical+junk held open") })
	status, raw := held.finish(t, " x")
	assertExactErrorBytes(t, status, raw, http.StatusBadRequest, "InvalidNetPolicyInputError")
	held.close()
	assertExistingUntouched("after identical+junk rejected")

	// 2) Different content (would be 409 if completed), complete object held,
	// then junk: malformed input wins — 400, not 409 — and nothing changes.
	changedBody := singleRuleBody("hold", "existing", "l-existing",
		"ingress", "allow", 80, 80, `{"mode":"audit"}`)
	obj = strings.TrimRight(changedBody, " \t\r\n")
	held = startHeldPOST(t, server, obj, len(obj)+2)
	settleWhileOpen(t, func() { assertExistingUntouched("while changed+junk held open") })
	status, raw = held.finish(t, " x")
	assertExactErrorBytes(t, status, raw, http.StatusBadRequest, "InvalidNetPolicyInputError")
	held.close()
	assertExistingUntouched("after changed+junk rejected")

	// 3) Identical content, complete object held, then trailing read fails:
	// 400 and the record keeps its order 2 and conflict=true.
	obj = strings.TrimRight(existingBody, " \t\r\n")
	held = startHeldPOST(t, server, obj, len(obj)+5)
	settleWhileOpen(t, func() { assertExistingUntouched("while identical+read-failure held open") })
	status, raw = held.failRead(t)
	assertExactErrorBytes(t, status, raw, http.StatusBadRequest, "InvalidNetPolicyInputError")
	held.close()
	assertExistingUntouched("after trailing read failure")

	// The failed requests consumed no order: a brand-new legal policy takes 5.
	final := postExpectCreated(t, server,
		singleRuleBody("hold", "after-failures", "l-final", "egress", "allow", 53, 53, `{}`), 5, false)
	committed = append(committed, final)

	// Read-only anchors: complete fields, ascending order, every filter shape.
	if items := clientListItems(t, server, "/v1/net-policies?namespace=hold"); !reflect.DeepEqual(items, committed) {
		t.Fatalf("namespace items = %v, want %v", items, committed)
	}
	if items := clientListItems(t, server, "/v1/net-policies?label=l-candidate"); !reflect.DeepEqual(
		items, []map[string]any{candidate}) {
		t.Fatalf("label items = %v, want exactly the candidate record", items)
	}
	if items := clientListItems(t, server, "/v1/net-policies?namespace=hold&label=l-existing"); !reflect.DeepEqual(
		items, []map[string]any{committed[0], existing}) {
		t.Fatalf("intersection items = %v, want the deny seed and the existing record ascending", items)
	}

	// No hit keeps 404 NetPolicyNotFoundError.
	st, miss, err := clientRequest(client, http.MethodGet, server.URL+"/v1/net-policies?label=l-missing", "")
	if err != nil {
		t.Fatalf("missing-label GET: %v", err)
	}
	assertExactErrorBytes(t, st, miss, http.StatusNotFound, "NetPolicyNotFoundError")

	// A completed different-content retry is still 409.
	st, conflict, err := clientRequest(client, http.MethodPost, server.URL+"/v1/net-policies", changedBody)
	if err != nil {
		t.Fatalf("changed-content POST: %v", err)
	}
	assertExactErrorBytes(t, st, conflict, http.StatusConflict, "NetPolicyConflictError")
	// The 409 also consumed no order: the registry is unchanged.
	if items := clientListItems(t, server, "/v1/net-policies?namespace=hold"); !reflect.DeepEqual(items, committed) {
		t.Fatalf("items after 409 = %v, want unchanged %v", items, committed)
	}

	// The health convention keeps its published healthy shape.
	hstatus, hraw, err := clientRequest(client, http.MethodGet, server.URL+"/healthz", "")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	if hstatus != http.StatusOK || string(hraw) != `{"database":"ok","status":"ok"}` {
		t.Fatalf("healthz = %d %s, want 200 ok", hstatus, string(hraw))
	}
}
