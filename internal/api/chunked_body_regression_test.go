package api

// Segmented body regression tests: the same legal request must behave
// identically whether its body arrives as one piece or split at arbitrary byte
// boundaries — including splits inside a UTF-8 multibyte character, a JSON
// \uXXXX escape, a port number or a pluginParams member. Bodies that end
// before the JSON closes, fail with a non-EOF read error, or carry data after
// the complete object are invalid input and must leave no trace: no record, no
// order consumed, existing records untouched in every field, order and
// conflict flag. A candidate record becomes visible to queries only once its
// request body has ended cleanly. Every expectation is derived from the public
// contract in README.md, never from observed service output.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// The shared fixture pair: a seed (deny [8080,9090]) and a target (allow
// [9000,65535]) whose closed port intervals overlap, so the target commits
// with order 2 and conflict=true whenever the seed is present. The target
// carries a multibyte character in its name and label, a \uXXXX escape in a
// pluginParams value and multi-digit ports, giving the split points below
// somewhere interesting to land.
const chunkedSeedBody = `{
	"namespace": "payments",
	"name": "seed-deny",
	"label": "tier=后端",
	"rules": [{"direction": "ingress", "action": "deny", "ports": [8080, 9090]}],
	"pluginParams": {"mode": "enforce"}
}`

const chunkedTargetBody = `{
	"namespace": "payments",
	"name": "chunked-策略",
	"label": "tier=后端",
	"rules": [{"direction": "ingress", "action": "allow", "ports": [9000, 65535]}],
	"pluginParams": {"mode": "audit", "zone": "华\u5317", "retries": "3"}
}`

// gatedQueries returns both single-condition queries and their intersection
// for the shared fixture identity; the candidate shares namespace and label
// with the seed, so these are exactly the queries that would expose it.
var gatedQueries = []string{
	"/v1/net-policies?namespace=payments",
	"/v1/net-policies?label=" + url.QueryEscape("tier=后端"),
	"/v1/net-policies?namespace=payments&label=" + url.QueryEscape("tier=后端"),
}

// errBodyRead simulates a non-EOF transport failure while the request body is
// being read.
var errBodyRead = errors.New("simulated transport failure")

// chunkedReader yields the body one piece per Read call, so a test controls
// exactly where the request body is segmented on the wire.
type chunkedReader struct {
	chunks []string
	off    int
}

func (r *chunkedReader) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[0][r.off:])
	r.off += n
	if r.off == len(r.chunks[0]) {
		r.chunks = r.chunks[1:]
		r.off = 0
	}
	return n, nil
}

// failingReader delivers data and then reports a non-EOF error instead of EOF,
// modelling a connection that breaks while the body is being read.
type failingReader struct {
	data []byte
	err  error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// gatedBody delivers prefix, signals delivered, then blocks until release is
// closed before producing the suffix (or err, or EOF when both are empty). It
// models a request whose complete JSON object has arrived while the body
// itself has not finished.
type gatedBody struct {
	prefix    []byte
	suffix    []byte
	err       error
	delivered chan struct{}
	release   chan struct{}
	once      sync.Once
}

func (g *gatedBody) Read(p []byte) (int, error) {
	if len(g.prefix) > 0 {
		n := copy(p, g.prefix)
		g.prefix = g.prefix[n:]
		if len(g.prefix) == 0 {
			g.once.Do(func() { close(g.delivered) })
		}
		return n, nil
	}
	<-g.release
	if g.err != nil {
		return 0, g.err
	}
	if len(g.suffix) > 0 {
		n := copy(p, g.suffix)
		g.suffix = g.suffix[n:]
		return n, nil
	}
	return 0, io.EOF
}

// splitBody cuts the body at the given ascending byte offsets. Offsets may
// split a UTF-8 character or a JSON escape: that is the point of the test.
func splitBody(t *testing.T, body string, offsets ...int) []string {
	t.Helper()
	parts := []string{}
	last := 0
	for _, off := range offsets {
		if off <= last || off >= len(body) {
			t.Fatalf("split offset %d out of range for body of %d bytes", off, len(body))
		}
		parts = append(parts, body[last:off])
		last = off
	}
	return append(parts, body[last:])
}

// chunksOf cuts the body into fixed-size byte pieces (size 1 puts every byte
// in its own chunk, splitting every multibyte character and escape).
func chunksOf(body string, size int) []string {
	var chunks []string
	for i := 0; i < len(body); i += size {
		end := i + size
		if end > len(body) {
			end = len(body)
		}
		chunks = append(chunks, body[i:end])
	}
	return chunks
}

// doReaderRequest posts a body produced by the given reader, bypassing the
// content-length special-casing httptest applies to known reader types so the
// handler genuinely consumes the reader.
func doReaderRequest(router http.Handler, body io.Reader) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/net-policies", nil)
	req.Body = io.NopCloser(body)
	req.ContentLength = -1
	router.ServeHTTP(recorder, req)
	return recorder
}

// waitClosed fails the test unless ch closes within the budget.
func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// assertInvalidBody checks the published 400 shape for a rejected request body.
func assertInvalidBody(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	assertExactErrorShape(t, recorder, "InvalidNetPolicyInputError")
	assertSafeErrorMessage(t, recorder)
}

// assertOnlyCommitted queries every fixture filter and demands exactly the
// given committed records, order ascending, fields complete.
func assertOnlyCommitted(t *testing.T, router *gin.Engine, want []map[string]any) {
	t.Helper()
	for _, target := range gatedQueries {
		if items := listItems(t, router, target); !reflect.DeepEqual(items, want) {
			t.Fatalf("GET %s items = %v, want %v", target, items, want)
		}
	}
}

// A legal request registered from a segmented body is indistinguishable from
// the same request registered whole: 201 with every submitted field preserved,
// the same order and conflict flag, a segmented same-content retry returning
// 200 with the original record without consuming a record or an order, a
// different-content retry returning 409, and queries exposing the records
// complete and ascending. Split points land inside a UTF-8 multibyte
// character, a JSON \uXXXX escape, a port number and pluginParams members.
func TestChunkedBodyRegistersIdenticallyToFullBody(t *testing.T) {
	// Control: the same legal request posted as one unbroken body.
	controlRouter, _ := newTestRouter(t)
	registerCreated(t, controlRouter, chunkedSeedBody, 1, false)
	control := registerCreated(t, controlRouter, chunkedTargetBody, 2, true)

	offset := func(marker string, plus int) int {
		idx := strings.Index(chunkedTargetBody, marker)
		if idx < 0 {
			t.Fatalf("marker %q not found in target body", marker)
		}
		return idx + plus
	}

	scenarios := []struct {
		name   string
		chunks []string
	}{
		{"split inside multibyte name character", splitBody(t, chunkedTargetBody, offset("策", 1))},
		{"split inside multibyte label character", splitBody(t, chunkedTargetBody, offset("后", 2))},
		{"split inside json escape", splitBody(t, chunkedTargetBody, offset(`\u5317`, 3))},
		{"split around json escape", splitBody(t, chunkedTargetBody, offset(`\u5317`, 2), offset(`\u5317`, 4))},
		{"split inside port number", splitBody(t, chunkedTargetBody, offset("65535", 2))},
		{"split inside plugin member name", splitBody(t, chunkedTargetBody, offset(`"mode"`, 3))},
		{"split inside plugin member value", splitBody(t, chunkedTargetBody, offset(`"audit"`, 3))},
		{"every byte its own chunk", chunksOf(chunkedTargetBody, 1)},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			seed := registerCreated(t, router, chunkedSeedBody, 1, false)

			recorder := doReaderRequest(router, &chunkedReader{chunks: sc.chunks})
			if recorder.Code != http.StatusCreated {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusCreated, recorder.Body.String())
			}
			var record map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &record); err != nil {
				t.Fatalf("decode record: %v", err)
			}
			if !reflect.DeepEqual(record, control) {
				t.Fatalf("chunked record = %v, want identical to full-body control %v", record, control)
			}

			// Same identity and content, segmented differently: an idempotent
			// retry returning the original record.
			retry := doReaderRequest(router, &chunkedReader{chunks: chunksOf(chunkedTargetBody, 7)})
			if retry.Code != http.StatusOK {
				t.Fatalf("retry status = %d, want %d: %s", retry.Code, http.StatusOK, retry.Body.String())
			}
			var retryRecord map[string]any
			if err := json.Unmarshal(retry.Body.Bytes(), &retryRecord); err != nil {
				t.Fatalf("decode retry: %v", err)
			}
			if !reflect.DeepEqual(retryRecord, record) {
				t.Fatalf("retry record = %v, want original %v", retryRecord, record)
			}

			// The retry added no record: both filters and their intersection
			// return exactly the seed and the target, complete and ascending.
			assertOnlyCommitted(t, router, []map[string]any{seed, record})

			// A different-content retry on the same identity stays a 409.
			changed := strings.Replace(chunkedTargetBody, `"audit"`, `"changed"`, 1)
			conflict := doReaderRequest(router, &chunkedReader{chunks: chunksOf(changed, 5)})
			if conflict.Code != http.StatusConflict {
				t.Fatalf("changed retry status = %d, want %d: %s",
					conflict.Code, http.StatusConflict, conflict.Body.String())
			}
			assertExactErrorShape(t, conflict, "NetPolicyConflictError")
			assertSafeErrorMessage(t, conflict)

			// Neither the retry nor the 409 consumed an order: the next
			// brand-new identity takes order 3.
			next := singleRuleBody("payments", "after-chunked", "tier=后端",
				"egress", "allow", 53, 53, `{}`)
			registerCreated(t, router, next, 3, false)

			// The health check contract is untouched.
			health := doRequest(router, http.MethodGet, "/healthz", "")
			if health.Code != http.StatusOK || health.Body.String() != `{"database":"ok","status":"ok"}` {
				t.Fatalf("healthz = %d %s, want 200 ok", health.Code, health.Body.String())
			}
		})
	}
}

// A segmented body that ends before the JSON closes — inside a field name,
// inside a string value, inside the rules array, or with every field complete
// but the top-level object unclosed — is invalid input: 400
// InvalidNetPolicyInputError, no record, no order consumed.
func TestChunkedBodyTruncatedBeforeClose(t *testing.T) {
	trimmed := strings.TrimSpace(chunkedTargetBody)
	cut := func(marker string, plus int) string {
		idx := strings.Index(chunkedTargetBody, marker)
		if idx < 0 {
			t.Fatalf("marker %q not found in target body", marker)
		}
		return chunkedTargetBody[:idx+plus]
	}
	cases := map[string]string{
		"field name not closed":       cut(`"namespace"`, 5),
		"string value not closed":     cut(`"payments"`, 5),
		"rules array not closed":      cut("[9000", 3),
		"top-level object not closed": trimmed[:len(trimmed)-1],
	}
	for name, partial := range cases {
		t.Run(name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			// The truncated body is itself delivered in two segments.
			recorder := doReaderRequest(router, &chunkedReader{
				chunks: splitBody(t, partial, len(partial)/2),
			})
			assertInvalidBody(t, recorder)

			// Nothing was committed: both filters stay 404.
			for _, target := range gatedQueries[:2] {
				miss := doRequest(router, http.MethodGet, target, "")
				if miss.Code != http.StatusNotFound {
					t.Fatalf("GET %s status = %d, want %d", target, miss.Code, http.StatusNotFound)
				}
				assertExactErrorShape(t, miss, "NetPolicyNotFoundError")
			}

			// The rejection consumed no order: the same request, properly
			// terminated, commits with order 1.
			registerCreated(t, router, chunkedTargetBody, 1, false)
		})
	}
}

// A non-EOF read failure while the body is being read is invalid input, both
// when the stream breaks mid-object and when the complete object has already
// arrived but the following read fails instead of reporting EOF.
func TestChunkedBodyReadError(t *testing.T) {
	cases := map[string]string{
		"read error mid body":              chunkedTargetBody[:len(chunkedTargetBody)/2],
		"read error after complete object": chunkedTargetBody,
	}
	for name, delivered := range cases {
		t.Run(name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			recorder := doReaderRequest(router, &failingReader{data: []byte(delivered), err: errBodyRead})
			assertInvalidBody(t, recorder)

			for _, target := range gatedQueries[:2] {
				miss := doRequest(router, http.MethodGet, target, "")
				if miss.Code != http.StatusNotFound {
					t.Fatalf("GET %s status = %d, want %d", target, miss.Code, http.StatusNotFound)
				}
				assertExactErrorShape(t, miss, "NetPolicyNotFoundError")
			}

			registerCreated(t, router, chunkedTargetBody, 1, false)
		})
	}
}

// JSON whitespace after the complete object is accepted; a second JSON value
// or any non-whitespace garbage after it is invalid input, even when the
// object and the tail arrive in separate segments.
func TestChunkedBodyTrailingData(t *testing.T) {
	t.Run("json whitespace after object accepted", func(t *testing.T) {
		router, _ := newTestRouter(t)
		recorder := doReaderRequest(router, &chunkedReader{
			chunks: []string{chunkedTargetBody, " \t\r\n  "},
		})
		if recorder.Code != http.StatusCreated {
			t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusCreated, recorder.Body.String())
		}
		var record map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &record); err != nil {
			t.Fatalf("decode record: %v", err)
		}
		if want := wantRecord(t, chunkedTargetBody, 1, false); !reflect.DeepEqual(record, want) {
			t.Fatalf("record = %v, want %v", record, want)
		}
		assertOnlyCommitted(t, router, []map[string]any{record})
	})

	rejected := map[string]string{
		"second json object":     ` {}`,
		"second json scalar":     ` null`,
		"non-whitespace garbage": ` x`,
		"comma after object":     `,`,
	}
	for name, tail := range rejected {
		t.Run(name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			recorder := doReaderRequest(router, &chunkedReader{
				chunks: []string{chunkedTargetBody, tail},
			})
			assertInvalidBody(t, recorder)

			for _, target := range gatedQueries[:2] {
				miss := doRequest(router, http.MethodGet, target, "")
				if miss.Code != http.StatusNotFound {
					t.Fatalf("GET %s status = %d, want %d", target, miss.Code, http.StatusNotFound)
				}
				assertExactErrorShape(t, miss, "NetPolicyNotFoundError")
			}

			registerCreated(t, router, chunkedTargetBody, 1, false)
		})
	}
}

// Segmentation must not change pluginParams validation: an illegal member
// value is not masked by a later same-name legal string, legal duplicate
// members still resolve to the last string value, and member names are
// recognized after JSON decoding — with chunk boundaries inside the
// pluginParams object itself.
func TestChunkedBodyPluginParamsValidation(t *testing.T) {
	t.Run("illegal member not masked by later legal string", func(t *testing.T) {
		router, _ := newTestRouter(t)
		body := singleRuleBody("payments", "chunked-pp", "tier=backend",
			"ingress", "allow", 80, 80, `{"mode": null, "mode": "enforce"}`)
		idx := strings.Index(body, "null")
		if idx < 0 {
			t.Fatalf("null member not found in %s", body)
		}
		recorder := doReaderRequest(router, &chunkedReader{
			chunks: splitBody(t, body, idx+2),
		})
		assertInvalidBody(t, recorder)

		miss := doRequest(router, http.MethodGet, "/v1/net-policies?namespace=payments", "")
		if miss.Code != http.StatusNotFound {
			t.Fatalf("GET status = %d, want %d", miss.Code, http.StatusNotFound)
		}
		assertExactErrorShape(t, miss, "NetPolicyNotFoundError")

		legal := singleRuleBody("payments", "chunked-pp", "tier=backend",
			"ingress", "allow", 80, 80, `{"mode": "enforce"}`)
		registerCreated(t, router, legal, 1, false)
	})

	t.Run("legal duplicate members last string wins", func(t *testing.T) {
		router, _ := newTestRouter(t)
		body := singleRuleBody("payments", "chunked-pp", "tier=backend",
			"ingress", "allow", 80, 80, `{"mode": "audit", "mode": "enforce"}`)
		recorder := doReaderRequest(router, &chunkedReader{chunks: chunksOf(body, 3)})
		if recorder.Code != http.StatusCreated {
			t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusCreated, recorder.Body.String())
		}
		var record map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &record); err != nil {
			t.Fatalf("decode record: %v", err)
		}
		if want := map[string]any{"mode": "enforce"}; !reflect.DeepEqual(record["pluginParams"], want) {
			t.Fatalf("pluginParams = %v, want %v (last string value)", record["pluginParams"], want)
		}
		items := listItems(t, router, "/v1/net-policies?namespace=payments")
		if len(items) != 1 || !reflect.DeepEqual(items[0], record) {
			t.Fatalf("items = %v, want exactly %v", items, record)
		}
	})

	t.Run("member name matched after json decoding", func(t *testing.T) {
		router, _ := newTestRouter(t)
		body := singleRuleBody("payments", "chunked-pp", "tier=backend",
			"ingress", "allow", 80, 80, `{"\u006dode": "enforce"}`)
		idx := strings.Index(body, `\u006d`)
		if idx < 0 {
			t.Fatalf("escaped member name not found in %s", body)
		}
		// The chunk boundary lands inside the \u006d escape itself.
		recorder := doReaderRequest(router, &chunkedReader{
			chunks: splitBody(t, body, idx+3),
		})
		if recorder.Code != http.StatusCreated {
			t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusCreated, recorder.Body.String())
		}
		var record map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &record); err != nil {
			t.Fatalf("decode record: %v", err)
		}
		if want := map[string]any{"mode": "enforce"}; !reflect.DeepEqual(record["pluginParams"], want) {
			t.Fatalf("pluginParams = %v, want %v (member name decoded before matching)", record["pluginParams"], want)
		}
	})
}

// Failed requests — truncated, read-failed, carrying trailing data, or with an
// illegal pluginParams occurrence whose final legal value matches the stored
// content — never overwrite an existing identity: always 400 (never 200 or
// 409), and the committed record keeps every field, its order and its
// conflict flag; the next legal registration continues the sequence.
func TestFailedChunkedRequestsLeaveExistingRecordUntouched(t *testing.T) {
	router, _ := newTestRouter(t)
	seed := registerCreated(t, router, chunkedSeedBody, 1, false)
	target := registerCreated(t, router, chunkedTargetBody, 2, true)

	trimmed := strings.TrimSpace(chunkedTargetBody)
	// Same identity and same final content as the committed target, but with
	// an illegal null occurrence of "mode" hidden before the legal value.
	hiddenIllegal := singleRuleBody("payments", "chunked-策略", "tier=后端",
		"ingress", "allow", 9000, 65535,
		`{"mode": null, "mode": "audit", "zone": "华北", "retries": "3"}`)

	failures := []struct {
		name string
		body io.Reader
	}{
		{"truncated before object close", &chunkedReader{
			chunks: splitBody(t, trimmed[:len(trimmed)-1], 10)}},
		{"read error after complete object", &failingReader{
			data: []byte(chunkedTargetBody), err: errBodyRead}},
		{"garbage after complete object", &chunkedReader{
			chunks: []string{chunkedTargetBody, " x"}}},
		{"second json value after object", &chunkedReader{
			chunks: []string{chunkedTargetBody, " {}"}}},
		{"illegal member hidden by stored value", &chunkedReader{
			chunks: chunksOf(hiddenIllegal, 12)}},
	}
	for _, failure := range failures {
		t.Run(failure.name, func(t *testing.T) {
			recorder := doReaderRequest(router, failure.body)
			assertInvalidBody(t, recorder)
		})
	}

	// Every failure left the registry exactly as the two commits made it.
	assertOnlyCommitted(t, router, []map[string]any{seed, target})

	// No failure consumed an order: the next legal policy takes order 3.
	next := singleRuleBody("payments", "after-failures", "tier=后端",
		"egress", "allow", 53, 53, `{}`)
	registerCreated(t, router, next, 3, false)
}

// A new-identity request whose complete object has arrived but whose body has
// not ended is invisible: queries see only previously committed records. Once
// the body ends cleanly the candidate commits and becomes visible; when the
// body instead gains an illegal tail or fails to read, the candidate stays
// invisible and consumes nothing.
func TestInflightRequestInvisibleUntilBodyCompletes(t *testing.T) {
	// startInflight seeds the fixture record, starts a POST of the target
	// body that blocks after the complete object has been delivered, proves
	// queries still see only the seed, then releases the body to finish with
	// the given suffix or read error.
	startInflight := func(t *testing.T, suffix string, readErr error) (*gin.Engine, map[string]any, *httptest.ResponseRecorder) {
		router, _ := newTestRouter(t)
		seed := registerCreated(t, router, chunkedSeedBody, 1, false)

		gate := &gatedBody{
			prefix:    []byte(chunkedTargetBody),
			suffix:    []byte(suffix),
			err:       readErr,
			delivered: make(chan struct{}),
			release:   make(chan struct{}),
		}
		recorder := httptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			defer close(done)
			req := httptest.NewRequest(http.MethodPost, "/v1/net-policies", nil)
			req.Body = io.NopCloser(gate)
			req.ContentLength = -1
			router.ServeHTTP(recorder, req)
		}()
		waitClosed(t, gate.delivered, "the handler to receive the complete object")

		// The complete object has arrived but the body has not ended: queries
		// see only the previously committed record.
		assertOnlyCommitted(t, router, []map[string]any{seed})

		close(gate.release)
		waitClosed(t, done, "the handler to finish")
		return router, seed, recorder
	}

	t.Run("clean end commits and becomes visible", func(t *testing.T) {
		router, seed, recorder := startInflight(t, "", nil)
		if recorder.Code != http.StatusCreated {
			t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusCreated, recorder.Body.String())
		}
		var record map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &record); err != nil {
			t.Fatalf("decode record: %v", err)
		}
		if want := wantRecord(t, chunkedTargetBody, 2, true); !reflect.DeepEqual(record, want) {
			t.Fatalf("record = %v, want %v", record, want)
		}
		assertOnlyCommitted(t, router, []map[string]any{seed, record})
	})

	t.Run("illegal trailing keeps candidate invisible", func(t *testing.T) {
		router, seed, recorder := startInflight(t, " {}", nil)
		assertInvalidBody(t, recorder)
		assertOnlyCommitted(t, router, []map[string]any{seed})

		// The candidate consumed nothing: the next legal policy takes order 2.
		next := singleRuleBody("payments", "after-gate", "tier=后端",
			"egress", "allow", 53, 53, `{}`)
		registerCreated(t, router, next, 2, false)
	})

	t.Run("read failure keeps candidate invisible", func(t *testing.T) {
		router, seed, recorder := startInflight(t, "", errBodyRead)
		assertInvalidBody(t, recorder)
		assertOnlyCommitted(t, router, []map[string]any{seed})

		next := singleRuleBody("payments", "after-gate", "tier=后端",
			"egress", "allow", 53, 53, `{}`)
		registerCreated(t, router, next, 2, false)
	})
}
