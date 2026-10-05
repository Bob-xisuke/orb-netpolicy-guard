package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/Bob-xisuke/orb-netpolicy-guard/internal/store"
)

// Error codes published by the service contract in README.md.
const (
	codeInvalidInput = "InvalidNetPolicyInputError"
	codeConflict     = "NetPolicyConflictError"
	codeNotFound     = "NetPolicyNotFoundError"
	codeStorage      = "storage_unavailable"
)

// NewRouter wires the public HTTP surface. The service contract in README.md
// describes the error shape every entry must keep.
func NewRouter(st *store.Store) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	router.GET("/healthz", func(c *gin.Context) {
		if err := st.Ping(); err != nil {
			writeError(c, http.StatusServiceUnavailable, codeStorage, "database is not available")
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok", "database": "ok"})
	})

	router.POST("/v1/net-policies", func(c *gin.Context) {
		rec, ok := decodeNetPolicy(c.Request.Body)
		if !ok {
			writeError(c, http.StatusBadRequest, codeInvalidInput, "request body is not a valid net policy")
			return
		}
		stored, created, err := st.Register(rec)
		if errors.Is(err, store.ErrConflict) {
			writeError(c, http.StatusConflict, codeConflict, "a different net policy already exists for this namespace and name")
			return
		}
		if err != nil {
			writeError(c, http.StatusServiceUnavailable, codeStorage, "database is not available")
			return
		}
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		c.JSON(status, stored)
	})

	router.GET("/v1/net-policies", func(c *gin.Context) {
		filters, err := parseNetPolicyQuery(c.Request.URL.RawQuery)
		if err != nil {
			writeError(c, http.StatusBadRequest, codeInvalidInput, "query parameters are not valid")
			return
		}
		records, err := st.List(filters.namespace, filters.label)
		if err != nil {
			writeError(c, http.StatusServiceUnavailable, codeStorage, "database is not available")
			return
		}
		if len(records) == 0 {
			writeError(c, http.StatusNotFound, codeNotFound, "no net policies match the query")
			return
		}
		c.JSON(http.StatusOK, gin.H{"items": records})
	})

	router.NoRoute(func(c *gin.Context) {
		writeError(c, http.StatusNotFound, "route_not_found", "no route matches this path")
	})
	return router
}

func writeError(c *gin.Context, status int, code, message string) {
	c.JSON(status, gin.H{"error": gin.H{"code": code, "message": message}})
}

// netPolicyQueryFilters are the decoded query conditions the list endpoint
// accepts; an empty string means the condition was not supplied.
type netPolicyQueryFilters struct {
	namespace string
	label     string
}

// parseNetPolicyQuery validates the whole raw query before any record is read.
//
// Every fragment must decode cleanly: an incomplete or non-hex percent escape,
// or a literal (unescaped) semicolon in any fragment — including fragments for
// unknown parameters — invalidates the entire request rather than being
// dropped. Validation precedes storage access, so an invalid query never
// returns the records its surviving fragments would match.
//
// Once decoding succeeds, unknown parameters are ignored. The known parameters
// namespace and label must each appear at most once under their decoded name
// (namespace and %6Eamespace are the same parameter), must not be empty or
// whitespace-only, and at least one of the two must be present. Decoding
// happens exactly once and values are matched verbatim afterwards: "+" is a
// space while %2B, %3B and %26 arrive as literal "+", ";" and "&", with no
// trimming or case folding. Empty fragments and a trailing "&" carry no
// meaning and stay legal.
func parseNetPolicyQuery(rawQuery string) (netPolicyQueryFilters, error) {
	var filters netPolicyQueryFilters
	if rawQuery == "" {
		return filters, errInvalidQuery
	}

	// ParseQuery surfaces malformed escapes and literal semicolons as an error
	// even though it also returns the fragments decoded so far; the partial
	// result must never be used to answer the request.
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return netPolicyQueryFilters{}, errInvalidQuery
	}

	for key, decoded := range values {
		switch key {
		case "namespace", "label":
			// Identical repeated values are still a repeat, and an empty value
			// shows up as an empty-string entry, so both cases fail here.
			if len(decoded) != 1 || strings.TrimSpace(decoded[0]) == "" {
				return netPolicyQueryFilters{}, errInvalidQuery
			}
		default:
			// Unknown parameters are accepted after decoding, their values
			// (including empty ones) ignored.
			continue
		}
		if key == "namespace" {
			filters.namespace = decoded[0]
		} else {
			filters.label = decoded[0]
		}
	}

	if filters.namespace == "" && filters.label == "" {
		return netPolicyQueryFilters{}, errInvalidQuery
	}
	return filters, nil
}

var errInvalidQuery = errors.New("invalid net policy query")

// decodeNetPolicy strictly validates the request body: a single JSON object with
// the required fields, enums, and port intervals from the service contract.
func decodeNetPolicy(body io.Reader) (store.Record, bool) {
	var raw map[string]json.RawMessage
	decoder := json.NewDecoder(body)
	if err := decoder.Decode(&raw); err != nil {
		return store.Record{}, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return store.Record{}, false
	}

	var rec store.Record
	var ok bool
	if rec.Namespace, ok = requiredString(raw, "namespace"); !ok {
		return store.Record{}, false
	}
	if rec.Name, ok = requiredString(raw, "name"); !ok {
		return store.Record{}, false
	}
	if rec.Label, ok = requiredString(raw, "label"); !ok {
		return store.Record{}, false
	}
	if rec.Rules, ok = decodeRules(raw); !ok {
		return store.Record{}, false
	}
	if rec.PluginParams, ok = decodePluginParams(raw); !ok {
		return store.Record{}, false
	}
	return rec, true
}

// requiredString reads a present, non-blank JSON string field.
func requiredString(raw map[string]json.RawMessage, key string) (string, bool) {
	blob, present := raw[key]
	if !present {
		return "", false
	}
	var value string
	if err := json.Unmarshal(blob, &value); err != nil {
		return "", false
	}
	if strings.TrimSpace(value) == "" {
		return "", false
	}
	return value, true
}

func decodeRules(raw map[string]json.RawMessage) ([]store.Rule, bool) {
	blob, present := raw["rules"]
	if !present {
		return nil, false
	}
	var items []json.RawMessage
	if err := json.Unmarshal(blob, &items); err != nil || len(items) == 0 {
		return nil, false
	}
	rules := make([]store.Rule, 0, len(items))
	for _, item := range items {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(item, &fields); err != nil {
			return nil, false
		}
		direction, ok := requiredEnum(fields, "direction", "ingress", "egress")
		if !ok {
			return nil, false
		}
		action, ok := requiredEnum(fields, "action", "allow", "deny")
		if !ok {
			return nil, false
		}
		portsBlob, present := fields["ports"]
		if !present {
			return nil, false
		}
		var ports []int
		if err := json.Unmarshal(portsBlob, &ports); err != nil || len(ports) != 2 {
			return nil, false
		}
		if ports[0] < 1 || ports[0] > 65535 || ports[1] < 1 || ports[1] > 65535 || ports[0] > ports[1] {
			return nil, false
		}
		rules = append(rules, store.Rule{Direction: direction, Action: action, Ports: [2]int{ports[0], ports[1]}})
	}
	return rules, true
}

// requiredEnum reads a present JSON string field restricted to the given values.
func requiredEnum(raw map[string]json.RawMessage, key string, allowed ...string) (string, bool) {
	blob, present := raw[key]
	if !present {
		return "", false
	}
	var value string
	if err := json.Unmarshal(blob, &value); err != nil {
		return "", false
	}
	for _, candidate := range allowed {
		if value == candidate {
			return value, true
		}
	}
	return "", false
}

// decodePluginParams validates and decodes the pluginParams object. The published
// contract is a string-to-string object: null, numbers, booleans, arrays and
// nested objects are invalid input rather than coerced or dropped.
//
// Members are walked with a streaming decoder so every occurrence of a repeated
// member name is inspected, not just the value a map decode would keep last.
// {"mode":null,"mode":"enforce"} must fail on the null even though a legal
// string follows it; keys are matched after JSON unescaping, so "mode" and
// "mode" are the same member. When every occurrence is a string the last
// value for each decoded key wins. Only a top-level object appearing once is
// accepted here; other fields keep their existing parsing behaviour.
func decodePluginParams(raw map[string]json.RawMessage) (map[string]string, bool) {
	blob, present := raw["pluginParams"]
	if !present {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(blob))
	opening, err := decoder.Token()
	if err != nil {
		return nil, false
	}
	delim, ok := opening.(json.Delim)
	if !ok || delim != '{' {
		// Rejects null, scalars and arrays outright.
		return nil, false
	}

	params := map[string]string{}
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, false
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, false
		}
		valueToken, err := decoder.Token()
		if err != nil {
			return nil, false
		}
		value, ok := valueToken.(string)
		if !ok {
			return nil, false
		}
		params[key] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, false
	}

	// The RawMessage must contain exactly the object and nothing trailing.
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, false
	}
	return params, true
}
