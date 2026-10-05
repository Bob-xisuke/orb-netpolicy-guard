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
		namespace, label, ok := parseNetPolicyQuery(c.Request.URL.RawQuery)
		if !ok {
			writeError(c, http.StatusBadRequest, codeInvalidInput, "query must be well-formed and carry a single non-blank namespace or label")
			return
		}
		records, err := st.List(namespace, label)
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

// parseNetPolicyQuery strictly parses the raw query string for the GET entry.
// The whole query must validate before any record is returned: every segment
// needs valid percent escapes in both name and value, and no segment may carry
// an unescaped semicolon — a malformed fragment rejects the request even when
// it belongs to an unknown parameter or the remaining conditions would have
// matched committed records. Empty segments (including a trailing &) are
// skipped. Names are compared after a single decode, so "namespace" and
// "%6Eamespace" are the same parameter; a known parameter may appear at most
// once with a non-blank value, and at least one of namespace/label must be
// present. Legal unknown parameters are ignored. Values are decoded exactly
// once (+ means space) and matched verbatim — no trimming or case folding.
func parseNetPolicyQuery(rawQuery string) (namespace, label string, ok bool) {
	seen := map[string]bool{}
	values := map[string]string{}
	for _, segment := range strings.Split(rawQuery, "&") {
		if segment == "" {
			continue
		}
		if strings.Contains(segment, ";") {
			return "", "", false
		}
		name, value, _ := strings.Cut(segment, "=")
		decodedName, err := url.QueryUnescape(name)
		if err != nil {
			return "", "", false
		}
		decodedValue, err := url.QueryUnescape(value)
		if err != nil {
			return "", "", false
		}
		if decodedName != "namespace" && decodedName != "label" {
			continue
		}
		if seen[decodedName] || strings.TrimSpace(decodedValue) == "" {
			return "", "", false
		}
		seen[decodedName] = true
		values[decodedName] = decodedValue
	}
	namespace, label = values["namespace"], values["label"]
	if namespace == "" && label == "" {
		return "", "", false
	}
	return namespace, label, true
}

// decodeNetPolicy strictly validates the request body: a single JSON object
// with the required fields, enums, and port intervals from the service contract.
//
// The top-level object is walked with a streaming decoder instead of a plain
// map decode so every occurrence of pluginParams is validated on its own: a
// later object must not overwrite an earlier illegal one before that earlier
// object is checked, so {"mode":null} followed by {"mode":"enforce"} fails.
// Field names match after JSON unescaping, making "pluginParams" and
// "\u0070luginParams" the same field. When every occurrence is legal the last
// complete object wins. Other fields keep their existing single-value
// parsing behaviour (a repeated name keeps its last value).
func decodeNetPolicy(body io.Reader) (store.Record, bool) {
	decoder := json.NewDecoder(body)
	opening, err := decoder.Token()
	if err != nil {
		return store.Record{}, false
	}
	if delim, ok := opening.(json.Delim); !ok || delim != '{' {
		// Rejects empty input, null, scalars and arrays outright.
		return store.Record{}, false
	}

	raw := map[string]json.RawMessage{}
	var (
		pluginParams    map[string]string
		pluginParamsSet bool
	)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return store.Record{}, false
		}
		key, ok := keyToken.(string)
		if !ok {
			return store.Record{}, false
		}
		var blob json.RawMessage
		if err := decoder.Decode(&blob); err != nil {
			return store.Record{}, false
		}
		if key == "pluginParams" {
			// Validate each occurrence immediately: an illegal object must be
			// rejected even when a later legal object would overwrite it.
			params, valid := decodePluginObject(blob)
			if !valid {
				return store.Record{}, false
			}
			pluginParams, pluginParamsSet = params, true
		}
		raw[key] = blob
	}
	closing, err := decoder.Token()
	if err != nil {
		return store.Record{}, false
	}
	if delim, ok := closing.(json.Delim); !ok || delim != '}' {
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
	if !pluginParamsSet {
		return store.Record{}, false
	}
	rec.PluginParams = pluginParams
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

// decodePluginObject validates and decodes one pluginParams value. The
// published contract is a string-to-string object: null, numbers, booleans,
// arrays and nested objects are invalid input rather than coerced or dropped.
//
// Members are walked with a streaming decoder so every occurrence of a repeated
// member name is inspected, not just the value a map decode would keep last.
// {"mode":null,"mode":"enforce"} must fail on the null even though a legal
// string follows it; keys are matched after JSON unescaping, so "mode" and
// "\u006dode" are the same member. When every occurrence is a string the last
// value for each decoded key wins, and the empty object yields an empty map.
func decodePluginObject(blob json.RawMessage) (map[string]string, bool) {
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
