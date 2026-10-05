package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
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
		query := c.Request.URL.Query()
		namespace, ok := singleQueryValue(query, "namespace")
		if !ok {
			writeError(c, http.StatusBadRequest, codeInvalidInput, "namespace must appear at most once and be non-blank")
			return
		}
		label, ok := singleQueryValue(query, "label")
		if !ok {
			writeError(c, http.StatusBadRequest, codeInvalidInput, "label must appear at most once and be non-blank")
			return
		}
		if namespace == "" && label == "" {
			writeError(c, http.StatusBadRequest, codeInvalidInput, "namespace or label is required")
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

// singleQueryValue accepts a parameter that appears at most once with a non-blank
// value. Absent yields ("", true); duplicated or blank yields ("", false).
func singleQueryValue(query map[string][]string, key string) (string, bool) {
	values, present := query[key]
	if !present {
		return "", true
	}
	if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
		return "", false
	}
	return values[0], true
}

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

func decodePluginParams(raw map[string]json.RawMessage) (map[string]string, bool) {
	blob, present := raw["pluginParams"]
	if !present {
		return nil, false
	}
	// Decode members as a token stream: unmarshalling into a map keeps only the
	// final value of a duplicated member name, which would hide an earlier
	// non-string value. The published contract is a string-to-string object and
	// any non-string occurrence — null, number, boolean, array or nested object,
	// whether it appears before or after a legal string for the same name —
	// rejects the whole registration. Member names are compared after JSON
	// unescaping, so an escape-encoded spelling of a name collides with its
	// plain spelling; when every occurrence is a legal string the last one wins.
	decoder := json.NewDecoder(bytes.NewReader(blob))
	opening, err := decoder.Token()
	if err != nil {
		return nil, false
	}
	if delim, ok := opening.(json.Delim); !ok || delim != '{' {
		return nil, false
	}
	params := make(map[string]string)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, false
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, false
		}
		var value any
		if err := decoder.Decode(&value); err != nil {
			return nil, false
		}
		str, ok := value.(string)
		if !ok {
			return nil, false
		}
		params[key] = str
	}
	closing, err := decoder.Token()
	if err != nil {
		return nil, false
	}
	if delim, ok := closing.(json.Delim); !ok || delim != '}' {
		return nil, false
	}
	return params, true
}
