package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/Bob-xisuke/orb-netpolicy-guard/internal/store"
)

const (
	codeInvalidInput = "InvalidNetPolicyInputError"
	codeConflict     = "NetPolicyConflictError"
	codeNotFound     = "NetPolicyNotFoundError"
	codeStorageDown  = "storage_unavailable"
)

type netPolicyRequest struct {
	Namespace    *string            `json:"namespace"`
	Name         *string            `json:"name"`
	Label        *string            `json:"label"`
	Rules        *[]ruleRequest     `json:"rules"`
	PluginParams *map[string]string `json:"pluginParams"`
}

type ruleRequest struct {
	Direction string `json:"direction"`
	Action    string `json:"action"`
	// Ports is a slice (not [2]int) because encoding/json silently discards
	// extra elements when decoding a longer JSON array into a fixed array.
	Ports []int `json:"ports"`
}

func postNetPolicies(st *store.Store, c *gin.Context) {
	var req netPolicyRequest
	decoder := json.NewDecoder(c.Request.Body)
	if err := decoder.Decode(&req); err != nil {
		writeInvalidInput(c)
		return
	}
	// The body must carry exactly one JSON value: trailing objects or garbage
	// (other than whitespace) are rejected instead of being ignored.
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeInvalidInput(c)
		return
	}

	policy, ok := requestToPolicy(c, &req)
	if !ok {
		return
	}

	result, err := st.RegisterNetPolicy(c.Request.Context(), policy)
	if err != nil {
		if errors.Is(err, store.ErrNetPolicyConflict) {
			c.JSON(http.StatusConflict, gin.H{
				"error": gin.H{
					"code":    codeConflict,
					"message": "a net policy with the same identity but different content already exists",
				},
			})
			return
		}
		writeStorageUnavailable(c)
		return
	}

	status := http.StatusCreated
	if !result.Created {
		status = http.StatusOK
	}
	c.JSON(status, result.Policy)
}

func getNetPolicies(st *store.Store, c *gin.Context) {
	values := c.Request.URL.Query()
	if len(values["namespace"]) > 1 || len(values["label"]) > 1 {
		writeInvalidInput(c)
		return
	}

	var namespace, label *string
	if raw, ok := values["namespace"]; ok {
		value := raw[0]
		if strings.TrimSpace(value) == "" {
			writeInvalidInput(c)
			return
		}
		namespace = &value
	}
	if raw, ok := values["label"]; ok {
		value := raw[0]
		if strings.TrimSpace(value) == "" {
			writeInvalidInput(c)
			return
		}
		label = &value
	}
	if namespace == nil && label == nil {
		writeInvalidInput(c)
		return
	}

	policies, err := st.ListNetPolicies(c.Request.Context(), namespace, label)
	if err != nil {
		writeStorageUnavailable(c)
		return
	}
	if len(policies) == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"error": gin.H{
				"code":    codeNotFound,
				"message": "no net policy matches the given query",
			},
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": policies})
}

// requestToPolicy validates the decoded request and converts it into a store
// policy. Every malformed input answers InvalidNetPolicyInputError and writes
// nothing.
func requestToPolicy(c *gin.Context, req *netPolicyRequest) (store.NetPolicy, bool) {
	if req.Namespace == nil || req.Name == nil || req.Label == nil ||
		req.Rules == nil || req.PluginParams == nil {
		writeInvalidInput(c)
		return store.NetPolicy{}, false
	}
	if isBlank(*req.Namespace) || isBlank(*req.Name) || isBlank(*req.Label) {
		writeInvalidInput(c)
		return store.NetPolicy{}, false
	}
	if len(*req.Rules) == 0 {
		writeInvalidInput(c)
		return store.NetPolicy{}, false
	}

	rules := make([]store.Rule, 0, len(*req.Rules))
	for _, r := range *req.Rules {
		if r.Direction != "ingress" && r.Direction != "egress" {
			writeInvalidInput(c)
			return store.NetPolicy{}, false
		}
		if r.Action != "allow" && r.Action != "deny" {
			writeInvalidInput(c)
			return store.NetPolicy{}, false
		}
		if len(r.Ports) != 2 ||
			r.Ports[0] < 1 || r.Ports[0] > 65535 ||
			r.Ports[1] < 1 || r.Ports[1] > 65535 ||
			r.Ports[0] > r.Ports[1] {
			writeInvalidInput(c)
			return store.NetPolicy{}, false
		}
		rules = append(rules, store.Rule{
			Direction: r.Direction,
			Action:    r.Action,
			Ports:     [2]int{r.Ports[0], r.Ports[1]},
		})
	}

	return store.NetPolicy{
		Namespace:    *req.Namespace,
		Name:         *req.Name,
		Label:        *req.Label,
		Rules:        rules,
		PluginParams: *req.PluginParams,
	}, true
}

func isBlank(s string) bool { return strings.TrimSpace(s) == "" }

func writeInvalidInput(c *gin.Context) {
	c.JSON(http.StatusBadRequest, gin.H{
		"error": gin.H{
			"code":    codeInvalidInput,
			"message": "the submitted net policy input is invalid",
		},
	})
}

func writeStorageUnavailable(c *gin.Context) {
	c.JSON(http.StatusServiceUnavailable, gin.H{
		"error": gin.H{
			"code":    codeStorageDown,
			"message": "database is not available",
		},
	})
}
