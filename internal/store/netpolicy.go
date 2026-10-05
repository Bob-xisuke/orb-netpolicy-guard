package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

// ErrNetPolicyConflict marks a re-registration whose identity (namespace + name)
// already exists with different content. Records are immutable, so the stored
// record is left untouched.
var ErrNetPolicyConflict = errors.New("a net policy with the same identity but different content already exists")

// Rule is one ingress/egress allow/deny rule over a closed port interval.
type Rule struct {
	Direction string `json:"direction"`
	Action    string `json:"action"`
	Ports     [2]int `json:"ports"`
}

// NetPolicy is one registered, immutable network policy. Order and Conflict are
// assigned by the store on creation and are zero on input.
type NetPolicy struct {
	Namespace    string            `json:"namespace"`
	Name         string            `json:"name"`
	Label        string            `json:"label"`
	Rules        []Rule            `json:"rules"`
	PluginParams map[string]string `json:"pluginParams"`
	Order        int64             `json:"order"`
	Conflict     bool              `json:"conflict"`
}

// RegisterResult reports what RegisterNetPolicy did. Created is true for a new
// record (HTTP 201) and false for an idempotent replay (HTTP 200).
type RegisterResult struct {
	Policy  NetPolicy
	Created bool
}

type storedPolicy struct {
	label        string
	rules        []byte
	pluginParams []byte
	order        int64
	conflict     bool
	fingerprint  string
}

// RegisterNetPolicy creates a policy record, returns the existing one unchanged
// when the same identity is retried with identical content, or fails with
// ErrNetPolicyConflict when content differs. The whole operation runs in one
// write transaction: concurrent submissions of the same identity serialize,
// and an error never leaves partial data behind.
func (s *Store) RegisterNetPolicy(ctx context.Context, in NetPolicy) (RegisterResult, error) {
	if in.PluginParams == nil {
		in.PluginParams = map[string]string{}
	}
	rulesJSON, err := json.Marshal(in.Rules)
	if err != nil {
		return RegisterResult{}, err
	}
	paramsJSON, err := json.Marshal(in.PluginParams)
	if err != nil {
		return RegisterResult{}, err
	}
	fingerprint, err := contentFingerprint(in.Label, rulesJSON, paramsJSON)
	if err != nil {
		return RegisterResult{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RegisterResult{}, err
	}
	defer tx.Rollback()

	var existing storedPolicy
	row := tx.QueryRowContext(ctx,
		`SELECT label, rules, plugin_params, ord, conflict, content_fingerprint
		 FROM net_policies WHERE namespace = ? AND name = ?`,
		in.Namespace, in.Name)
	switch err := row.Scan(
		&existing.label,
		&existing.rules,
		&existing.pluginParams,
		&existing.order,
		&existing.conflict,
		&existing.fingerprint,
	); {
	case err == nil:
		if existing.fingerprint != fingerprint {
			return RegisterResult{}, ErrNetPolicyConflict
		}
		stored, err := decodePolicy(in.Namespace, in.Name, existing)
		if err != nil {
			return RegisterResult{}, err
		}
		return RegisterResult{Policy: stored, Created: false}, nil
	case !errors.Is(err, sql.ErrNoRows):
		return RegisterResult{}, err
	}

	conflict, err := hasConflictingRule(ctx, tx, in)
	if err != nil {
		return RegisterResult{}, err
	}

	var order int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(ord), 0) + 1 FROM net_policies`).Scan(&order); err != nil {
		return RegisterResult{}, err
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO net_policies
			(namespace, name, label, rules, plugin_params, content_fingerprint, ord, conflict)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		in.Namespace, in.Name, in.Label, string(rulesJSON), string(paramsJSON),
		fingerprint, order, conflict); err != nil {
		return RegisterResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return RegisterResult{}, err
	}

	in.Order = order
	in.Conflict = conflict
	return RegisterResult{Policy: in, Created: true}, nil
}

// ListNetPolicies returns committed policies filtered by namespace and/or label
// (both means intersection), ordered by their global registration order.
func (s *Store) ListNetPolicies(ctx context.Context, namespace, label *string) ([]NetPolicy, error) {
	query := `SELECT namespace, name, label, rules, plugin_params, ord, conflict
	          FROM net_policies`
	var conditions []string
	var args []any
	if namespace != nil {
		conditions = append(conditions, "namespace = ?")
		args = append(args, *namespace)
	}
	if label != nil {
		conditions = append(conditions, "label = ?")
		args = append(args, *label)
	}
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY ord ASC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []NetPolicy
	for rows.Next() {
		var (
			p                     NetPolicy
			rulesJSON, paramsJSON string
			conflict              bool
		)
		if err := rows.Scan(
			&p.Namespace, &p.Name, &p.Label,
			&rulesJSON, &paramsJSON, &p.Order, &conflict); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(rulesJSON), &p.Rules); err != nil {
			return nil, err
		}
		p.PluginParams = map[string]string{}
		if err := json.Unmarshal([]byte(paramsJSON), &p.PluginParams); err != nil {
			return nil, err
		}
		p.Conflict = conflict
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return policies, nil
}

// hasConflictingRule checks only records committed before this transaction: the
// new identity has not been inserted yet, and IMMEDIATE transactions serialize
// every writer. Conflict means some rule shares direction with an older rule of
// the same namespace and label, takes the opposite action, and overlaps ports.
func hasConflictingRule(ctx context.Context, tx *sql.Tx, in NetPolicy) (bool, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT rules FROM net_policies WHERE namespace = ? AND label = ?`,
		in.Namespace, in.Label)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var rulesJSON string
		if err := rows.Scan(&rulesJSON); err != nil {
			return false, err
		}
		var oldRules []Rule
		if err := json.Unmarshal([]byte(rulesJSON), &oldRules); err != nil {
			return false, err
		}
		for _, newRule := range in.Rules {
			for _, oldRule := range oldRules {
				if rulesConflict(newRule, oldRule) {
					return true, nil
				}
			}
		}
	}
	return false, rows.Err()
}

func rulesConflict(a, b Rule) bool {
	if a.Direction != b.Direction {
		return false
	}
	if !oppositeActions(a.Action, b.Action) {
		return false
	}
	return a.Ports[0] <= b.Ports[1] && b.Ports[0] <= a.Ports[1]
}

func oppositeActions(a, b string) bool {
	return (a == "allow" && b == "deny") || (a == "deny" && b == "allow")
}

func decodePolicy(namespace, name string, s storedPolicy) (NetPolicy, error) {
	p := NetPolicy{
		Namespace:    namespace,
		Name:         name,
		Label:        s.label,
		Order:        s.order,
		Conflict:     s.conflict,
		PluginParams: map[string]string{},
	}
	if err := json.Unmarshal(s.rules, &p.Rules); err != nil {
		return NetPolicy{}, err
	}
	if err := json.Unmarshal(s.pluginParams, &p.PluginParams); err != nil {
		return NetPolicy{}, err
	}
	return p, nil
}

// contentFingerprint is canonical over the mutable content of an identity:
// object keys of pluginParams are sorted by encoding/json, rule array order is
// kept, and the fixed struct field order makes the whole string deterministic.
func contentFingerprint(label string, rulesJSON, paramsJSON []byte) (string, error) {
	canonical := struct {
		Label        string          `json:"label"`
		Rules        json.RawMessage `json:"rules"`
		PluginParams json.RawMessage `json:"pluginParams"`
	}{Label: label, Rules: rulesJSON, PluginParams: paramsJSON}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
