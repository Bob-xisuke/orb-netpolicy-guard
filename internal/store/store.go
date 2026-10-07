// Package store owns the SQLite file and every write the service performs.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	_ "modernc.org/sqlite"
)

// ErrConflict reports that a net policy identity already holds different content.
var ErrConflict = errors.New("net policy identity holds different content")

// Rule is one allow/deny statement bound to a closed port interval.
type Rule struct {
	Direction string `json:"direction"`
	Action    string `json:"action"`
	Ports     [2]int `json:"ports"`
}

// Record is a committed net policy together with its registry metadata.
type Record struct {
	Namespace    string            `json:"namespace"`
	Name         string            `json:"name"`
	Label        string            `json:"label"`
	Rules        []Rule            `json:"rules"`
	PluginParams map[string]string `json:"pluginParams"`
	Order        int64             `json:"order"`
	Conflict     bool              `json:"conflict"`
}

// Store wraps the SQLite handle so callers never touch database/sql directly.
type Store struct {
	db *sql.DB
	mu sync.Mutex
}

// Open prepares the database file and the schema this service needs.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable wal: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Ping reports whether the storage layer is usable.
func (s *Store) Ping() error { return s.db.Ping() }

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// Register commits a new net policy. Retrying an identity with identical content
// returns the stored record with created=false; different content yields ErrConflict.
// The whole check-and-insert runs under one lock and one transaction so a failed
// registration leaves nothing behind and concurrent submits keep a single row.
func (s *Store) Register(rec Record) (stored Record, created bool, err error) {
	rulesJSON, err := json.Marshal(rec.Rules)
	if err != nil {
		return Record{}, false, fmt.Errorf("encode rules: %w", err)
	}
	paramsJSON, err := json.Marshal(rec.PluginParams)
	if err != nil {
		return Record{}, false, fmt.Errorf("encode plugin params: %w", err)
	}
	content := contentKey(rec.Label, rulesJSON, paramsJSON)

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return Record{}, false, fmt.Errorf("begin register: %w", err)
	}
	defer tx.Rollback()

	var (
		existing                                       Record
		existingRules, existingParams, existingContent string
		existingConflict                               int
	)
	row := tx.QueryRow(
		`SELECT label, rules, plugin_params, content, seq, conflict
		 FROM net_policies WHERE namespace = ? AND name = ?`,
		rec.Namespace, rec.Name)
	scanErr := row.Scan(&existing.Label, &existingRules, &existingParams, &existingContent, &existing.Order, &existingConflict)
	switch {
	case scanErr == nil:
		if existingContent != content {
			return Record{}, false, ErrConflict
		}
		existing.Namespace, existing.Name = rec.Namespace, rec.Name
		existing.Conflict = existingConflict != 0
		if err := json.Unmarshal([]byte(existingRules), &existing.Rules); err != nil {
			return Record{}, false, fmt.Errorf("decode stored rules: %w", err)
		}
		if err := json.Unmarshal([]byte(existingParams), &existing.PluginParams); err != nil {
			return Record{}, false, fmt.Errorf("decode stored plugin params: %w", err)
		}
		return existing, false, nil
	case !errors.Is(scanErr, sql.ErrNoRows):
		return Record{}, false, fmt.Errorf("lookup net policy: %w", scanErr)
	}

	conflict, err := detectConflict(tx, rec)
	if err != nil {
		return Record{}, false, err
	}

	var next int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(seq), 0) + 1 FROM net_policies`).Scan(&next); err != nil {
		return Record{}, false, fmt.Errorf("assign order: %w", err)
	}
	conflictFlag := 0
	if conflict {
		conflictFlag = 1
	}
	if _, err := tx.Exec(
		`INSERT INTO net_policies (namespace, name, label, rules, plugin_params, content, seq, conflict)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.Namespace, rec.Name, rec.Label, string(rulesJSON), string(paramsJSON), content, next, conflictFlag); err != nil {
		return Record{}, false, fmt.Errorf("insert net policy: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Record{}, false, fmt.Errorf("commit net policy: %w", err)
	}
	rec.Order = next
	rec.Conflict = conflict
	return rec, true, nil
}

// List returns committed records filtered by the non-empty conditions, ordered by seq.
func (s *Store) List(namespace, label string) ([]Record, error) {
	query := `SELECT namespace, name, label, rules, plugin_params, seq, conflict FROM net_policies`
	var conds []string
	var args []any
	if namespace != "" {
		conds = append(conds, "namespace = ?")
		args = append(args, namespace)
	}
	if label != "" {
		conds = append(conds, "label = ?")
		args = append(args, label)
	}
	if len(conds) > 0 {
		query += " WHERE " + strings.Join(conds, " AND ")
	}
	query += " ORDER BY seq ASC"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list net policies: %w", err)
	}
	defer rows.Close()

	var records []Record
	for rows.Next() {
		var (
			rec                 Record
			rulesRaw, paramsRaw string
			conflictFlag        int
		)
		if err := rows.Scan(&rec.Namespace, &rec.Name, &rec.Label, &rulesRaw, &paramsRaw, &rec.Order, &conflictFlag); err != nil {
			return nil, fmt.Errorf("scan net policy: %w", err)
		}
		if err := json.Unmarshal([]byte(rulesRaw), &rec.Rules); err != nil {
			return nil, fmt.Errorf("decode stored rules: %w", err)
		}
		if err := json.Unmarshal([]byte(paramsRaw), &rec.PluginParams); err != nil {
			return nil, fmt.Errorf("decode stored plugin params: %w", err)
		}
		rec.Conflict = conflictFlag != 0
		records = append(records, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate net policies: %w", err)
	}
	return records, nil
}

// detectConflict reports whether the candidate record clashes with any committed
// record sharing its namespace and label: same direction, opposite action, and
// overlapping port intervals. Every row in the scope is decoded before the
// result is decided, so an undecodable stored record fails the registration
// with the same error no matter where it sits in the scan order — the outcome
// never depends on the order the committed rows are read back.
func detectConflict(tx *sql.Tx, rec Record) (bool, error) {
	rows, err := tx.Query(
		`SELECT rules FROM net_policies WHERE namespace = ? AND label = ?`,
		rec.Namespace, rec.Label)
	if err != nil {
		return false, fmt.Errorf("scan conflicts: %w", err)
	}
	defer rows.Close()

	conflict := false
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return false, fmt.Errorf("scan conflict row: %w", err)
		}
		var existing []Rule
		if err := json.Unmarshal([]byte(raw), &existing); err != nil {
			return false, fmt.Errorf("decode stored rules: %w", err)
		}
		if rulesConflict(rec.Rules, existing) {
			conflict = true
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("iterate conflicts: %w", err)
	}
	return conflict, nil
}

func rulesConflict(candidate, existing []Rule) bool {
	for _, a := range candidate {
		for _, b := range existing {
			if a.Direction == b.Direction && a.Action != b.Action && portsOverlap(a.Ports, b.Ports) {
				return true
			}
		}
	}
	return false
}

func portsOverlap(p, q [2]int) bool { return p[0] <= q[1] && q[0] <= p[1] }

// contentKey is the canonical fingerprint of everything outside the identity:
// object key order is irrelevant (structs and maps encode deterministically)
// while the rules array order stays significant.
func contentKey(label string, rulesJSON, paramsJSON []byte) string {
	return string(label) + "\x00" + string(rulesJSON) + "\x00" + string(paramsJSON)
}

const schema = `
CREATE TABLE IF NOT EXISTS service_metadata (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS net_policies (
	namespace    TEXT NOT NULL,
	name         TEXT NOT NULL,
	label        TEXT NOT NULL,
	rules        TEXT NOT NULL,
	plugin_params TEXT NOT NULL,
	content      TEXT NOT NULL,
	seq          INTEGER NOT NULL UNIQUE,
	conflict     INTEGER NOT NULL,
	PRIMARY KEY (namespace, name)
);
`
