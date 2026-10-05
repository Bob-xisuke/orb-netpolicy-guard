// Package store owns the SQLite file and every write the service performs.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	_ "modernc.org/sqlite"
)

// testFaultTrigger marks the BEFORE INSERT trigger that test builds install to
// reject new rows. The trigger name is also quoted into the DDL, so it stays a
// fixed identifier rather than interpolated input.
const testFaultTrigger = "net_policies_reject_new_rows_test"

// TestingT is the subset of *testing.T the test-only fault hooks rely on. It
// keeps the production package free of a testing import while letting test
// builds surface injection setup failures immediately.
type TestingT interface {
	Helper()
	Fatalf(format string, args ...any)
}

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
	db   *sql.DB
	mu   sync.Mutex
	path string
	down bool
}

// Open prepares the database file and the schema this service needs.
func Open(path string) (*Store, error) {
	// Keep the connection pool at size one: BEGIN opens a transaction on one
	// pooled connection and COMMIT must land on that same connection. A single
	// connection also makes the test-only fault triggers below deterministic.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable wal: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db, path: filepath.Clean(path)}, nil
}

// Ping reports whether the storage layer is usable.
func (s *Store) Ping() error { return s.db.Ping() }

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// SetWritesFailForTesting installs (or, with fail=false, removes) a BEFORE
// INSERT trigger that rejects every new net_policies row at the storage layer.
// Reads, commits already on disk and idempotent same-content lookups all keep
// working while the trigger is installed, so callers observe a store that
// "can still read but refuses new records". It is intended solely for failure
// injection in tests.
func (s *Store) SetWritesFailForTesting(t TestingT, fail bool) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if fail {
		if _, err := s.db.Exec(fmt.Sprintf(
			`CREATE TRIGGER IF NOT EXISTS %s BEFORE INSERT ON net_policies
			 BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END`,
			testFaultTrigger)); err != nil {
			t.Fatalf("install write-failure trigger: %v", err)
		}
		return
	}
	if _, err := s.db.Exec(fmt.Sprintf(`DROP TRIGGER IF EXISTS %s`, testFaultTrigger)); err != nil {
		t.Fatalf("remove write-failure trigger: %v", err)
	}
}

// SetStorageDownForTesting tears down the live database handle (fail=true), so
// Ping, reads and writes all fail, or reopens the same database file
// (fail=false) with every committed record intact. It is intended solely for
// failure injection in tests.
func (s *Store) SetStorageDownForTesting(t TestingT, down bool) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if down == s.down {
		return
	}
	if down {
		if err := s.db.Close(); err != nil {
			t.Fatalf("close database to simulate outage: %v", err)
		}
		s.down = true
		return
	}
	db, err := sql.Open("sqlite", s.path)
	if err != nil {
		t.Fatalf("reopen sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		t.Fatalf("reopened database is not usable: %v", err)
	}
	s.db = db
	s.down = false
}

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
// overlapping port intervals.
func detectConflict(tx *sql.Tx, rec Record) (bool, error) {
	rows, err := tx.Query(
		`SELECT rules FROM net_policies WHERE namespace = ? AND label = ?`,
		rec.Namespace, rec.Label)
	if err != nil {
		return false, fmt.Errorf("scan conflicts: %w", err)
	}
	defer rows.Close()

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
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("iterate conflicts: %w", err)
	}
	return false, nil
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
