// Package store owns the SQLite file and every write the service performs.
package store

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"

	_ "modernc.org/sqlite"
)

// Store wraps the SQLite handle so callers never touch database/sql directly.
type Store struct {
	db *sql.DB
}

// Open prepares the database file and the schema this service needs.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

// sqliteDSN makes every connection open write transactions in IMMEDIATE mode
// (so concurrent registrations serialize and the same identity can never be
// inserted twice), waits on locks instead of failing instantly, and keeps WAL.
func sqliteDSN(path string) string {
	query := url.Values{}
	query.Set("_txlock", "immediate")
	query.Add("_pragma", "busy_timeout=10000")
	query.Add("_pragma", "journal_mode=WAL")
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + query.Encode()
}

// Ping reports whether the storage layer is usable.
func (s *Store) Ping() error { return s.db.Ping() }

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

const schema = `
CREATE TABLE IF NOT EXISTS service_metadata (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS net_policies (
	namespace           TEXT NOT NULL,
	name                TEXT NOT NULL,
	label               TEXT NOT NULL,
	rules               TEXT NOT NULL,
	plugin_params       TEXT NOT NULL,
	content_fingerprint TEXT NOT NULL,
	ord                 INTEGER NOT NULL UNIQUE,
	conflict            INTEGER NOT NULL,
	PRIMARY KEY (namespace, name)
);

CREATE INDEX IF NOT EXISTS idx_net_policies_namespace_label
	ON net_policies (namespace, label);
`
