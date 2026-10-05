package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// PendingRegistration is a test-only handle to a registration transaction that
// has completed every write (identity lookup, conflict scan, seq assignment
// and the net_policies INSERT) without committing. It lets regression tests
// query the service deterministically while the candidate row exists only in
// this uncommitted transaction — instead of racing concurrent requests and
// hoping to sample that state.
//
// The pending transaction holds the store mutex for its whole lifetime, so the
// published POST entry cannot interleave another registration; GET queries run
// on separate connections and, with the default SQLite journal/locking
// settings, read only committed rows. Commit or Rollback must be called once;
// both release the lock and finalize (or undo) the transaction.
type PendingRegistration struct {
	s      *Store
	tx     *sql.Tx
	order  int64
	closed bool
}

// HoldUncommittedRegistration performs exactly the write half of Register
// (same lookup, same detectConflict call, same MAX(seq)+1 assignment, same
// INSERT statement) but stops with the transaction open once the candidate row
// is fully written. conflict reports the flag stored on the pending row and
// order the seq value the committed registration would take. The candidate
// identity must be unused, as in a normal first registration.
func HoldUncommittedRegistration(s *Store, rec Record) (pending *PendingRegistration, order int64, conflict bool, err error) {
	rulesJSON, err := json.Marshal(rec.Rules)
	if err != nil {
		return nil, 0, false, fmt.Errorf("encode rules: %w", err)
	}
	paramsJSON, err := json.Marshal(rec.PluginParams)
	if err != nil {
		return nil, 0, false, fmt.Errorf("encode plugin params: %w", err)
	}
	content := contentKey(rec.Label, rulesJSON, paramsJSON)

	// Register takes the same lock for its whole check-and-insert; holding it
	// here keeps any concurrent Register (including one driven through POST)
	// blocked before Begin until the pending transaction commits or rolls back,
	// so it cannot observe or disturb the intermediate state.
	s.mu.Lock()

	tx, err := s.db.Begin()
	if err != nil {
		s.mu.Unlock()
		return nil, 0, false, fmt.Errorf("begin register: %w", err)
	}
	rollbackOnError := func(cause error) (*PendingRegistration, int64, bool, error) {
		_ = tx.Rollback()
		s.mu.Unlock()
		return nil, 0, false, cause
	}

	var existingCount int
	if err := tx.QueryRow(
		`SELECT COUNT(*) FROM net_policies WHERE namespace = ? AND name = ?`,
		rec.Namespace, rec.Name).Scan(&existingCount); err != nil {
		return rollbackOnError(fmt.Errorf("lookup net policy: %w", err))
	}
	if existingCount != 0 {
		return rollbackOnError(errors.New("HoldUncommittedRegistration requires an unused identity"))
	}

	conflictFlag, err := detectConflict(tx, rec)
	if err != nil {
		return rollbackOnError(err)
	}

	if err := tx.QueryRow(`SELECT COALESCE(MAX(seq), 0) + 1 FROM net_policies`).Scan(&order); err != nil {
		return rollbackOnError(fmt.Errorf("assign order: %w", err))
	}
	conflictInt := 0
	if conflictFlag {
		conflictInt = 1
	}
	if _, err := tx.Exec(
		`INSERT INTO net_policies (namespace, name, label, rules, plugin_params, content, seq, conflict)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.Namespace, rec.Name, rec.Label, string(rulesJSON), string(paramsJSON), content, order, conflictInt); err != nil {
		return rollbackOnError(fmt.Errorf("insert net policy: %w", err))
	}
	return &PendingRegistration{s: s, tx: tx, order: order}, order, conflictFlag, nil
}

// Commit finalizes the pending registration exactly as Register would.
func (p *PendingRegistration) Commit() error {
	if p.closed {
		return errors.New("pending registration already finalized")
	}
	p.closed = true
	defer p.s.mu.Unlock()
	return p.tx.Commit()
}

// Rollback undoes the pending registration; the candidate row and its seq
// assignment never become visible to other connections.
func (p *PendingRegistration) Rollback() error {
	if p.closed {
		return errors.New("pending registration already finalized")
	}
	p.closed = true
	defer p.s.mu.Unlock()
	return p.tx.Rollback()
}

// CountInTransaction counts rows visible to the pending transaction under the
// given (non-empty) filters. It exists for tests to prove the window is real:
// the same filters count the fully written candidate inside the transaction
// while every committed-read connection (the public GET entry) returns one row
// fewer, and after rollback the count is back to the committed set.
func (p *PendingRegistration) CountInTransaction(namespace, label string) (int, error) {
	query := `SELECT COUNT(*) FROM net_policies`
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
	var count int
	if err := p.tx.QueryRow(query, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// Order reports the seq value assigned to the pending row.
func (p *PendingRegistration) Order() int64 { return p.order }
