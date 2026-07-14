package store

import (
	"context"
	"database/sql"
	"fmt"
)

// SessionInfo summarizes one stored session for listing.
type SessionInfo struct {
	Session string
	Entries int
}

// childTables are the per-entry tables whose rows are owned by an entry and must
// be removed alongside it.
var childTables = []string{"headers", "cookies", "query_params", "post_params", "cache_states"}

// SessionInfos returns every session that has at least one entry, with its entry
// count, ordered by session id.
func (s *Store) SessionInfos(ctx context.Context) ([]SessionInfo, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT session, COUNT(*) FROM entries GROUP BY session ORDER BY session")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionInfo
	for rows.Next() {
		var si SessionInfo
		if err := rows.Scan(&si.Session, &si.Entries); err != nil {
			return nil, err
		}
		out = append(out, si)
	}
	return out, rows.Err()
}

// DeleteSession removes a session's entries (and their child rows) and its log
// metadata. It is a no-op for an unknown session and leaves other sessions
// untouched.
func (s *Store) DeleteSession(ctx context.Context, session string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, t := range childTables {
		q := s.d.rebind("DELETE FROM " + t + " WHERE entry_id IN (SELECT id FROM entries WHERE session = ?)")
		if _, err := tx.ExecContext(ctx, q, session); err != nil {
			tx.Rollback()
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, s.d.rebind("DELETE FROM entries WHERE session = ?"), session); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.ExecContext(ctx, s.d.rebind("DELETE FROM logs WHERE session = ?"), session); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// RenameSession moves every row belonging to old under the id new. It fails if
// new already names a stored session, so a rename never merges or clobbers.
func (s *Store) RenameSession(ctx context.Context, old, new string) error {
	if old == new {
		return nil
	}
	n, err := s.Count(ctx, Query{Session: new})
	if err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("session %q already exists", new)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	// Drop any orphan log row under new so the logs primary key does not collide.
	if _, err := tx.ExecContext(ctx, s.d.rebind("DELETE FROM logs WHERE session = ?"), new); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.ExecContext(ctx, s.d.rebind("UPDATE entries SET session = ? WHERE session = ?"), new, old); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.ExecContext(ctx, s.d.rebind("UPDATE logs SET session = ? WHERE session = ?"), new, old); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// HasSession reports whether a session has any stored entries.
func (s *Store) HasSession(ctx context.Context, session string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, s.d.rebind("SELECT COUNT(*) FROM entries WHERE session = ?"), session).Scan(&n)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return n > 0, err
}
