package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/ntakezo/lebedev/model"
)

// OpenDB wraps an existing database handle instead of opening one from a DSN, so
// a consumer can bring its own *sql.DB (and its own pooling, tracing, and
// lifecycle) while the store still owns the schema. driver names the SQL dialect:
// "sqlite" or "postgres" (aliases "sqlite3", "postgresql", "pgx" are accepted).
// The idempotent schema migration runs before the store is returned. The caller
// retains ownership of db and is responsible for closing it.
func OpenDB(db *sql.DB, driver string) (*Store, error) {
	d, ok := dialectByName(driver)
	if !ok {
		return nil, fmt.Errorf("store: unknown driver %q (want sqlite or postgres)", driver)
	}
	s := &Store{db: db, d: d}
	if err := s.migrate(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

func dialectByName(name string) (dialect, bool) {
	switch name {
	case "sqlite", "sqlite3":
		return sqliteDialect, true
	case "postgres", "postgresql", "pgx":
		return postgresDialect, true
	}
	return dialect{}, false
}

// DB exposes the underlying handle so a consumer can run fully custom SQL. Any
// entry ids such a query surfaces can be reassembled byte-faithfully with
// Hydrate; the store's own reads never touch the handle's transaction state.
func (s *Store) DB() *sql.DB { return s.db }

// DialectName reports the SQL dialect ("sqlite" or "postgres"), which a consumer
// writing raw SQL needs to know to pick the placeholder style.
func (s *Store) DialectName() string { return s.d.name }

// Rebind rewrites '?' placeholders into the store's dialect form, so a consumer
// can author portable custom SQL with '?' and let the store adapt it.
func (s *Store) Rebind(query string) string { return s.d.rebind(query) }

// ListWhere is the raw-predicate escape hatch: it selects entries matching a
// caller-supplied WHERE clause (SQL against the entries table, without the
// leading WHERE, using '?' placeholders) ordered by id ascending, and hydrates
// each one byte-faithfully. It is for filters that Query cannot express while
// still leaving reassembly to the store. An empty clause selects every entry.
func (s *Store) ListWhere(ctx context.Context, where string, args ...any) ([]model.Stored, error) {
	clause := ""
	if strings.TrimSpace(where) != "" {
		clause = " WHERE " + where
	}
	rows, err := s.db.QueryContext(ctx, s.d.rebind("SELECT "+entryColumns+" FROM entries"+clause+" ORDER BY id ASC"), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Stored
	for rows.Next() {
		st, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Load child rows only after the entry cursor is closed so a single-connection
	// (in-memory) store does not deadlock on a second concurrent query.
	rows.Close()
	for i := range out {
		if err := s.loadChildren(ctx, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Hydrate loads full, byte-faithful entries for the given ids, preserving the
// argument order and silently skipping ids that no longer exist. It is the
// reassembly half of the custom-SQL escape hatch: select ids however you like via
// DB(), then hand them here to rebuild ordered entries.
func (s *Store) Hydrate(ctx context.Context, ids ...int64) ([]model.Stored, error) {
	out := make([]model.Stored, 0, len(ids))
	for _, id := range ids {
		st, err := s.Get(ctx, id)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, nil
}
