// Package sqlite implements repository.Repository over SQLite. It owns its
// schema: every Open applies the embedded migrations, so a caller brings a
// database file but never authors DDL.
//
// The layout is the HAR 1.3 model shaped for SQLite (see migrations) — one row
// per ordered child so header and cookie order survive, one shared row per TLS
// connection instead of a fingerprint copied onto every entry, and foreign keys
// with ON DELETE CASCADE so deleting a session or an entry is a single
// statement. Reads reassemble exactly what was written.
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/ntakezo/lebedev/repository"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Repository is a SQLite-backed capture store. It satisfies
// repository.Repository and is safe for concurrent use. The zero value is not
// usable; construct one with Open or OpenDB.
type Repository struct {
	db     *sql.DB
	ownsDB bool
	now    func() time.Time
}

// compile-time check that the implementation still satisfies the contract.
var _ repository.Repository = (*Repository)(nil)

// Open opens the SQLite database at path and applies the schema. An empty path
// (or ":memory:") opens a private in-memory database that is discarded on Close.
// The returned Repository owns the handle.
func Open(path string) (*Repository, error) {
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("sqlite: open %q: %w", path, err)
	}
	// SQLite serializes writers, and an in-memory database is scoped to its
	// connection, so a single connection both keeps the database addressable
	// across queries and avoids "database is locked" under concurrent captures.
	db.SetMaxOpenConns(1)
	r, err := newRepository(db, true)
	if err != nil {
		db.Close()
		return nil, err
	}
	return r, nil
}

// OpenDB adapts a handle the caller already holds, applying the schema before
// returning. The caller keeps ownership: Close does not touch the handle, so the
// same database can back other application tables. The handle must have foreign
// keys enabled, which is what makes deletes cascade.
func OpenDB(db *sql.DB) (*Repository, error) {
	return newRepository(db, false)
}

func newRepository(db *sql.DB, ownsDB bool) (*Repository, error) {
	r := &Repository{db: db, ownsDB: ownsDB, now: time.Now}
	if err := r.migrate(context.Background()); err != nil {
		return nil, err
	}
	return r, nil
}

// dsn builds the connection string, pinning the pragmas the schema depends on:
// foreign keys (ownership and cascading deletes), WAL plus NORMAL sync (readers
// never block on the capture writing), and a busy timeout so a contended write
// waits instead of failing.
func dsn(path string) string {
	if path == "" || path == ":memory:" || path == "memory" {
		path = ":memory:"
	}
	pragmas := []string{
		"_pragma=foreign_keys(1)",
		"_pragma=busy_timeout(5000)",
		"_pragma=synchronous(1)",
	}
	if path != ":memory:" {
		pragmas = append(pragmas, "_pragma=journal_mode(WAL)")
	}
	return "file:" + url.PathEscape(path) + "?" + strings.Join(pragmas, "&")
}

// DB exposes the underlying handle for reads the contract does not cover. Treat
// it as read-only: the schema belongs to this package.
func (r *Repository) DB() *sql.DB { return r.db }

// Close releases the handle opened by Open. For a Repository built with OpenDB it
// is a no-op, since the caller owns the handle.
func (r *Repository) Close() error {
	if !r.ownsDB {
		return nil
	}
	return r.db.Close()
}

// migrate applies every embedded migration that has not run yet, in filename
// order, each in its own transaction. Applied versions are recorded so reopening
// a database is a no-op.
func (r *Repository) migrate(ctx context.Context) error {
	const ddl = `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    TEXT    PRIMARY KEY,
		applied_at INTEGER NOT NULL
	) STRICT`
	if _, err := r.db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("sqlite: migration table: %w", err)
	}

	names, err := migrationNames()
	if err != nil {
		return err
	}
	for _, name := range names {
		applied, err := r.migrationApplied(ctx, name)
		if err != nil {
			return err
		}
		if applied {
			continue
		}
		body, err := migrations.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("sqlite: read migration %s: %w", name, err)
		}
		if err := r.applyMigration(ctx, name, string(body)); err != nil {
			return err
		}
	}
	return nil
}

func migrationNames() ([]string, error) {
	entries, err := fs.ReadDir(migrations, "migrations")
	if err != nil {
		return nil, fmt.Errorf("sqlite: read migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func (r *Repository) migrationApplied(ctx context.Context, name string) (bool, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, name).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("sqlite: check migration %s: %w", name, err)
	}
	return n > 0, nil
}

func (r *Repository) applyMigration(ctx context.Context, name, body string) error {
	err := r.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, body); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
			name, r.now().UnixMilli())
		return err
	})
	if err != nil {
		return fmt.Errorf("sqlite: apply migration %s: %w", name, err)
	}
	return nil
}

// tx runs fn inside a transaction, committing when it returns nil and rolling
// back otherwise, so a partially written entry is never visible to a reader.
func (r *Repository) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// notFound maps a missing row onto the contract's error, leaving every other
// failure to surface as itself.
func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return repository.ErrNotFound
	}
	return err
}

func nullInt(p *int) any {
	if p == nil {
		return nil
	}
	return int64(*p)
}

func nullFloat(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}

func nullBool(p *bool) any {
	if p == nil {
		return nil
	}
	if *p {
		return int64(1)
	}
	return int64(0)
}

func intPtr(n sql.NullInt64) *int {
	if !n.Valid {
		return nil
	}
	v := int(n.Int64)
	return &v
}

func floatPtr(n sql.NullFloat64) *float64 {
	if !n.Valid {
		return nil
	}
	return &n.Float64
}

func boolPtr(n sql.NullInt64) *bool {
	if !n.Valid {
		return nil
	}
	v := n.Int64 != 0
	return &v
}
