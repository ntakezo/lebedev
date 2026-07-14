// Package lebedev is the public, read-only interface to a lebedev capture store.
// A consumer imports it to query stored sessions byte-faithfully — header and
// cookie order, whitespace, bodies, and the TLS/HTTP2 fingerprint are returned
// exactly as captured — without depending on lebedev's internal packages.
//
// The store owns its schema. Open (from a DSN) or OpenDB (over a handle the
// consumer already has) both run the idempotent migration, so a consumer brings
// a database but never authors DDL or manages migrations for these tables.
//
// Reads come in two grades. The standard queries — Sessions, Session, Entry —
// cover the common cases directly. When those are too coarse, three escape
// hatches of increasing rawness keep byte-faithful reassembly the store's job,
// not the caller's: List/Count take a structured Query; Where takes a raw SQL
// predicate against the entries table; and DB together with Hydrate lets a caller
// select entry ids with arbitrary SQL and hand them back to be rebuilt in full.
//
// Entry and Stored are defined in package model; the strict HAR 1.3 types they
// build on are in package har.
package lebedev

import (
	"context"
	"database/sql"
	"errors"
	"io"

	"github.com/ntakezo/lebedev/internal/store"
	"github.com/ntakezo/lebedev/model"
)

// ErrNotFound is returned by Session and Entry when the named session or entry
// does not exist, or when an entry exists but under a different session.
var ErrNotFound = errors.New("lebedev: not found")

// Column names for the entries table, for building Where predicates and custom
// SQL. The schema is owned by lebedev and these names are part of its contract.
const (
	ColID        = "id"
	ColSession   = "session"
	ColCreatedAt = "created_at"
	ColMethod    = "req_method"
	ColURL       = "req_url"
	ColStatus    = "resp_status"
	ColMimeType  = "content_mime_type"
)

// Reader is a read-only handle on a capture store. It is safe for concurrent use.
type Reader struct {
	store  *store.Store
	ownsDB bool
}

// Open connects to the store described by dsn and ensures the schema exists. The
// dsn forms match the lebedev binary:
//
//	""                     in-memory SQLite (discarded on Close)
//	"sqlite:PATH"          on-disk SQLite at PATH
//	"postgres://…"         PostgreSQL
//	anything else          treated as an on-disk SQLite path
//
// The returned Reader owns the connection; Close releases it.
func Open(dsn string) (*Reader, error) {
	st, err := store.Open(dsn)
	if err != nil {
		return nil, err
	}
	return &Reader{store: st, ownsDB: true}, nil
}

// OpenDB wraps a database handle the consumer already holds, running the
// idempotent schema migration before returning. driver names the dialect:
// "sqlite" or "postgres". The consumer retains ownership of db — Close does not
// touch it — so the same handle can back other application tables.
func OpenDB(db *sql.DB, driver string) (*Reader, error) {
	st, err := store.OpenDB(db, driver)
	if err != nil {
		return nil, err
	}
	return &Reader{store: st, ownsDB: false}, nil
}

// Close releases the connection opened by Open. For a Reader built with OpenDB it
// is a no-op, since the caller owns the handle.
func (r *Reader) Close() error {
	if !r.ownsDB {
		return nil
	}
	return r.store.Close()
}

// SessionInfo summarizes one stored session.
type SessionInfo struct {
	Name    string
	Entries int
}

// Session is one stored session: its log-level metadata and its entries in
// insertion (export) order, each tagged with its store id. Meta.Entries is left
// empty — use Entries, which carries the ids needed for Entry lookups; to emit a
// full HAR document use Export.
type Session struct {
	Name    string
	Meta    model.Log
	Entries []model.Stored
}

// Sessions lists every stored session that has at least one entry, with its entry
// count, ordered by name.
func (r *Reader) Sessions(ctx context.Context) ([]SessionInfo, error) {
	infos, err := r.store.SessionInfos(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]SessionInfo, len(infos))
	for i, si := range infos {
		out[i] = SessionInfo{Name: si.Session, Entries: si.Entries}
	}
	return out, nil
}

// Session returns the session named name (a session's id and name are the same
// string), with its metadata and its entries in insertion order. It returns
// ErrNotFound when no entry is stored under name.
func (r *Reader) Session(ctx context.Context, name string) (*Session, error) {
	ok, err := r.store.HasSession(ctx, name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotFound
	}
	meta, err := r.store.GetLog(ctx, name)
	if err != nil {
		return nil, err
	}
	entries, err := r.store.List(ctx, store.Query{Session: name, Ascending: true})
	if err != nil {
		return nil, err
	}
	return &Session{Name: name, Meta: meta, Entries: entries}, nil
}

// Entry returns the single entry identified by session and id, byte-faithful. It
// returns ErrNotFound when no such entry exists, or when the entry exists but
// belongs to a different session — so the (session, id) pair is authoritative.
func (r *Reader) Entry(ctx context.Context, session string, id int64) (model.Stored, error) {
	st, err := r.store.Get(ctx, id)
	if err == sql.ErrNoRows {
		return model.Stored{}, ErrNotFound
	}
	if err != nil {
		return model.Stored{}, err
	}
	if st.Session != session {
		return model.Stored{}, ErrNotFound
	}
	return st, nil
}

// Query selects and orders stored entries by structured filters. A zero-valued
// field imposes no constraint. Entries are ordered by id — ascending (insertion
// order) when Ascending is set, newest-first otherwise.
type Query struct {
	Session   string
	Method    string
	URLGlob   string // glob with '*' matching any run of characters
	Status    int
	MimeType  string
	Limit     int
	Offset    int
	Ascending bool
}

func (q Query) toStore() store.Query {
	return store.Query{
		Session:   q.Session,
		Method:    q.Method,
		URLGlob:   q.URLGlob,
		Status:    q.Status,
		MimeType:  q.MimeType,
		Limit:     q.Limit,
		Offset:    q.Offset,
		Ascending: q.Ascending,
	}
}

// List returns the entries matching q, byte-faithful, in the requested order.
func (r *Reader) List(ctx context.Context, q Query) ([]model.Stored, error) {
	return r.store.List(ctx, q.toStore())
}

// Count returns how many entries match q, ignoring Limit and Offset.
func (r *Reader) Count(ctx context.Context, q Query) (int, error) {
	return r.store.Count(ctx, q.toStore())
}

// Where is the raw-predicate escape hatch: whereSQL is a SQL condition against
// the entries table (without the leading WHERE) using '?' placeholders, which are
// rebound to the store's dialect. Matching entries are hydrated byte-faithfully
// and ordered by id ascending. Use the Col* constants to name columns. An empty
// predicate selects every entry.
func (r *Reader) Where(ctx context.Context, whereSQL string, args ...any) ([]model.Stored, error) {
	return r.store.ListWhere(ctx, whereSQL, args...)
}

// DB exposes the underlying handle for fully custom SQL — for example selecting
// entry ids by joining the child tables. Reassemble any ids it yields with
// Hydrate rather than reading the entry columns by hand, so byte-faithfulness is
// preserved. Treat the handle as read-only; the schema belongs to lebedev.
func (r *Reader) DB() *sql.DB { return r.store.DB() }

// Dialect reports the SQL dialect ("sqlite" or "postgres"), so custom SQL run
// through DB can pick the right placeholder style. Rebind converts '?' portably.
func (r *Reader) Dialect() string { return r.store.DialectName() }

// Rebind rewrites '?' placeholders in query into the store's dialect form.
func (r *Reader) Rebind(query string) string { return r.store.Rebind(query) }

// Hydrate rebuilds full, byte-faithful entries for the given ids, preserving
// argument order and skipping ids that no longer exist. Pair it with DB to run
// arbitrary id-selecting SQL and get complete entries back.
func (r *Reader) Hydrate(ctx context.Context, ids ...int64) ([]model.Stored, error) {
	return r.store.Hydrate(ctx, ids...)
}

// Export writes the entries matching q as a single HAR 1.3 document to w, in
// insertion order, with the session's log metadata.
func (r *Reader) Export(ctx context.Context, q Query, w io.Writer) error {
	return r.store.Export(ctx, q.toStore(), w)
}
