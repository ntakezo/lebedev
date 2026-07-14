package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// Store is a SQL-backed collection of captured HAR entries. It is safe for
// concurrent use. The zero value is not usable; construct one with Open.
//
// Faithfulness contract: the store persists and returns every field exactly as
// given — header and cookie order (via a seq column), whitespace, URLs, form
// fields, and bodies are round-tripped verbatim. Any transformation of an
// observation (base64-encoding a binary body, deriving a status text, parsing a
// Cookie header into cookie objects) is the caller's business logic, performed
// before Insert; the SQL layer never alters the bytes it is handed.
type Store struct {
	db *sql.DB
	d  dialect
}

// Open connects to the store described by dsn and ensures the schema exists.
// Recognized dsn forms:
//
//	""                     in-memory SQLite (default; discarded on Close)
//	"memory" / ":memory:"  in-memory SQLite
//	"sqlite:PATH"          on-disk SQLite at PATH
//	"postgres://…"         PostgreSQL (also "postgresql://…")
//	anything else          treated as an on-disk SQLite path
//
// The in-memory store is pinned to a single connection so every query sees the
// same database.
func Open(dsn string) (*Store, error) {
	d, conn := resolveDSN(dsn)
	db, err := sql.Open(d.driver, conn)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", d.name, err)
	}
	// SQLite serializes writers, so a single connection both keeps an in-memory
	// database addressable across queries and avoids "database is locked" when
	// concurrent captures write to a file. PostgreSQL keeps its pool.
	if d.name == "sqlite" {
		db.SetMaxOpenConns(1)
	}
	s := &Store{db: db, d: d}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func resolveDSN(dsn string) (d dialect, conn string) {
	switch {
	case dsn == "" || dsn == "memory" || dsn == ":memory:":
		return sqliteDialect, ":memory:"
	case strings.HasPrefix(dsn, "postgres://"), strings.HasPrefix(dsn, "postgresql://"):
		return postgresDialect, dsn
	case strings.HasPrefix(dsn, "sqlite:"):
		return sqliteDialect, strings.TrimPrefix(dsn, "sqlite:")
	default:
		return sqliteDialect, dsn
	}
}

// Close releases the underlying database handle. For an in-memory store this
// discards all captured data.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	for _, stmt := range s.d.schema() {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return nil
}

// PutLog records or updates the log-level metadata (creator, browser, comment)
// for a session. Entries are stored separately via Insert.
func (s *Store) PutLog(ctx context.Context, session string, log Log) error {
	version := log.Version
	if version == "" {
		version = "1.3"
	}
	var b Browser
	if log.Browser != nil {
		b = *log.Browser
	}
	q := s.d.rebind(`INSERT INTO logs
		(session, version, creator_name, creator_version, creator_comment,
		 browser_name, browser_version, browser_comment, comment)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (session) DO UPDATE SET
		 version=excluded.version, creator_name=excluded.creator_name,
		 creator_version=excluded.creator_version, creator_comment=excluded.creator_comment,
		 browser_name=excluded.browser_name, browser_version=excluded.browser_version,
		 browser_comment=excluded.browser_comment, comment=excluded.comment`)
	_, err := s.db.ExecContext(ctx, q, session, version,
		log.Creator.Name, log.Creator.Version, log.Creator.Comment,
		b.Name, b.Version, b.Comment, log.Comment)
	return err
}

// Insert stores one entry under session, stamped with insertion time at (Unix
// milliseconds, used only for internal ordering), and returns its assigned id.
// The entry and its ordered child rows are written in a single transaction so a
// reader never sees a partially materialized entry.
func (s *Store) Insert(ctx context.Context, session string, e Entry, at int64) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	id, err := s.insertEntry(ctx, tx, session, e, at)
	if err != nil {
		tx.Rollback()
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

func (s *Store) insertEntry(ctx context.Context, tx *sql.Tx, session string, e Entry, at int64) (int64, error) {
	var post PostData
	hasPost := 0
	if e.Request.PostData != nil {
		post = *e.Request.PostData
		hasPost = 1
	}
	http2JSON := ""
	var lb Lebedev
	if e.Lebedev != nil {
		lb = *e.Lebedev
		if lb.HTTP2 != nil {
			b, _ := json.Marshal(lb.HTTP2)
			http2JSON = string(b)
		}
	}

	const cols = `INSERT INTO entries (
		session, created_at, pageref, started_date_time, time, server_ip_address, connection, comment,
		req_method, req_url, req_http_version, req_headers_size, req_headers_compression, req_body_size, req_comment,
		has_post, post_mime_type, post_text, post_encoding, post_comment,
		resp_status, resp_status_text, resp_http_version, resp_redirect_url, resp_headers_size, resp_headers_compression, resp_body_size, resp_comment,
		content_size, content_compression, content_mime_type, content_text, content_encoding, content_comment,
		t_blocked, t_dns, t_connect, t_send, t_wait, t_receive, t_ssl, timings_comment,
		cache_comment, client_hello_hex, upstream_proto, http2)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	args := []any{
		session, at, e.Pageref, e.StartedDateTime, e.Time, e.ServerIPAddress, e.Connection, e.Comment,
		e.Request.Method, e.Request.URL, e.Request.HTTPVersion, e.Request.HeadersSize, nullInt(e.Request.HeadersCompression), e.Request.BodySize, e.Request.Comment,
		hasPost, post.MimeType, post.Text, post.Encoding, post.Comment,
		e.Response.Status, e.Response.StatusText, e.Response.HTTPVersion, e.Response.RedirectURL, e.Response.HeadersSize, nullInt(e.Response.HeadersCompression), e.Response.BodySize, e.Response.Comment,
		e.Response.Content.Size, nullInt(e.Response.Content.Compression), e.Response.Content.MimeType, e.Response.Content.Text, e.Response.Content.Encoding, e.Response.Content.Comment,
		nullFloat(e.Timings.Blocked), nullFloat(e.Timings.DNS), nullFloat(e.Timings.Connect), e.Timings.Send, e.Timings.Wait, e.Timings.Receive, nullFloat(e.Timings.SSL), e.Timings.Comment,
		e.Cache.Comment, lb.ClientHelloHex, lb.UpstreamProto, http2JSON,
	}

	id, err := s.execInsert(ctx, tx, cols, args...)
	if err != nil {
		return 0, err
	}

	if err := s.insertHeaders(ctx, tx, id, "request", e.Request.Headers); err != nil {
		return 0, err
	}
	if err := s.insertHeaders(ctx, tx, id, "response", e.Response.Headers); err != nil {
		return 0, err
	}
	if err := s.insertCookies(ctx, tx, id, "request", e.Request.Cookies); err != nil {
		return 0, err
	}
	if err := s.insertCookies(ctx, tx, id, "response", e.Response.Cookies); err != nil {
		return 0, err
	}
	if err := s.insertQueryParams(ctx, tx, id, e.Request.QueryString); err != nil {
		return 0, err
	}
	if hasPost == 1 {
		if err := s.insertPostParams(ctx, tx, id, post.Params); err != nil {
			return 0, err
		}
	}
	if err := s.insertCacheState(ctx, tx, id, "before", e.Cache.BeforeRequest); err != nil {
		return 0, err
	}
	if err := s.insertCacheState(ctx, tx, id, "after", e.Cache.AfterRequest); err != nil {
		return 0, err
	}
	return id, nil
}

// execInsert runs an INSERT and returns the new row id, bridging the SQLite
// (LastInsertId) and PostgreSQL (RETURNING id) conventions.
func (s *Store) execInsert(ctx context.Context, tx *sql.Tx, query string, args ...any) (int64, error) {
	if s.d.returningID {
		var id int64
		err := tx.QueryRowContext(ctx, s.d.rebind(query+" RETURNING id"), args...).Scan(&id)
		return id, err
	}
	res, err := tx.ExecContext(ctx, s.d.rebind(query), args...)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) insertHeaders(ctx context.Context, tx *sql.Tx, id int64, kind string, hs []NVP) error {
	q := s.d.rebind(`INSERT INTO headers (entry_id, kind, seq, name, value, comment) VALUES (?, ?, ?, ?, ?, ?)`)
	for i, h := range hs {
		if _, err := tx.ExecContext(ctx, q, id, kind, i, h.Name, h.Value, h.Comment); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) insertCookies(ctx context.Context, tx *sql.Tx, id int64, kind string, cs []Cookie) error {
	q := s.d.rebind(`INSERT INTO cookies (entry_id, kind, seq, name, value, path, domain, expires, http_only, secure, comment)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	for i, c := range cs {
		if _, err := tx.ExecContext(ctx, q, id, kind, i, c.Name, c.Value, c.Path, c.Domain, c.Expires, nullBool(c.HTTPOnly), nullBool(c.Secure), c.Comment); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) insertQueryParams(ctx context.Context, tx *sql.Tx, id int64, ps []NVP) error {
	q := s.d.rebind(`INSERT INTO query_params (entry_id, seq, name, value, comment) VALUES (?, ?, ?, ?, ?)`)
	for i, p := range ps {
		if _, err := tx.ExecContext(ctx, q, id, i, p.Name, p.Value, p.Comment); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) insertPostParams(ctx context.Context, tx *sql.Tx, id int64, ps []Param) error {
	q := s.d.rebind(`INSERT INTO post_params (entry_id, seq, name, value, file_name, content_type, encoding, comment)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	for i, p := range ps {
		if _, err := tx.ExecContext(ctx, q, id, i, p.Name, p.Value, p.FileName, p.ContentType, p.Encoding, p.Comment); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) insertCacheState(ctx context.Context, tx *sql.Tx, id int64, kind string, cs *CacheState) error {
	if cs == nil {
		return nil
	}
	q := s.d.rebind(`INSERT INTO cache_states (entry_id, kind, expires, last_access, etag, hit_count, comment)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	_, err := tx.ExecContext(ctx, q, id, kind, cs.Expires, cs.LastAccess, cs.ETag, cs.HitCount, cs.Comment)
	return err
}

func nullInt(p *int) any {
	if p == nil {
		return nil
	}
	return *p
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
		return 1
	}
	return 0
}
