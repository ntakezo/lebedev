package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"

	"github.com/ntakezo/lebedev/har"
	"github.com/ntakezo/lebedev/model"
)

// Query selects and orders stored entries. A zero-valued field imposes no
// constraint on that dimension. Entries are ordered by id — ascending (insertion
// order, the natural export order) when Ascending is set, newest-first otherwise.
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

// entryColumns lists the entries columns selected by every read, in scan order.
const entryColumns = `id, session, created_at, pageref, started_date_time, time, server_ip_address, connection, comment,
	req_method, req_url, req_http_version, req_headers_size, req_headers_compression, req_body_size, req_comment,
	has_post, post_mime_type, post_text, post_encoding, post_comment,
	resp_status, resp_status_text, resp_http_version, resp_redirect_url, resp_headers_size, resp_headers_compression, resp_body_size, resp_comment,
	content_size, content_compression, content_mime_type, content_text, content_encoding, content_comment,
	t_blocked, t_dns, t_connect, t_send, t_wait, t_receive, t_ssl, timings_comment,
	cache_comment, client_hello_hex, upstream_proto, http2`

// where builds the WHERE clause and its arguments from q's non-zero filters.
func (q Query) where() (string, []any) {
	var clauses []string
	var args []any
	if q.Session != "" {
		clauses = append(clauses, "session = ?")
		args = append(args, q.Session)
	}
	if q.Method != "" {
		clauses = append(clauses, "req_method = ?")
		args = append(args, q.Method)
	}
	if q.Status != 0 {
		clauses = append(clauses, "resp_status = ?")
		args = append(args, q.Status)
	}
	if q.MimeType != "" {
		clauses = append(clauses, "content_mime_type = ?")
		args = append(args, q.MimeType)
	}
	if q.URLGlob != "" {
		clauses = append(clauses, `req_url LIKE ? ESCAPE '\'`)
		args = append(args, globToLike(q.URLGlob))
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// List returns the entries matching q in the requested order.
func (s *Store) List(ctx context.Context, q Query) ([]model.Stored, error) {
	where, args := q.where()
	order := " ORDER BY id DESC"
	if q.Ascending {
		order = " ORDER BY id ASC"
	}
	limit := ""
	if q.Limit > 0 {
		limit = " LIMIT ?"
		args = append(args, q.Limit)
	}
	if q.Offset > 0 {
		limit += " OFFSET ?"
		args = append(args, q.Offset)
	}
	rows, err := s.db.QueryContext(ctx, s.d.rebind("SELECT "+entryColumns+" FROM entries"+where+order+limit), args...)
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
	// Child rows are loaded after the entry cursor is closed so a single-connection
	// (in-memory) store does not deadlock on a second concurrent query.
	rows.Close()
	for i := range out {
		if err := s.loadChildren(ctx, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Count returns how many entries match q, ignoring Limit/Offset.
func (s *Store) Count(ctx context.Context, q Query) (int, error) {
	where, args := q.where()
	var n int
	err := s.db.QueryRowContext(ctx, s.d.rebind("SELECT COUNT(*) FROM entries"+where), args...).Scan(&n)
	return n, err
}

// Get returns the single entry with the given id, or sql.ErrNoRows if absent.
func (s *Store) Get(ctx context.Context, id int64) (model.Stored, error) {
	row := s.db.QueryRowContext(ctx, s.d.rebind("SELECT "+entryColumns+" FROM entries WHERE id = ?"), id)
	st, err := scanEntry(row)
	if err != nil {
		return model.Stored{}, err
	}
	if err := s.loadChildren(ctx, &st); err != nil {
		return model.Stored{}, err
	}
	return st, nil
}

// Sessions returns the distinct session ids that have at least one entry.
func (s *Store) Sessions(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT DISTINCT session FROM entries ORDER BY session")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// GetLog returns the stored log-level metadata for a session. When no row exists
// it returns a zero Log with Version defaulted, so export always has a valid log.
func (s *Store) GetLog(ctx context.Context, session string) (model.Log, error) {
	row := s.db.QueryRowContext(ctx, s.d.rebind(`SELECT version, creator_name, creator_version, creator_comment,
		browser_name, browser_version, browser_comment, comment FROM logs WHERE session = ?`), session)
	var l model.Log
	var b har.Browser
	err := row.Scan(&l.Version, &l.Creator.Name, &l.Creator.Version, &l.Creator.Comment,
		&b.Name, &b.Version, &b.Comment, &l.Comment)
	if err == sql.ErrNoRows {
		return model.Log{Version: "1.3"}, nil
	}
	if err != nil {
		return model.Log{}, err
	}
	if b != (har.Browser{}) {
		l.Browser = &b
	}
	return l, nil
}

// scanRow is the read surface shared by *sql.Row and *sql.Rows.
type scanRow interface {
	Scan(dest ...any) error
}

// scanEntry reads one entries row into a Stored, leaving child collections to
// loadChildren. Nullable columns are read through sql.Null* and converted back to
// the pointer or zero values the HAR types expect.
func scanEntry(row scanRow) (model.Stored, error) {
	var st model.Stored
	e := &st.Entry
	var (
		createdAt                                    int64
		reqHeadersComp, respHeadersComp, contentComp sql.NullInt64
		hasPost                                      int
		post                                         har.PostData
		blocked, dns, connect, ssl                   sql.NullFloat64
		clientHello, upstreamProto, http2JSON        string
	)
	err := row.Scan(
		&st.ID, &st.Session, &createdAt, &e.Pageref, &e.StartedDateTime, &e.Time, &e.ServerIPAddress, &e.Connection, &e.Comment,
		&e.Request.Method, &e.Request.URL, &e.Request.HTTPVersion, &e.Request.HeadersSize, &reqHeadersComp, &e.Request.BodySize, &e.Request.Comment,
		&hasPost, &post.MimeType, &post.Text, &post.Encoding, &post.Comment,
		&e.Response.Status, &e.Response.StatusText, &e.Response.HTTPVersion, &e.Response.RedirectURL, &e.Response.HeadersSize, &respHeadersComp, &e.Response.BodySize, &e.Response.Comment,
		&e.Response.Content.Size, &contentComp, &e.Response.Content.MimeType, &e.Response.Content.Text, &e.Response.Content.Encoding, &e.Response.Content.Comment,
		&blocked, &dns, &connect, &e.Timings.Send, &e.Timings.Wait, &e.Timings.Receive, &ssl, &e.Timings.Comment,
		&e.Cache.Comment, &clientHello, &upstreamProto, &http2JSON,
	)
	if err != nil {
		return model.Stored{}, err
	}
	e.Request.HeadersCompression = intPtr(reqHeadersComp)
	e.Response.HeadersCompression = intPtr(respHeadersComp)
	e.Response.Content.Compression = intPtr(contentComp)
	e.Timings.Blocked = floatPtr(blocked)
	e.Timings.DNS = floatPtr(dns)
	e.Timings.Connect = floatPtr(connect)
	e.Timings.SSL = floatPtr(ssl)
	if hasPost == 1 {
		e.Request.PostData = &post
	}
	if lb := buildLebedev(st.Session, clientHello, upstreamProto, http2JSON); lb != nil {
		e.Lebedev = lb
	}
	return st, nil
}

func buildLebedev(session, clientHello, upstreamProto, http2JSON string) *model.Lebedev {
	lb := model.Lebedev{Session: session, ClientHelloHex: clientHello, UpstreamProto: upstreamProto}
	if http2JSON != "" {
		var h model.HTTP2
		if err := json.Unmarshal([]byte(http2JSON), &h); err == nil {
			lb.HTTP2 = &h
		}
	}
	if lb.ClientHelloHex == "" && lb.UpstreamProto == "" && lb.HTTP2 == nil {
		return nil
	}
	return &lb
}

// loadChildren fills the ordered collections hanging off an entry. Every list is
// ordered by seq so header, cookie, and parameter order is reproduced exactly.
func (s *Store) loadChildren(ctx context.Context, st *model.Stored) error {
	e := &st.Entry
	var err error
	if e.Request.Headers, err = s.loadHeaders(ctx, st.ID, "request"); err != nil {
		return err
	}
	if e.Response.Headers, err = s.loadHeaders(ctx, st.ID, "response"); err != nil {
		return err
	}
	if e.Request.Cookies, err = s.loadCookies(ctx, st.ID, "request"); err != nil {
		return err
	}
	if e.Response.Cookies, err = s.loadCookies(ctx, st.ID, "response"); err != nil {
		return err
	}
	if e.Request.QueryString, err = s.loadQueryParams(ctx, st.ID); err != nil {
		return err
	}
	if e.Request.PostData != nil {
		if e.Request.PostData.Params, err = s.loadPostParams(ctx, st.ID); err != nil {
			return err
		}
	}
	if e.Cache.BeforeRequest, err = s.loadCacheState(ctx, st.ID, "before"); err != nil {
		return err
	}
	if e.Cache.AfterRequest, err = s.loadCacheState(ctx, st.ID, "after"); err != nil {
		return err
	}
	return nil
}

func (s *Store) loadHeaders(ctx context.Context, id int64, kind string) ([]har.NVP, error) {
	rows, err := s.db.QueryContext(ctx, s.d.rebind(`SELECT name, value, comment FROM headers WHERE entry_id = ? AND kind = ? ORDER BY seq`), id, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []har.NVP{}
	for rows.Next() {
		var h har.NVP
		if err := rows.Scan(&h.Name, &h.Value, &h.Comment); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) loadCookies(ctx context.Context, id int64, kind string) ([]har.Cookie, error) {
	rows, err := s.db.QueryContext(ctx, s.d.rebind(`SELECT name, value, path, domain, expires, http_only, secure, comment
		FROM cookies WHERE entry_id = ? AND kind = ? ORDER BY seq`), id, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []har.Cookie{}
	for rows.Next() {
		var c har.Cookie
		var httpOnly, secure sql.NullInt64
		if err := rows.Scan(&c.Name, &c.Value, &c.Path, &c.Domain, &c.Expires, &httpOnly, &secure, &c.Comment); err != nil {
			return nil, err
		}
		c.HTTPOnly = boolPtr(httpOnly)
		c.Secure = boolPtr(secure)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) loadQueryParams(ctx context.Context, id int64) ([]har.NVP, error) {
	rows, err := s.db.QueryContext(ctx, s.d.rebind(`SELECT name, value, comment FROM query_params WHERE entry_id = ? ORDER BY seq`), id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []har.NVP{}
	for rows.Next() {
		var p har.NVP
		if err := rows.Scan(&p.Name, &p.Value, &p.Comment); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) loadPostParams(ctx context.Context, id int64) ([]har.Param, error) {
	rows, err := s.db.QueryContext(ctx, s.d.rebind(`SELECT name, value, file_name, content_type, encoding, comment
		FROM post_params WHERE entry_id = ? ORDER BY seq`), id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []har.Param
	for rows.Next() {
		var p har.Param
		if err := rows.Scan(&p.Name, &p.Value, &p.FileName, &p.ContentType, &p.Encoding, &p.Comment); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) loadCacheState(ctx context.Context, id int64, kind string) (*har.CacheState, error) {
	row := s.db.QueryRowContext(ctx, s.d.rebind(`SELECT expires, last_access, etag, hit_count, comment
		FROM cache_states WHERE entry_id = ? AND kind = ?`), id, kind)
	var c har.CacheState
	err := row.Scan(&c.Expires, &c.LastAccess, &c.ETag, &c.HitCount, &c.Comment)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// globToLike converts a '*' glob into a LIKE pattern, escaping the LIKE
// metacharacters %, _ and the escape char itself so only '*' is a wildcard.
func globToLike(glob string) string {
	var b strings.Builder
	for _, r := range glob {
		switch r {
		case '*':
			b.WriteByte('%')
		case '%', '_', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
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
