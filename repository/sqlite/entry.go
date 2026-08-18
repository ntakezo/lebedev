package sqlite

import (
	"context"
	"database/sql"

	"github.com/ntakezo/lebedev/har"
	"github.com/ntakezo/lebedev/model"
	"github.com/ntakezo/lebedev/repository"
)

// entryColumns lists the entries columns every full read selects, in scan order.
const entryColumns = `id, session_id, connection_id, pageref, started_date_time, time,
	server_ip_address, connection, comment,
	req_method, req_url, req_http_version, req_headers_size, req_headers_compression, req_body_size, req_comment,
	has_post, post_mime_type, post_text, post_encoding, post_comment,
	resp_status, resp_status_text, resp_http_version, resp_redirect_url, resp_headers_size, resp_headers_compression, resp_body_size, resp_comment,
	content_size, content_compression, content_mime_type, content_text, content_encoding, content_comment,
	t_blocked, t_dns, t_connect, t_send, t_wait, t_receive, t_ssl, timings_comment,
	cache_comment`

// CreateEntry records one transaction under session, attributed to the
// connection it was captured over (0 when none was recorded), and returns its
// id. The entry and its ordered child rows — headers, cookies, query and post
// parameters, cache states — are written in one transaction, so a reader never
// sees a half-materialized entry. Every value is stored as handed over; encoding
// a body or deriving a status text is the caller's business, done before this
// call.
func (r *Repository) CreateEntry(ctx context.Context, session string, connection int64, e model.Entry) (int64, error) {
	var id int64
	err := r.tx(ctx, func(tx *sql.Tx) error {
		sid, err := sessionID(ctx, tx, session)
		if err != nil {
			return err
		}
		conn, err := connectionRef(ctx, tx, sid, connection)
		if err != nil {
			return err
		}
		if id, err = r.insertEntry(ctx, tx, sid, conn, e); err != nil {
			return err
		}
		return insertChildren(ctx, tx, id, e)
	})
	if err != nil {
		return 0, err
	}
	return id, nil
}

// Entry returns one stored entry in full, byte-faithful, with its _lebedev field
// rebuilt from the connection it was captured over.
func (r *Repository) Entry(ctx context.Context, id int64) (model.Stored, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+entryColumns+` FROM entries WHERE id = ?`, id)
	st, sid, conn, err := scanEntry(row)
	if err != nil {
		return model.Stored{}, notFound(err)
	}
	if err := r.db.QueryRowContext(ctx, `SELECT name FROM sessions WHERE id = ?`, sid).Scan(&st.Session); err != nil {
		return model.Stored{}, notFound(err)
	}
	c, err := r.connectionFor(ctx, conn)
	if err != nil {
		return model.Stored{}, err
	}
	c.Session = st.Session
	st.Connection = c.ID
	st.Entry.Lebedev = c.Lebedev()
	if err := r.loadChildren(ctx, &st); err != nil {
		return model.Stored{}, err
	}
	return st, nil
}

// DeleteEntry removes one entry and its child rows, which cascade. The
// connection it referenced stays, since the other entries captured over that
// connection still need it.
func (r *Repository) DeleteEntry(ctx context.Context, id int64) error {
	return r.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM entries WHERE id = ?`, id)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

// connectionRef validates the connection an entry claims to have been captured
// over, returning the value to store: NULL for 0, the id itself when it belongs
// to the same session. A connection from another session is rejected rather than
// silently dropped, since it would misattribute the entry's fingerprint.
func connectionRef(ctx context.Context, tx *sql.Tx, sessionID, connection int64) (any, error) {
	if connection == 0 {
		return nil, nil
	}
	var owner int64
	if err := tx.QueryRowContext(ctx, `SELECT session_id FROM connections WHERE id = ?`, connection).Scan(&owner); err != nil {
		return nil, notFound(err)
	}
	if owner != sessionID {
		return nil, repository.ErrNotFound
	}
	return connection, nil
}

func (r *Repository) insertEntry(ctx context.Context, tx *sql.Tx, sessionID int64, connection any, e model.Entry) (int64, error) {
	var post har.PostData
	hasPost := int64(0)
	if e.Request.PostData != nil {
		post = *e.Request.PostData
		hasPost = 1
	}

	res, err := tx.ExecContext(ctx, `INSERT INTO entries (
		session_id, connection_id, created_at, pageref, started_date_time, time, server_ip_address, connection, comment,
		req_method, req_url, req_http_version, req_headers_size, req_headers_compression, req_body_size, req_comment,
		has_post, post_mime_type, post_text, post_encoding, post_comment,
		resp_status, resp_status_text, resp_http_version, resp_redirect_url, resp_headers_size, resp_headers_compression, resp_body_size, resp_comment,
		content_size, content_compression, content_mime_type, content_text, content_encoding, content_comment,
		t_blocked, t_dns, t_connect, t_send, t_wait, t_receive, t_ssl, timings_comment,
		cache_comment)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sessionID, connection, r.now().UnixMilli(), e.Pageref, e.StartedDateTime, e.Time, e.ServerIPAddress, e.Connection, e.Comment,
		e.Request.Method, e.Request.URL, e.Request.HTTPVersion, int64(e.Request.HeadersSize), nullInt(e.Request.HeadersCompression), int64(e.Request.BodySize), e.Request.Comment,
		hasPost, post.MimeType, post.Text, post.Encoding, post.Comment,
		int64(e.Response.Status), e.Response.StatusText, e.Response.HTTPVersion, e.Response.RedirectURL, int64(e.Response.HeadersSize), nullInt(e.Response.HeadersCompression), int64(e.Response.BodySize), e.Response.Comment,
		int64(e.Response.Content.Size), nullInt(e.Response.Content.Compression), e.Response.Content.MimeType, e.Response.Content.Text, e.Response.Content.Encoding, e.Response.Content.Comment,
		nullFloat(e.Timings.Blocked), nullFloat(e.Timings.DNS), nullFloat(e.Timings.Connect), e.Timings.Send, e.Timings.Wait, e.Timings.Receive, nullFloat(e.Timings.SSL), e.Timings.Comment,
		e.Cache.Comment)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// insertChildren writes the ordered lists hanging off an entry, each row stamped
// with its position so the read reproduces the captured order exactly.
func insertChildren(ctx context.Context, tx *sql.Tx, id int64, e model.Entry) error {
	if err := insertHeaders(ctx, tx, id, "request", e.Request.Headers); err != nil {
		return err
	}
	if err := insertHeaders(ctx, tx, id, "response", e.Response.Headers); err != nil {
		return err
	}
	if err := insertCookies(ctx, tx, id, "request", e.Request.Cookies); err != nil {
		return err
	}
	if err := insertCookies(ctx, tx, id, "response", e.Response.Cookies); err != nil {
		return err
	}
	if err := insertQueryParams(ctx, tx, id, e.Request.QueryString); err != nil {
		return err
	}
	if e.Request.PostData != nil {
		if err := insertPostParams(ctx, tx, id, e.Request.PostData.Params); err != nil {
			return err
		}
	}
	if err := insertCacheState(ctx, tx, id, "before", e.Cache.BeforeRequest); err != nil {
		return err
	}
	return insertCacheState(ctx, tx, id, "after", e.Cache.AfterRequest)
}

func insertHeaders(ctx context.Context, tx *sql.Tx, id int64, kind string, hs []har.NVP) error {
	for i, h := range hs {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO headers (entry_id, kind, seq, name, value, comment) VALUES (?, ?, ?, ?, ?, ?)`,
			id, kind, int64(i), h.Name, h.Value, h.Comment)
		if err != nil {
			return err
		}
	}
	return nil
}

func insertCookies(ctx context.Context, tx *sql.Tx, id int64, kind string, cs []har.Cookie) error {
	for i, c := range cs {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO cookies (entry_id, kind, seq, name, value, path, domain, expires, http_only, secure, comment)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, kind, int64(i), c.Name, c.Value, c.Path, c.Domain, c.Expires,
			nullBool(c.HTTPOnly), nullBool(c.Secure), c.Comment)
		if err != nil {
			return err
		}
	}
	return nil
}

func insertQueryParams(ctx context.Context, tx *sql.Tx, id int64, ps []har.NVP) error {
	for i, p := range ps {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO query_params (entry_id, seq, name, value, comment) VALUES (?, ?, ?, ?, ?)`,
			id, int64(i), p.Name, p.Value, p.Comment)
		if err != nil {
			return err
		}
	}
	return nil
}

func insertPostParams(ctx context.Context, tx *sql.Tx, id int64, ps []har.Param) error {
	for i, p := range ps {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO post_params (entry_id, seq, name, value, file_name, content_type, encoding, comment)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			id, int64(i), p.Name, p.Value, p.FileName, p.ContentType, p.Encoding, p.Comment)
		if err != nil {
			return err
		}
	}
	return nil
}

func insertCacheState(ctx context.Context, tx *sql.Tx, id int64, kind string, cs *har.CacheState) error {
	if cs == nil {
		return nil
	}
	_, err := tx.ExecContext(ctx,
		`INSERT INTO cache_states (entry_id, kind, expires, last_access, etag, hit_count, comment)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, kind, cs.Expires, cs.LastAccess, cs.ETag, int64(cs.HitCount), cs.Comment)
	return err
}

// scanEntry reads one entries row into a Stored, returning the owning session id
// and connection reference alongside it. Nullable columns come back through
// sql.Null* and convert to the pointers the HAR types use, so a field that was
// absent stays absent instead of reading back as a zero.
func scanEntry(row scanRow) (st model.Stored, sessionID int64, connection sql.NullInt64, err error) {
	e := &st.Entry
	var (
		reqHeadersComp, respHeadersComp, contentComp sql.NullInt64
		hasPost                                      int64
		post                                         har.PostData
		blocked, dns, connect, ssl                   sql.NullFloat64
	)
	err = row.Scan(
		&st.ID, &sessionID, &connection, &e.Pageref, &e.StartedDateTime, &e.Time,
		&e.ServerIPAddress, &e.Connection, &e.Comment,
		&e.Request.Method, &e.Request.URL, &e.Request.HTTPVersion, &e.Request.HeadersSize, &reqHeadersComp, &e.Request.BodySize, &e.Request.Comment,
		&hasPost, &post.MimeType, &post.Text, &post.Encoding, &post.Comment,
		&e.Response.Status, &e.Response.StatusText, &e.Response.HTTPVersion, &e.Response.RedirectURL, &e.Response.HeadersSize, &respHeadersComp, &e.Response.BodySize, &e.Response.Comment,
		&e.Response.Content.Size, &contentComp, &e.Response.Content.MimeType, &e.Response.Content.Text, &e.Response.Content.Encoding, &e.Response.Content.Comment,
		&blocked, &dns, &connect, &e.Timings.Send, &e.Timings.Wait, &e.Timings.Receive, &ssl, &e.Timings.Comment,
		&e.Cache.Comment,
	)
	if err != nil {
		return model.Stored{}, 0, sql.NullInt64{}, err
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
	return st, sessionID, connection, nil
}

// loadChildren fills the ordered collections hanging off an entry. Every list is
// read ordered by seq, so header, cookie, and parameter order — including
// repeated names — comes back exactly as captured.
func (r *Repository) loadChildren(ctx context.Context, st *model.Stored) error {
	e := &st.Entry
	var err error
	if e.Request.Headers, err = r.loadHeaders(ctx, st.ID, "request"); err != nil {
		return err
	}
	if e.Response.Headers, err = r.loadHeaders(ctx, st.ID, "response"); err != nil {
		return err
	}
	if e.Request.Cookies, err = r.loadCookies(ctx, st.ID, "request"); err != nil {
		return err
	}
	if e.Response.Cookies, err = r.loadCookies(ctx, st.ID, "response"); err != nil {
		return err
	}
	if e.Request.QueryString, err = r.loadQueryParams(ctx, st.ID); err != nil {
		return err
	}
	if e.Request.PostData != nil {
		if e.Request.PostData.Params, err = r.loadPostParams(ctx, st.ID); err != nil {
			return err
		}
	}
	if e.Cache.BeforeRequest, err = r.loadCacheState(ctx, st.ID, "before"); err != nil {
		return err
	}
	e.Cache.AfterRequest, err = r.loadCacheState(ctx, st.ID, "after")
	return err
}

func (r *Repository) loadHeaders(ctx context.Context, id int64, kind string) ([]har.NVP, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT name, value, comment FROM headers WHERE entry_id = ? AND kind = ? ORDER BY seq`, id, kind)
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

func (r *Repository) loadCookies(ctx context.Context, id int64, kind string) ([]har.Cookie, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT name, value, path, domain, expires, http_only, secure, comment
		 FROM cookies WHERE entry_id = ? AND kind = ? ORDER BY seq`, id, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []har.Cookie{}
	for rows.Next() {
		var (
			c                har.Cookie
			httpOnly, secure sql.NullInt64
		)
		if err := rows.Scan(&c.Name, &c.Value, &c.Path, &c.Domain, &c.Expires, &httpOnly, &secure, &c.Comment); err != nil {
			return nil, err
		}
		c.HTTPOnly = boolPtr(httpOnly)
		c.Secure = boolPtr(secure)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *Repository) loadQueryParams(ctx context.Context, id int64) ([]har.NVP, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT name, value, comment FROM query_params WHERE entry_id = ? ORDER BY seq`, id)
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

func (r *Repository) loadPostParams(ctx context.Context, id int64) ([]har.Param, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT name, value, file_name, content_type, encoding, comment
		 FROM post_params WHERE entry_id = ? ORDER BY seq`, id)
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

func (r *Repository) loadCacheState(ctx context.Context, id int64, kind string) (*har.CacheState, error) {
	var c har.CacheState
	err := r.db.QueryRowContext(ctx,
		`SELECT expires, last_access, etag, hit_count, comment FROM cache_states WHERE entry_id = ? AND kind = ?`,
		id, kind).Scan(&c.Expires, &c.LastAccess, &c.ETag, &c.HitCount, &c.Comment)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}
