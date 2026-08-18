package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/ntakezo/lebedev/har"
	"github.com/ntakezo/lebedev/model"
	"github.com/ntakezo/lebedev/repository"
)

// CreateSession records a new session with its log-level metadata and returns
// its id. The name is unique, so a second call with the same name reports
// repository.ErrExists rather than merging into the stored session.
func (r *Repository) CreateSession(ctx context.Context, s repository.Session) (int64, error) {
	if s.Name == "" {
		return 0, fmt.Errorf("sqlite: session name is required")
	}
	version := s.Log.Version
	if version == "" {
		version = "1.3"
	}
	var b har.Browser
	if s.Log.Browser != nil {
		b = *s.Log.Browser
	}

	var id int64
	err := r.tx(ctx, func(tx *sql.Tx) error {
		exists, err := sessionExists(ctx, tx, s.Name)
		if err != nil {
			return err
		}
		if exists {
			return repository.ErrExists
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO sessions
			(name, created_at, version, creator_name, creator_version, creator_comment,
			 browser_name, browser_version, browser_comment, comment)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			s.Name, r.now().UnixMilli(), version,
			s.Log.Creator.Name, s.Log.Creator.Version, s.Log.Creator.Comment,
			b.Name, b.Version, b.Comment, s.Log.Comment)
		if err != nil {
			return err
		}
		if id, err = res.LastInsertId(); err != nil {
			return err
		}
		return insertPages(ctx, tx, id, s.Log.Pages)
	})
	if err != nil {
		return 0, err
	}
	return id, nil
}

// Session returns one session: its identity, log metadata, the TLS connections
// its traffic was captured over, and a summary of every entry in capture order.
// Entry bodies are left on disk — read one in full with Entry.
func (r *Repository) Session(ctx context.Context, name string) (repository.SessionDetails, error) {
	var (
		d         repository.SessionDetails
		createdAt int64
		b         har.Browser
	)
	err := r.db.QueryRowContext(ctx, `SELECT id, name, created_at, version,
		creator_name, creator_version, creator_comment,
		browser_name, browser_version, browser_comment, comment
		FROM sessions WHERE name = ?`, name).Scan(
		&d.ID, &d.Name, &createdAt, &d.Log.Version,
		&d.Log.Creator.Name, &d.Log.Creator.Version, &d.Log.Creator.Comment,
		&b.Name, &b.Version, &b.Comment, &d.Log.Comment)
	if err != nil {
		return repository.SessionDetails{}, notFound(err)
	}
	d.CreatedAt = time.UnixMilli(createdAt)
	if b != (har.Browser{}) {
		d.Log.Browser = &b
	}
	if d.Log.Pages, err = r.loadPages(ctx, d.ID); err != nil {
		return repository.SessionDetails{}, err
	}
	if d.Connections, err = r.sessionConnections(ctx, d.ID, d.Name); err != nil {
		return repository.SessionDetails{}, err
	}
	if d.Entries, err = r.entrySummaries(ctx, d.ID); err != nil {
		return repository.SessionDetails{}, err
	}
	return d, nil
}

// RenameSession moves a session to a new name. Because entries and connections
// reference the session by id, nothing else moves; the rename is one UPDATE. It
// refuses to rename onto a stored name, so it never merges two sessions.
func (r *Repository) RenameSession(ctx context.Context, old, name string) error {
	if name == "" {
		return fmt.Errorf("sqlite: session name is required")
	}
	if old == name {
		return nil
	}
	return r.tx(ctx, func(tx *sql.Tx) error {
		exists, err := sessionExists(ctx, tx, old)
		if err != nil {
			return err
		}
		if !exists {
			return repository.ErrNotFound
		}
		taken, err := sessionExists(ctx, tx, name)
		if err != nil {
			return err
		}
		if taken {
			return repository.ErrExists
		}
		_, err = tx.ExecContext(ctx, `UPDATE sessions SET name = ? WHERE name = ?`, name, old)
		return err
	})
}

// DeleteSession removes a session together with its pages, connections, entries,
// and everything hanging off them. Ownership is expressed as ON DELETE CASCADE,
// so one statement is the whole delete.
func (r *Repository) DeleteSession(ctx context.Context, name string) error {
	return r.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE name = ?`, name)
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

// sessionID resolves a session name to its row id, reporting
// repository.ErrNotFound when the name is unknown.
func sessionID(ctx context.Context, q querier, name string) (int64, error) {
	var id int64
	if err := q.QueryRowContext(ctx, `SELECT id FROM sessions WHERE name = ?`, name).Scan(&id); err != nil {
		return 0, notFound(err)
	}
	return id, nil
}

func sessionExists(ctx context.Context, q querier, name string) (bool, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE name = ?`, name).Scan(&n)
	return n > 0, err
}

// querier is the read surface shared by *sql.DB and *sql.Tx, so a lookup works
// the same inside and outside a transaction.
type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func insertPages(ctx context.Context, tx *sql.Tx, sessionID int64, pages []har.Page) error {
	for i, p := range pages {
		_, err := tx.ExecContext(ctx, `INSERT INTO pages
			(session_id, seq, page_id, started_date_time, title, on_content_load, on_load, page_timings_comment, comment)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			sessionID, i, p.ID, p.StartedDateTime, p.Title,
			nullFloat(p.PageTimings.OnContentLoad), nullFloat(p.PageTimings.OnLoad),
			p.PageTimings.Comment, p.Comment)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Repository) loadPages(ctx context.Context, sessionID int64) ([]har.Page, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT page_id, started_date_time, title,
		on_content_load, on_load, page_timings_comment, comment
		FROM pages WHERE session_id = ? ORDER BY seq`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []har.Page
	for rows.Next() {
		var (
			p                 har.Page
			contentLoad, load sql.NullFloat64
		)
		if err := rows.Scan(&p.ID, &p.StartedDateTime, &p.Title,
			&contentLoad, &load, &p.PageTimings.Comment, &p.Comment); err != nil {
			return nil, err
		}
		p.PageTimings.OnContentLoad = floatPtr(contentLoad)
		p.PageTimings.OnLoad = floatPtr(load)
		out = append(out, p)
	}
	return out, rows.Err()
}

// entrySummaries lists a session's entries in capture order, reading only the
// columns a listing needs so a large session stays cheap to open.
func (r *Repository) entrySummaries(ctx context.Context, sessionID int64) ([]repository.EntrySummary, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, connection_id, started_date_time,
		req_method, req_url, resp_status, content_mime_type, resp_body_size
		FROM entries WHERE session_id = ? ORDER BY id`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []repository.EntrySummary
	for rows.Next() {
		var (
			s    repository.EntrySummary
			conn sql.NullInt64
		)
		if err := rows.Scan(&s.ID, &conn, &s.StartedDateTime,
			&s.Method, &s.URL, &s.Status, &s.MimeType, &s.BodySize); err != nil {
			return nil, err
		}
		s.Connection = conn.Int64
		out = append(out, s)
	}
	return out, rows.Err()
}

// sessionConnections returns every connection recorded under a session, tagged
// with the session name so each one exports the _lebedev field it was
// captured with.
func (r *Repository) sessionConnections(ctx context.Context, sessionID int64, name string) ([]model.Connection, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+connectionColumns+`
		FROM connections WHERE session_id = ? ORDER BY id`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Connection
	for rows.Next() {
		c, err := scanConnection(rows, name)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
