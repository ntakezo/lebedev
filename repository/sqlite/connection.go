package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/ntakezo/lebedev/model"
	"github.com/ntakezo/lebedev/repository"
)

// connectionColumns lists the connections columns every read selects, in scan
// order.
const connectionColumns = `id, client_hello_hex, upstream_proto,
	h2_connection_flow, h2_settings, h2_pseudo_order, h2_header_order`

// CreateConnection records the TLS connection a session's entries were captured
// over and returns its id. The raw ClientHello and the HTTP/2 traits are stored
// once per connection, the way the wire produced them, rather than copied onto
// every entry; entries reference the row and rebuild their _lebedev field from
// it on read.
func (r *Repository) CreateConnection(ctx context.Context, session string, c model.Connection) (int64, error) {
	settings, pseudo, header, err := marshalHTTP2(c.HTTP2)
	if err != nil {
		return 0, err
	}
	var flow uint32
	if c.HTTP2 != nil {
		flow = c.HTTP2.ConnectionFlow
	}

	var id int64
	err = r.tx(ctx, func(tx *sql.Tx) error {
		sid, err := sessionID(ctx, tx, session)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO connections
			(session_id, created_at, client_hello_hex, upstream_proto,
			 h2_connection_flow, h2_settings, h2_pseudo_order, h2_header_order)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			sid, r.now().UnixMilli(), c.ClientHelloHex, c.UpstreamProto,
			int64(flow), settings, pseudo, header)
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	if err != nil {
		return 0, err
	}
	return id, nil
}

// Connection returns one stored connection, with the session it belongs to
// filled in so it exports the same _lebedev field its entries carry.
func (r *Repository) Connection(ctx context.Context, id int64) (model.Connection, error) {
	var session string
	if err := r.db.QueryRowContext(ctx,
		`SELECT s.name FROM connections c JOIN sessions s ON s.id = c.session_id WHERE c.id = ?`,
		id).Scan(&session); err != nil {
		return model.Connection{}, notFound(err)
	}
	row := r.db.QueryRowContext(ctx, `SELECT `+connectionColumns+` FROM connections WHERE id = ?`, id)
	c, err := scanConnection(row, session)
	if err != nil {
		return model.Connection{}, notFound(err)
	}
	return c, nil
}

// scanRow is the read surface shared by *sql.Row and *sql.Rows.
type scanRow interface {
	Scan(dest ...any) error
}

// scanConnection reads one connections row. The HTTP/2 traits are reassembled
// only when the connection recorded any, so an HTTP/1.1 connection reads back
// with a nil HTTP2 rather than an empty one.
func scanConnection(row scanRow, session string) (model.Connection, error) {
	var (
		c                             model.Connection
		flow                          int64
		settings, pseudo, headerOrder string
	)
	if err := row.Scan(&c.ID, &c.ClientHelloHex, &c.UpstreamProto,
		&flow, &settings, &pseudo, &headerOrder); err != nil {
		return model.Connection{}, err
	}
	c.Session = session
	h2, err := unmarshalHTTP2(uint32(flow), settings, pseudo, headerOrder)
	if err != nil {
		return model.Connection{}, err
	}
	c.HTTP2 = h2
	return c, nil
}

// marshalHTTP2 flattens the HTTP/2 fingerprint into the three JSON columns that
// hold it. JSON arrays are used because the order of the settings, pseudo
// headers, and headers is itself the fingerprint, and an array preserves it.
// A nil fingerprint stores empty strings, which read back as nil.
func marshalHTTP2(h *model.HTTP2) (settings, pseudo, headerOrder string, err error) {
	if h == nil {
		return "", "", "", nil
	}
	if settings, err = marshalJSON(h.Settings); err != nil {
		return "", "", "", err
	}
	if pseudo, err = marshalJSON(h.PseudoOrder); err != nil {
		return "", "", "", err
	}
	if headerOrder, err = marshalJSON(h.HeaderOrder); err != nil {
		return "", "", "", err
	}
	// A fingerprint whose only content is the flow-control window still has to
	// read back, so record the presence of the object even when its lists are empty.
	if settings == "" && pseudo == "" && headerOrder == "" {
		settings = "[]"
	}
	return settings, pseudo, headerOrder, nil
}

func marshalJSON(v any) (string, error) {
	switch t := v.(type) {
	case []model.Setting:
		if len(t) == 0 {
			return "", nil
		}
	case []string:
		if len(t) == 0 {
			return "", nil
		}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// unmarshalHTTP2 rebuilds the fingerprint from its columns, returning nil when
// the connection stored none (an HTTP/1.1 connection).
func unmarshalHTTP2(flow uint32, settings, pseudo, headerOrder string) (*model.HTTP2, error) {
	if settings == "" && pseudo == "" && headerOrder == "" && flow == 0 {
		return nil, nil
	}
	h := model.HTTP2{ConnectionFlow: flow}
	if settings != "" {
		if err := json.Unmarshal([]byte(settings), &h.Settings); err != nil {
			return nil, err
		}
	}
	if pseudo != "" {
		if err := json.Unmarshal([]byte(pseudo), &h.PseudoOrder); err != nil {
			return nil, err
		}
	}
	if headerOrder != "" {
		if err := json.Unmarshal([]byte(headerOrder), &h.HeaderOrder); err != nil {
			return nil, err
		}
	}
	return &h, nil
}

// connectionFor loads the connection an entry references, returning a zero
// Connection when the entry recorded none.
func (r *Repository) connectionFor(ctx context.Context, id sql.NullInt64) (model.Connection, error) {
	if !id.Valid || id.Int64 == 0 {
		return model.Connection{}, nil
	}
	c, err := r.Connection(ctx, id.Int64)
	// An entry outlives its connection (ON DELETE SET NULL), so a missing one is
	// not an error — the entry simply reads back without a fingerprint.
	if err == repository.ErrNotFound {
		return model.Connection{}, nil
	}
	return c, err
}
