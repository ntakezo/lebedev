package store

import (
	"strconv"
	"strings"
)

// dialect captures the few ways SQLite and PostgreSQL differ for this store:
// the auto-increment primary-key declaration, how a freshly inserted row's id is
// recovered, and the placeholder style. All other SQL is shared verbatim.
type dialect struct {
	name        string // "sqlite" | "postgres"
	driver      string // database/sql driver name
	serialPK    string // primary-key column definition
	returningID bool   // true when INSERT must use "RETURNING id" to get the id
}

var (
	sqliteDialect = dialect{
		name:     "sqlite",
		driver:   "sqlite",
		serialPK: "INTEGER PRIMARY KEY AUTOINCREMENT",
	}
	postgresDialect = dialect{
		name:        "postgres",
		driver:      "pgx",
		serialPK:    "BIGSERIAL PRIMARY KEY",
		returningID: true,
	}
)

// rebind rewrites '?' placeholders into the dialect's positional form. SQLite
// keeps '?'; PostgreSQL needs $1, $2, … in order.
func (d dialect) rebind(query string) string {
	if !d.returningID {
		return query
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(query[i])
	}
	return b.String()
}

// schema returns the DDL that creates every table and index, tailored to the
// dialect's primary-key syntax. It is idempotent (IF NOT EXISTS throughout) so it
// can run on every Open.
func (d dialect) schema() []string {
	pk := d.serialPK
	return []string{
		`CREATE TABLE IF NOT EXISTS logs (
			session TEXT PRIMARY KEY,
			version TEXT NOT NULL DEFAULT '1.3',
			creator_name TEXT NOT NULL DEFAULT '',
			creator_version TEXT NOT NULL DEFAULT '',
			creator_comment TEXT NOT NULL DEFAULT '',
			browser_name TEXT NOT NULL DEFAULT '',
			browser_version TEXT NOT NULL DEFAULT '',
			browser_comment TEXT NOT NULL DEFAULT '',
			comment TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS pages (
			id ` + pk + `,
			session TEXT NOT NULL,
			page_id TEXT NOT NULL,
			started_date_time TEXT NOT NULL,
			title TEXT NOT NULL,
			on_content_load REAL,
			on_load REAL,
			page_timings_comment TEXT NOT NULL DEFAULT '',
			comment TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS entries (
			id ` + pk + `,
			session TEXT NOT NULL,
			created_at BIGINT NOT NULL,
			pageref TEXT NOT NULL DEFAULT '',
			started_date_time TEXT NOT NULL,
			time REAL NOT NULL DEFAULT 0,
			server_ip_address TEXT NOT NULL DEFAULT '',
			connection TEXT NOT NULL DEFAULT '',
			comment TEXT NOT NULL DEFAULT '',
			req_method TEXT NOT NULL,
			req_url TEXT NOT NULL,
			req_http_version TEXT NOT NULL,
			req_headers_size INTEGER NOT NULL DEFAULT -1,
			req_headers_compression INTEGER,
			req_body_size INTEGER NOT NULL DEFAULT -1,
			req_comment TEXT NOT NULL DEFAULT '',
			has_post INTEGER NOT NULL DEFAULT 0,
			post_mime_type TEXT NOT NULL DEFAULT '',
			post_text TEXT NOT NULL DEFAULT '',
			post_encoding TEXT NOT NULL DEFAULT '',
			post_comment TEXT NOT NULL DEFAULT '',
			resp_status INTEGER NOT NULL,
			resp_status_text TEXT NOT NULL DEFAULT '',
			resp_http_version TEXT NOT NULL,
			resp_redirect_url TEXT NOT NULL DEFAULT '',
			resp_headers_size INTEGER NOT NULL DEFAULT -1,
			resp_headers_compression INTEGER,
			resp_body_size INTEGER NOT NULL DEFAULT -1,
			resp_comment TEXT NOT NULL DEFAULT '',
			content_size INTEGER NOT NULL DEFAULT 0,
			content_compression INTEGER,
			content_mime_type TEXT NOT NULL DEFAULT '',
			content_text TEXT NOT NULL DEFAULT '',
			content_encoding TEXT NOT NULL DEFAULT '',
			content_comment TEXT NOT NULL DEFAULT '',
			t_blocked REAL,
			t_dns REAL,
			t_connect REAL,
			t_send REAL NOT NULL DEFAULT 0,
			t_wait REAL NOT NULL DEFAULT 0,
			t_receive REAL NOT NULL DEFAULT 0,
			t_ssl REAL,
			timings_comment TEXT NOT NULL DEFAULT '',
			cache_comment TEXT NOT NULL DEFAULT '',
			client_hello_hex TEXT NOT NULL DEFAULT '',
			upstream_proto TEXT NOT NULL DEFAULT '',
			http2 TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS headers (
			id ` + pk + `,
			entry_id BIGINT NOT NULL,
			kind TEXT NOT NULL,
			seq INTEGER NOT NULL,
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			comment TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS cookies (
			id ` + pk + `,
			entry_id BIGINT NOT NULL,
			kind TEXT NOT NULL,
			seq INTEGER NOT NULL,
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			path TEXT NOT NULL DEFAULT '',
			domain TEXT NOT NULL DEFAULT '',
			expires TEXT NOT NULL DEFAULT '',
			http_only INTEGER,
			secure INTEGER,
			comment TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS query_params (
			id ` + pk + `,
			entry_id BIGINT NOT NULL,
			seq INTEGER NOT NULL,
			name TEXT NOT NULL,
			value TEXT NOT NULL,
			comment TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS post_params (
			id ` + pk + `,
			entry_id BIGINT NOT NULL,
			seq INTEGER NOT NULL,
			name TEXT NOT NULL,
			value TEXT NOT NULL DEFAULT '',
			file_name TEXT NOT NULL DEFAULT '',
			content_type TEXT NOT NULL DEFAULT '',
			encoding TEXT NOT NULL DEFAULT '',
			comment TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS cache_states (
			id ` + pk + `,
			entry_id BIGINT NOT NULL,
			kind TEXT NOT NULL,
			expires TEXT NOT NULL DEFAULT '',
			last_access TEXT NOT NULL DEFAULT '',
			etag TEXT NOT NULL DEFAULT '',
			hit_count INTEGER NOT NULL DEFAULT 0,
			comment TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_entries_session ON entries(session)`,
		`CREATE INDEX IF NOT EXISTS idx_entries_url ON entries(req_url)`,
		`CREATE INDEX IF NOT EXISTS idx_entries_status ON entries(resp_status)`,
		`CREATE INDEX IF NOT EXISTS idx_entries_mime ON entries(content_mime_type)`,
		`CREATE INDEX IF NOT EXISTS idx_headers_entry ON headers(entry_id)`,
		`CREATE INDEX IF NOT EXISTS idx_cookies_entry ON cookies(entry_id)`,
		`CREATE INDEX IF NOT EXISTS idx_query_params_entry ON query_params(entry_id)`,
		`CREATE INDEX IF NOT EXISTS idx_post_params_entry ON post_params(entry_id)`,
		`CREATE INDEX IF NOT EXISTS idx_cache_states_entry ON cache_states(entry_id)`,
	}
}
