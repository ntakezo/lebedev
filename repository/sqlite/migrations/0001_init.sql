-- Initial schema: the HAR 1.3 object model laid out for SQLite.
--
-- Shape follows the wire, not the document. A HAR file repeats a connection's
-- fingerprint on every entry; here one TLS connection is stored once and
-- referenced by the entries captured over it. Everything HAR defines as an
-- ordered list (headers, cookies, query and post parameters) is a child row
-- carrying its position in `seq`, so order, casing, and duplicates survive a
-- round trip rather than collapsing into a map. Scalars that HAR treats as
-- optional are nullable here, so "absent" and "zero" stay distinct.
--
-- Tables are STRICT: SQLite rejects a value whose type does not match the
-- column instead of silently coercing it, which is what keeps a stored
-- observation identical to the observed one. Ownership runs through ON DELETE
-- CASCADE, so removing a session or an entry is a single statement.

CREATE TABLE sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    created_at      INTEGER NOT NULL,
    version         TEXT    NOT NULL DEFAULT '1.3',
    creator_name    TEXT    NOT NULL DEFAULT '',
    creator_version TEXT    NOT NULL DEFAULT '',
    creator_comment TEXT    NOT NULL DEFAULT '',
    browser_name    TEXT    NOT NULL DEFAULT '',
    browser_version TEXT    NOT NULL DEFAULT '',
    browser_comment TEXT    NOT NULL DEFAULT '',
    comment         TEXT    NOT NULL DEFAULT ''
) STRICT;

-- One client TLS connection. The h2_* columns are empty for an HTTP/1.1
-- connection; the ordered ones are JSON arrays because their order is the
-- fingerprint and JSON preserves it without a child table per connection.
CREATE TABLE connections (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id         INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    created_at         INTEGER NOT NULL,
    client_hello_hex   TEXT    NOT NULL DEFAULT '',
    upstream_proto     TEXT    NOT NULL DEFAULT '',
    h2_connection_flow INTEGER NOT NULL DEFAULT 0,
    h2_settings        TEXT    NOT NULL DEFAULT '',
    h2_pseudo_order    TEXT    NOT NULL DEFAULT '',
    h2_header_order    TEXT    NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX idx_connections_session ON connections(session_id);

-- One tracked page load that entries may reference by pageref.
CREATE TABLE pages (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id           INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    seq                  INTEGER NOT NULL,
    page_id              TEXT    NOT NULL,
    started_date_time    TEXT    NOT NULL,
    title                TEXT    NOT NULL DEFAULT '',
    on_content_load      REAL,
    on_load              REAL,
    page_timings_comment TEXT    NOT NULL DEFAULT '',
    comment              TEXT    NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX idx_pages_session ON pages(session_id);

-- One request/response round trip. connection_id is NULL when the entry was
-- recorded without a captured connection (an imported HAR, for instance); it is
-- set NULL rather than cascaded when a connection goes away, so the transaction
-- outlives the fingerprint it was observed under.
CREATE TABLE entries (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id               INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    connection_id            INTEGER REFERENCES connections(id) ON DELETE SET NULL,
    created_at               INTEGER NOT NULL,
    pageref                  TEXT    NOT NULL DEFAULT '',
    started_date_time        TEXT    NOT NULL,
    time                     REAL    NOT NULL DEFAULT 0,
    server_ip_address        TEXT    NOT NULL DEFAULT '',
    connection               TEXT    NOT NULL DEFAULT '',
    comment                  TEXT    NOT NULL DEFAULT '',

    req_method               TEXT    NOT NULL,
    req_url                  TEXT    NOT NULL,
    req_http_version         TEXT    NOT NULL,
    req_headers_size         INTEGER NOT NULL DEFAULT -1,
    req_headers_compression  INTEGER,
    req_body_size            INTEGER NOT NULL DEFAULT -1,
    req_comment              TEXT    NOT NULL DEFAULT '',

    has_post                 INTEGER NOT NULL DEFAULT 0,
    post_mime_type           TEXT    NOT NULL DEFAULT '',
    post_text                TEXT    NOT NULL DEFAULT '',
    post_encoding            TEXT    NOT NULL DEFAULT '',
    post_comment             TEXT    NOT NULL DEFAULT '',

    resp_status              INTEGER NOT NULL,
    resp_status_text         TEXT    NOT NULL DEFAULT '',
    resp_http_version        TEXT    NOT NULL,
    resp_redirect_url        TEXT    NOT NULL DEFAULT '',
    resp_headers_size        INTEGER NOT NULL DEFAULT -1,
    resp_headers_compression INTEGER,
    resp_body_size           INTEGER NOT NULL DEFAULT -1,
    resp_comment             TEXT    NOT NULL DEFAULT '',

    content_size             INTEGER NOT NULL DEFAULT 0,
    content_compression      INTEGER,
    content_mime_type        TEXT    NOT NULL DEFAULT '',
    content_text             TEXT    NOT NULL DEFAULT '',
    content_encoding         TEXT    NOT NULL DEFAULT '',
    content_comment          TEXT    NOT NULL DEFAULT '',

    t_blocked                REAL,
    t_dns                    REAL,
    t_connect                REAL,
    t_send                   REAL    NOT NULL DEFAULT 0,
    t_wait                   REAL    NOT NULL DEFAULT 0,
    t_receive                REAL    NOT NULL DEFAULT 0,
    t_ssl                    REAL,
    timings_comment          TEXT    NOT NULL DEFAULT '',

    cache_comment            TEXT    NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX idx_entries_session ON entries(session_id, id);
CREATE INDEX idx_entries_connection ON entries(connection_id);
CREATE INDEX idx_entries_url ON entries(req_url);
CREATE INDEX idx_entries_status ON entries(resp_status);
CREATE INDEX idx_entries_mime ON entries(content_mime_type);

-- kind is 'request' or 'response'; seq is the header's position in that block,
-- which is what makes header order reproducible.
CREATE TABLE headers (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    kind     TEXT    NOT NULL,
    seq      INTEGER NOT NULL,
    name     TEXT    NOT NULL,
    value    TEXT    NOT NULL,
    comment  TEXT    NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX idx_headers_entry ON headers(entry_id, kind, seq);
CREATE INDEX idx_headers_name ON headers(name);

CREATE TABLE cookies (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id  INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    kind      TEXT    NOT NULL,
    seq       INTEGER NOT NULL,
    name      TEXT    NOT NULL,
    value     TEXT    NOT NULL,
    path      TEXT    NOT NULL DEFAULT '',
    domain    TEXT    NOT NULL DEFAULT '',
    expires   TEXT    NOT NULL DEFAULT '',
    http_only INTEGER,
    secure    INTEGER,
    comment   TEXT    NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX idx_cookies_entry ON cookies(entry_id, kind, seq);

CREATE TABLE query_params (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    seq      INTEGER NOT NULL,
    name     TEXT    NOT NULL,
    value    TEXT    NOT NULL,
    comment  TEXT    NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX idx_query_params_entry ON query_params(entry_id, seq);

CREATE TABLE post_params (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id     INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    seq          INTEGER NOT NULL,
    name         TEXT    NOT NULL,
    value        TEXT    NOT NULL DEFAULT '',
    file_name    TEXT    NOT NULL DEFAULT '',
    content_type TEXT    NOT NULL DEFAULT '',
    encoding     TEXT    NOT NULL DEFAULT '',
    comment      TEXT    NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX idx_post_params_entry ON post_params(entry_id, seq);

-- kind is 'before' or 'after'; at most one row of each per entry.
CREATE TABLE cache_states (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id    INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    kind        TEXT    NOT NULL,
    expires     TEXT    NOT NULL DEFAULT '',
    last_access TEXT    NOT NULL DEFAULT '',
    etag        TEXT    NOT NULL DEFAULT '',
    hit_count   INTEGER NOT NULL DEFAULT 0,
    comment     TEXT    NOT NULL DEFAULT '',
    UNIQUE (entry_id, kind)
) STRICT;
