package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ntakezo/lebedev/har"
	"github.com/ntakezo/lebedev/model"
	"github.com/ntakezo/lebedev/repository"
)

func open(t *testing.T) *Repository {
	t.Helper()
	r, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

// seed creates a session and returns the repository and its name.
func seed(t *testing.T, r *Repository, name string) {
	t.Helper()
	if _, err := r.CreateSession(context.Background(), repository.Session{
		Name: name,
		Log:  model.Log{Creator: har.Creator{Name: "lebedev", Version: "1.3"}},
	}); err != nil {
		t.Fatal(err)
	}
}

func ptrInt(v int) *int           { return &v }
func ptrFloat(v float64) *float64 { return &v }
func ptrBool(v bool) *bool        { return &v }

// fullEntry exercises every part of the model: ordered headers with a repeated
// name, cookies with both flag states, query and post parameters, a base64 body,
// cache states, and each nullable scalar.
func fullEntry() model.Entry {
	return model.Entry{
		Pageref:         "page_1",
		StartedDateTime: "2026-08-18T00:00:00.000Z",
		Time:            12.5,
		ServerIPAddress: "93.184.216.34",
		Connection:      "443",
		Comment:         "entry comment",
		Request: har.Request{
			Method:      "POST",
			URL:         "https://example.com/submit?b=2&a=1&a=3",
			HTTPVersion: "HTTP/2.0",
			Cookies: []har.Cookie{
				{Name: "sid", Value: "abc", Path: "/", Domain: ".example.com", Expires: "2026-09-01T00:00:00.000Z", HTTPOnly: ptrBool(true), Secure: ptrBool(false), Comment: "c"},
				{Name: "dup", Value: "1"},
			},
			Headers: []har.NVP{
				{Name: "User-Agent", Value: "UA"},
				{Name: "Accept", Value: "*/*"},
				{Name: "accept", Value: "text/html", Comment: "repeated, different casing"},
				{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
			},
			QueryString: []har.NVP{
				{Name: "b", Value: "2"},
				{Name: "a", Value: "1"},
				{Name: "a", Value: "3"},
			},
			PostData: &har.PostData{
				MimeType: "application/x-www-form-urlencoded",
				Params: []har.Param{
					{Name: "f", Value: "v"},
					{Name: "file", FileName: "x.bin", ContentType: "application/octet-stream", Encoding: "base64"},
				},
				Text:     "f=v",
				Encoding: "",
				Comment:  "post comment",
			},
			HeadersSize:        231,
			HeadersCompression: ptrInt(4),
			BodySize:           3,
			Comment:            "req comment",
		},
		Response: har.Response{
			Status:      200,
			StatusText:  "OK",
			HTTPVersion: "HTTP/2.0",
			Cookies: []har.Cookie{
				{Name: "set", Value: "yes", Secure: ptrBool(true)},
			},
			Headers: []har.NVP{
				{Name: "content-type", Value: "application/octet-stream"},
				{Name: "set-cookie", Value: "a=1"},
				{Name: "set-cookie", Value: "b=2"},
			},
			Content: har.Content{
				Size:        4,
				Compression: ptrInt(0),
				MimeType:    "application/octet-stream",
				Text:        "AAECAw==",
				Encoding:    "base64",
				Comment:     "content comment",
			},
			RedirectURL:        "",
			HeadersSize:        99,
			HeadersCompression: ptrInt(7),
			BodySize:           4,
			Comment:            "resp comment",
		},
		Cache: har.Cache{
			BeforeRequest: &har.CacheState{Expires: "2026-09-01T00:00:00.000Z", LastAccess: "2026-08-18T00:00:00.000Z", ETag: "\"v1\"", HitCount: 2, Comment: "before"},
			AfterRequest:  &har.CacheState{LastAccess: "2026-08-18T00:00:01.000Z", ETag: "\"v2\"", HitCount: 3},
			Comment:       "cache comment",
		},
		Timings: har.Timings{
			Blocked: ptrFloat(1.5),
			DNS:     ptrFloat(-1),
			Connect: ptrFloat(3),
			Send:    0.25,
			Wait:    8,
			Receive: 2.75,
			SSL:     ptrFloat(1.25),
			Comment: "timings comment",
		},
	}
}

func fullConnection() model.Connection {
	return model.Connection{
		ClientHelloHex: "1603010200010001fc0303deadbeef",
		UpstreamProto:  "HTTP/3.0",
		HTTP2: &model.HTTP2{
			Settings:       []model.Setting{{ID: 1, Value: 65536}, {ID: 2, Value: 0}, {ID: 4, Value: 6291456}},
			ConnectionFlow: 15663105,
			PseudoOrder:    []string{":method", ":authority", ":scheme", ":path"},
			HeaderOrder:    []string{"user-agent", "accept", "accept", "content-type"},
		},
	}
}

func TestEntryRoundTripsVerbatim(t *testing.T) {
	ctx := context.Background()
	r := open(t)
	seed(t, r, "s1")

	conn, err := r.CreateConnection(ctx, "s1", fullConnection())
	if err != nil {
		t.Fatal(err)
	}
	want := fullEntry()
	id, err := r.CreateEntry(ctx, "s1", conn, want)
	if err != nil {
		t.Fatal(err)
	}

	got, err := r.Entry(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != id || got.Session != "s1" || got.Connection != conn {
		t.Errorf("identity = (%d, %q, %d), want (%d, %q, %d)", got.ID, got.Session, got.Connection, id, "s1", conn)
	}

	// The _lebedev field is rebuilt from the connection, so compare the HAR half
	// against what was written and the extension against the connection.
	want.Lebedev = nil
	gotHAR := got.Entry
	gotHAR.Lebedev = nil
	if !reflect.DeepEqual(gotHAR, want) {
		t.Errorf("entry did not round-trip verbatim:\n got %#v\nwant %#v", gotHAR, want)
	}

	lb := got.Entry.Lebedev
	if lb == nil {
		t.Fatal("_lebedev should be rebuilt from the entry's connection")
	}
	src := fullConnection()
	if lb.Session != "s1" || lb.ClientHelloHex != src.ClientHelloHex || lb.UpstreamProto != src.UpstreamProto {
		t.Errorf("_lebedev scalars = %#v", lb)
	}
	if !reflect.DeepEqual(lb.HTTP2, src.HTTP2) {
		t.Errorf("http2 fingerprint = %#v, want %#v", lb.HTTP2, src.HTTP2)
	}
}

func TestEntryPreservesHeaderAndParamOrder(t *testing.T) {
	ctx := context.Background()
	r := open(t)
	seed(t, r, "s1")

	id, err := r.CreateEntry(ctx, "s1", 0, fullEntry())
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Entry(ctx, id)
	if err != nil {
		t.Fatal(err)
	}

	wantReq := []string{"User-Agent", "Accept", "accept", "Content-Type"}
	for i, h := range got.Entry.Request.Headers {
		if h.Name != wantReq[i] {
			t.Errorf("request header %d = %q, want %q (order and casing must survive)", i, h.Name, wantReq[i])
		}
	}
	wantQuery := []string{"b", "a", "a"}
	for i, p := range got.Entry.Request.QueryString {
		if p.Name != wantQuery[i] {
			t.Errorf("query param %d = %q, want %q", i, p.Name, wantQuery[i])
		}
	}
	if n := len(got.Entry.Response.Headers); n != 3 {
		t.Fatalf("response headers = %d, want 3 (repeated set-cookie must not collapse)", n)
	}
	if got.Entry.Response.Headers[1].Value != "a=1" || got.Entry.Response.Headers[2].Value != "b=2" {
		t.Errorf("repeated set-cookie order lost: %#v", got.Entry.Response.Headers)
	}
}

func TestEntryWithoutConnectionHasNoExtension(t *testing.T) {
	ctx := context.Background()
	r := open(t)
	seed(t, r, "s1")

	id, err := r.CreateEntry(ctx, "s1", 0, fullEntry())
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Entry(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Connection != 0 {
		t.Errorf("connection = %d, want 0", got.Connection)
	}
	if got.Entry.Lebedev != nil {
		t.Errorf("_lebedev = %#v, want nil for an entry with no connection", got.Entry.Lebedev)
	}
}

func TestConnectionStoredOncePerConnection(t *testing.T) {
	ctx := context.Background()
	r := open(t)
	seed(t, r, "s1")

	conn, err := r.CreateConnection(ctx, "s1", fullConnection())
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := r.CreateEntry(ctx, "s1", conn, fullEntry()); err != nil {
			t.Fatal(err)
		}
	}

	var rows int
	if err := r.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM connections`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Errorf("connections rows = %d, want 1 — a connection is stored once, not per entry", rows)
	}

	d, err := r.Session(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Entries) != 3 {
		t.Errorf("session entries = %d, want 3", len(d.Entries))
	}
	if len(d.Connections) != 1 {
		t.Fatalf("session connections = %d, want 1", len(d.Connections))
	}
	for _, s := range d.Entries {
		if s.Connection != conn {
			t.Errorf("entry %d references connection %d, want %d", s.ID, s.Connection, conn)
		}
	}
}

func TestConnectionRoundTripsHTTP1(t *testing.T) {
	ctx := context.Background()
	r := open(t)
	seed(t, r, "s1")

	// An h1 connection carries a hello but no HTTP/2 traits at all.
	id, err := r.CreateConnection(ctx, "s1", model.Connection{ClientHelloHex: "160301", UpstreamProto: "HTTP/1.1"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Connection(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.HTTP2 != nil {
		t.Errorf("HTTP2 = %#v, want nil for an h1 connection", got.HTTP2)
	}
	if got.ClientHelloHex != "160301" || got.UpstreamProto != "HTTP/1.1" || got.Session != "s1" {
		t.Errorf("connection = %#v", got)
	}
}

func TestSessionDetails(t *testing.T) {
	ctx := context.Background()
	r := open(t)

	log := model.Log{
		Version: "1.3",
		Creator: har.Creator{Name: "lebedev", Version: "1.3", Comment: "c"},
		Browser: &har.Browser{Name: "Chrome", Version: "150"},
		Pages: []har.Page{
			{ID: "page_1", StartedDateTime: "2026-08-18T00:00:00.000Z", Title: "home", PageTimings: har.PageTimings{OnLoad: ptrFloat(120)}},
			{ID: "page_2", StartedDateTime: "2026-08-18T00:00:05.000Z", Title: "cart"},
		},
		Comment: "log comment",
	}
	if _, err := r.CreateSession(ctx, repository.Session{Name: "s1", Log: log}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.CreateEntry(ctx, "s1", 0, fullEntry()); err != nil {
		t.Fatal(err)
	}

	d, err := r.Session(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if d.Name != "s1" || d.ID == 0 || d.CreatedAt.IsZero() {
		t.Errorf("identity = %#v", d)
	}
	if !reflect.DeepEqual(d.Log, log) {
		t.Errorf("log did not round-trip:\n got %#v\nwant %#v", d.Log, log)
	}
	if len(d.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(d.Entries))
	}
	got := d.Entries[0]
	if got.Method != "POST" || got.Status != 200 || got.MimeType != "application/octet-stream" || got.BodySize != 4 {
		t.Errorf("summary = %#v", got)
	}
}

func TestCreateSessionRejectsDuplicate(t *testing.T) {
	ctx := context.Background()
	r := open(t)
	seed(t, r, "s1")

	_, err := r.CreateSession(ctx, repository.Session{Name: "s1"})
	if !errors.Is(err, repository.ErrExists) {
		t.Errorf("err = %v, want ErrExists", err)
	}
}

func TestRenameSessionKeepsRows(t *testing.T) {
	ctx := context.Background()
	r := open(t)
	seed(t, r, "old")
	seed(t, r, "taken")

	conn, err := r.CreateConnection(ctx, "old", fullConnection())
	if err != nil {
		t.Fatal(err)
	}
	id, err := r.CreateEntry(ctx, "old", conn, fullEntry())
	if err != nil {
		t.Fatal(err)
	}

	if err := r.RenameSession(ctx, "old", "new"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Session(ctx, "old"); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("old name still resolves: %v", err)
	}
	d, err := r.Session(ctx, "new")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Entries) != 1 || len(d.Connections) != 1 {
		t.Errorf("rename lost rows: %d entries, %d connections", len(d.Entries), len(d.Connections))
	}
	// The entry and its connection follow the session, and both report the new name.
	e, err := r.Entry(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if e.Session != "new" || e.Entry.Lebedev == nil || e.Entry.Lebedev.Session != "new" {
		t.Errorf("entry session after rename = %q (_lebedev %#v)", e.Session, e.Entry.Lebedev)
	}

	if err := r.RenameSession(ctx, "new", "taken"); !errors.Is(err, repository.ErrExists) {
		t.Errorf("renaming onto a stored name: err = %v, want ErrExists", err)
	}
	if err := r.RenameSession(ctx, "missing", "other"); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("renaming an unknown session: err = %v, want ErrNotFound", err)
	}
}

func TestDeleteEntryCascadesChildrenAndKeepsConnection(t *testing.T) {
	ctx := context.Background()
	r := open(t)
	seed(t, r, "s1")

	conn, err := r.CreateConnection(ctx, "s1", fullConnection())
	if err != nil {
		t.Fatal(err)
	}
	first, err := r.CreateEntry(ctx, "s1", conn, fullEntry())
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.CreateEntry(ctx, "s1", conn, fullEntry())
	if err != nil {
		t.Fatal(err)
	}

	if err := r.DeleteEntry(ctx, first); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Entry(ctx, first); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("deleted entry still readable: %v", err)
	}
	for _, table := range []string{"headers", "cookies", "query_params", "post_params", "cache_states"} {
		var n int
		if err := r.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE entry_id = ?`, first).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s kept %d orphan rows after the entry was deleted", table, n)
		}
	}
	// The surviving entry still needs the shared connection.
	if _, err := r.Connection(ctx, conn); err != nil {
		t.Errorf("connection removed with the entry: %v", err)
	}
	if _, err := r.Entry(ctx, second); err != nil {
		t.Errorf("sibling entry lost: %v", err)
	}
	if err := r.DeleteEntry(ctx, first); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("deleting twice: err = %v, want ErrNotFound", err)
	}
}

func TestDeleteSessionCascades(t *testing.T) {
	ctx := context.Background()
	r := open(t)
	seed(t, r, "doomed")
	seed(t, r, "kept")

	conn, err := r.CreateConnection(ctx, "doomed", fullConnection())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.CreateEntry(ctx, "doomed", conn, fullEntry()); err != nil {
		t.Fatal(err)
	}
	keptConn, err := r.CreateConnection(ctx, "kept", fullConnection())
	if err != nil {
		t.Fatal(err)
	}
	keptEntry, err := r.CreateEntry(ctx, "kept", keptConn, fullEntry())
	if err != nil {
		t.Fatal(err)
	}

	if err := r.DeleteSession(ctx, "doomed"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Session(ctx, "doomed"); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("deleted session still resolves: %v", err)
	}
	// Exactly the kept session's rows should remain: one entry and one connection,
	// with the child rows of that single entry and none of the deleted one's.
	counts := map[string]int{"sessions": 1, "entries": 1, "connections": 1}
	for _, table := range []string{"headers", "cookies", "query_params", "post_params", "cache_states"} {
		var n int
		if err := r.DB().QueryRowContext(ctx,
			`SELECT COUNT(*) FROM `+table+` WHERE entry_id = ?`, keptEntry).Scan(&n); err != nil {
			t.Fatal(err)
		}
		counts[table] = n // the kept entry's own rows, asserted non-zero below
		if n == 0 {
			t.Errorf("%s: the kept entry lost its rows", table)
		}
	}
	for table, want := range counts {
		var n int
		if err := r.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != want {
			t.Errorf("%s rows = %d, want %d — the deleted session left orphans", table, n, want)
		}
	}
	if _, err := r.Entry(ctx, keptEntry); err != nil {
		t.Errorf("other session's entry removed: %v", err)
	}
	if err := r.DeleteSession(ctx, "doomed"); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("deleting twice: err = %v, want ErrNotFound", err)
	}
}

func TestNotFound(t *testing.T) {
	ctx := context.Background()
	r := open(t)
	seed(t, r, "s1")

	if _, err := r.Session(ctx, "missing"); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("Session: err = %v, want ErrNotFound", err)
	}
	if _, err := r.Entry(ctx, 404); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("Entry: err = %v, want ErrNotFound", err)
	}
	if _, err := r.Connection(ctx, 404); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("Connection: err = %v, want ErrNotFound", err)
	}
	if _, err := r.CreateEntry(ctx, "missing", 0, fullEntry()); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("CreateEntry under an unknown session: err = %v, want ErrNotFound", err)
	}
	if _, err := r.CreateConnection(ctx, "missing", fullConnection()); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("CreateConnection under an unknown session: err = %v, want ErrNotFound", err)
	}
	if _, err := r.CreateEntry(ctx, "s1", 404, fullEntry()); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("CreateEntry with an unknown connection: err = %v, want ErrNotFound", err)
	}
}

func TestCreateEntryRejectsForeignConnection(t *testing.T) {
	ctx := context.Background()
	r := open(t)
	seed(t, r, "a")
	seed(t, r, "b")

	conn, err := r.CreateConnection(ctx, "a", fullConnection())
	if err != nil {
		t.Fatal(err)
	}
	// Attributing b's entry to a's connection would misreport the fingerprint the
	// transaction was observed under.
	if _, err := r.CreateEntry(ctx, "b", conn, fullEntry()); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound for a connection from another session", err)
	}
}

func TestMigrationsAreIdempotentOnDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	ctx := context.Background()

	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	seed(t, first, "s1")
	id, err := first.CreateEntry(ctx, "s1", 0, fullEntry())
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := Open(path)
	if err != nil {
		t.Fatalf("reopening an existing store must be a no-op migration: %v", err)
	}
	defer second.Close()
	if _, err := second.Entry(ctx, id); err != nil {
		t.Errorf("entry lost across reopen: %v", err)
	}
	var applied int
	if err := second.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Errorf("schema_migrations rows = %d, want 1", applied)
	}
}

func TestForeignKeysAreEnforced(t *testing.T) {
	ctx := context.Background()
	r := open(t)

	// The pragma is what makes ownership real; without it the cascades above are
	// silently inert.
	_, err := r.DB().ExecContext(ctx,
		`INSERT INTO entries (session_id, created_at, started_date_time, req_method, req_url, req_http_version, resp_status, resp_http_version)
		 VALUES (999, 0, '', 'GET', 'https://x/', 'HTTP/2.0', 200, 'HTTP/2.0')`)
	if err == nil {
		t.Error("inserting an entry under an unknown session should violate the foreign key")
	}
}

func TestStrictTablesRejectMistypedValues(t *testing.T) {
	ctx := context.Background()
	r := open(t)
	seed(t, r, "s1")

	// STRICT is what stops SQLite from coercing a value into a column's type and
	// handing back something other than what was stored.
	_, err := r.DB().ExecContext(ctx,
		`INSERT INTO entries (session_id, created_at, started_date_time, req_method, req_url, req_http_version, resp_status, resp_http_version)
		 VALUES ((SELECT id FROM sessions WHERE name='s1'), 0, '', 'GET', 'https://x/', 'HTTP/2.0', 'not-a-number', 'HTTP/2.0')`)
	if err == nil {
		t.Error("a text value in an INTEGER column should be rejected by a STRICT table")
	}
}
