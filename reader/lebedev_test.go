package lebedev

import (
	"context"
	"errors"
	"testing"

	"github.com/ntakezo/lebedev/har"
	"github.com/ntakezo/lebedev/internal/store"
	"github.com/ntakezo/lebedev/model"
)

// newReader builds a Reader over a fresh in-memory store and returns both so a
// test can seed through the store's write path and read through the facade.
func newReader(t *testing.T) (*Reader, *store.Store) {
	t.Helper()
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &Reader{store: st, ownsDB: true}, st
}

func sampleEntry(method, url string, status int) model.Entry {
	return model.Entry{
		StartedDateTime: "2026-07-14T00:00:00.000Z",
		Request: har.Request{
			Method:      method,
			URL:         url,
			HTTPVersion: "HTTP/2.0",
			Headers:     []har.NVP{{Name: "user-agent", Value: "UA"}, {Name: "accept", Value: "*/*"}},
			Cookies:     []har.Cookie{{Name: "sid", Value: "xyz"}},
			HeadersSize: -1,
			BodySize:    -1,
		},
		Response: har.Response{
			Status:      status,
			StatusText:  "OK",
			HTTPVersion: "HTTP/2.0",
			Headers:     []har.NVP{{Name: "content-type", Value: "application/json"}},
			Content:     har.Content{Size: 2, MimeType: "application/json", Text: "{}"},
			HeadersSize: -1,
			BodySize:    2,
		},
		Lebedev: &model.Lebedev{Session: "s1", ClientHelloHex: "1603010001ff"},
	}
}

func TestSessionAndEntry(t *testing.T) {
	ctx := context.Background()
	r, st := newReader(t)
	id1, _ := st.Insert(ctx, "s1", sampleEntry("GET", "https://a/1", 200), 0)
	id2, _ := st.Insert(ctx, "s1", sampleEntry("POST", "https://a/2", 201), 1)
	st.Insert(ctx, "s2", sampleEntry("GET", "https://b/1", 200), 0)

	// Sessions lists both, with counts.
	sessions, err := r.Sessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 || sessions[0].Name != "s1" || sessions[0].Entries != 2 {
		t.Fatalf("sessions = %+v", sessions)
	}

	// Session by name returns entries in insertion order, header order preserved.
	s, err := r.Session(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Entries) != 2 || s.Entries[0].ID != id1 || s.Entries[1].ID != id2 {
		t.Fatalf("session entries = %+v", s.Entries)
	}
	got := s.Entries[0].Entry.Request.Headers
	if len(got) != 2 || got[0].Name != "user-agent" || got[1].Name != "accept" {
		t.Fatalf("header order not preserved: %+v", got)
	}

	// Entry by (session, id) is authoritative: right pair resolves, wrong session
	// or unknown id is ErrNotFound.
	e, err := r.Entry(ctx, "s1", id2)
	if err != nil {
		t.Fatal(err)
	}
	if e.Entry.Request.Method != "POST" {
		t.Fatalf("entry method = %q", e.Entry.Request.Method)
	}
	if _, err := r.Entry(ctx, "s2", id2); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-session lookup err = %v, want ErrNotFound", err)
	}
	if _, err := r.Entry(ctx, "s1", 99999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id err = %v, want ErrNotFound", err)
	}
	if _, err := r.Session(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown session err = %v, want ErrNotFound", err)
	}
}

func TestEscapeHatches(t *testing.T) {
	ctx := context.Background()
	r, st := newReader(t)
	st.Insert(ctx, "s1", sampleEntry("GET", "https://a/1", 200), 0)
	id2, _ := st.Insert(ctx, "s1", sampleEntry("POST", "https://a/2", 201), 1)

	// Tier 1: structured Query + Count.
	n, err := r.Count(ctx, Query{Session: "s1", Method: "POST"})
	if err != nil || n != 1 {
		t.Fatalf("count = %d, err = %v", n, err)
	}

	// Tier 2: raw predicate against the entries table, using a Col* constant.
	got, err := r.Where(ctx, ColStatus+" = ?", 201)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != id2 {
		t.Fatalf("where = %+v", got)
	}

	// Tier 3: fully custom SQL selects ids, Hydrate reassembles byte-faithfully.
	rows, err := r.DB().QueryContext(ctx, r.Rebind("SELECT id FROM entries WHERE req_method = ? ORDER BY id"), "POST")
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	hydrated, err := r.Hydrate(ctx, ids...)
	if err != nil {
		t.Fatal(err)
	}
	if len(hydrated) != 1 || hydrated[0].Entry.Request.URL != "https://a/2" {
		t.Fatalf("hydrate = %+v", hydrated)
	}
	// Hydrated entry is fully reassembled, not just the entries row.
	if len(hydrated[0].Entry.Request.Headers) != 2 {
		t.Fatalf("hydrate did not load child rows: %+v", hydrated[0].Entry.Request.Headers)
	}
}
