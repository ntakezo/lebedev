package repl

import (
	"context"
	"testing"

	"github.com/ntakezo/lebedev/internal/store"
)

func testEntry(url string) store.Entry {
	return store.Entry{
		StartedDateTime: "2026-07-13T00:00:00.000Z",
		Request:         store.Request{Method: "GET", URL: url, HTTPVersion: "HTTP/2.0", Cookies: []store.Cookie{}, Headers: []store.NVP{}, QueryString: []store.NVP{}, HeadersSize: -1},
		Response:        store.Response{Status: 200, StatusText: "OK", HTTPVersion: "HTTP/2.0", Cookies: []store.Cookie{}, Headers: []store.NVP{}, HeadersSize: -1, Content: store.Content{}},
		Cache:           store.Cache{},
		Timings:         store.Timings{},
	}
}

// newTestCapture builds a capture wired to an in-memory store without starting a
// proxy, so its recording behaviour can be exercised directly.
func newTestCapture(t *testing.T) *capture {
	t.Helper()
	mem, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mem.Close() })
	return &capture{id: "s1", mem: mem}
}

// TestCaptureInsert verifies that inserted entries land in the in-memory store.
func TestCaptureInsert(t *testing.T) {
	ctx := context.Background()
	c := newTestCapture(t)

	c.Insert(ctx, "s1", testEntry("https://a/1"), 1)
	c.Insert(ctx, "s1", testEntry("https://a/2"), 2)

	n, err := c.mem.Count(ctx, store.Query{Session: "s1"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("in-memory count = %d, want 2", n)
	}
}

// TestSave verifies that save copies the live session's in-memory entries to the
// durable store and that re-saving overwrites rather than duplicates.
func TestSave(t *testing.T) {
	ctx := context.Background()
	durable, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer durable.Close()

	c := newTestCapture(t)
	r := New(durable, nil, "", nil)
	r.out = discard{}
	r.current = c

	// Nothing captured yet — durable stays empty.
	r.cmdSave(ctx)
	if got, _ := durable.Count(ctx, store.Query{Session: "s1"}); got != 0 {
		t.Fatalf("durable count before capture = %d, want 0", got)
	}

	// Capture two entries, then save.
	c.Insert(ctx, "s1", testEntry("https://a/1"), 1)
	c.Insert(ctx, "s1", testEntry("https://a/2"), 2)
	r.cmdSave(ctx)
	if got, _ := durable.Count(ctx, store.Query{Session: "s1"}); got != 2 {
		t.Fatalf("durable count after save = %d, want 2", got)
	}

	// A third entry plus a re-save snapshots the whole session without duplicating.
	c.Insert(ctx, "s1", testEntry("https://a/3"), 3)
	r.cmdSave(ctx)
	if got, _ := durable.Count(ctx, store.Query{Session: "s1"}); got != 3 {
		t.Fatalf("durable count after re-save = %d, want 3 (overwrite, no dupes)", got)
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
