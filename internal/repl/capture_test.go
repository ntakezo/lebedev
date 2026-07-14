package repl

import (
	"context"
	"testing"

	"github.com/ntakezo/lebedev/har"
	"github.com/ntakezo/lebedev/internal/ca"
	"github.com/ntakezo/lebedev/internal/store"
	"github.com/ntakezo/lebedev/model"
)

func testEntry(url string) model.Entry {
	return model.Entry{
		StartedDateTime: "2026-07-13T00:00:00.000Z",
		Request:         har.Request{Method: "GET", URL: url, HTTPVersion: "HTTP/2.0", Cookies: []har.Cookie{}, Headers: []har.NVP{}, QueryString: []har.NVP{}, HeadersSize: -1},
		Response:        har.Response{Status: 200, StatusText: "OK", HTTPVersion: "HTTP/2.0", Cookies: []har.Cookie{}, Headers: []har.NVP{}, HeadersSize: -1, Content: har.Content{}},
		Cache:           har.Cache{},
		Timings:         har.Timings{},
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

// TestStopResume verifies that a capture can be stopped and then resumed on the
// same bound address, and that the in-memory session survives the pause.
func TestStopResume(t *testing.T) {
	authority, err := ca.Generate("test")
	if err != nil {
		t.Fatal(err)
	}
	c, err := startCapture("s1", "127.0.0.1:0", "", authority)
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()

	if !c.running {
		t.Fatal("expected capture to be running after start")
	}
	addr := c.addr()

	// An entry recorded before the pause must still be there afterward.
	c.Insert(context.Background(), "s1", testEntry("https://a/1"), 1)

	if err := c.stop(); err != nil {
		t.Fatal(err)
	}
	if c.running {
		t.Fatal("expected capture to be stopped after stop")
	}

	if err := c.resume(); err != nil {
		t.Fatal(err)
	}
	if !c.running {
		t.Fatal("expected capture to be running after resume")
	}
	if got := c.addr(); got != addr {
		t.Fatalf("resumed on %s, want same address %s", got, addr)
	}
	if n, _ := c.count(context.Background()); n != 1 {
		t.Fatalf("entry count after resume = %d, want 1 (session survives pause)", n)
	}
}
