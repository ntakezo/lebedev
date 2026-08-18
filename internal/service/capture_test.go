package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ntakezo/lebedev/har"
	"github.com/ntakezo/lebedev/internal/ca"
	"github.com/ntakezo/lebedev/model"
	"github.com/ntakezo/lebedev/repository"
	"github.com/ntakezo/lebedev/repository/sqlite"
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

// openRepo builds an in-memory repository holding one empty session.
func openRepo(t *testing.T, session string) *sqlite.Repository {
	t.Helper()
	repo, err := sqlite.Open("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { repo.Close() })
	if _, err := repo.CreateSession(context.Background(), repository.Session{Name: session}); err != nil {
		t.Fatal(err)
	}
	return repo
}

// newTestCapture builds a capture wired to an in-memory repository without
// starting a proxy, so its recording behaviour can be exercised directly.
func newTestCapture(t *testing.T) *capture {
	t.Helper()
	return &capture{id: "s1", mem: openRepo(t, "s1")}
}

func TestCaptureCountsRecordedEntries(t *testing.T) {
	ctx := context.Background()
	c := newTestCapture(t)

	for _, url := range []string{"https://a/1", "https://a/2"} {
		if _, err := c.mem.CreateEntry(ctx, "s1", 0, testEntry(url)); err != nil {
			t.Fatal(err)
		}
	}

	n, err := c.count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("in-memory count = %d, want 2", n)
	}
}

// TestSaveCapture verifies that saving copies the live session to the durable
// repository, that re-saving overwrites rather than duplicates, and that entries
// sharing a connection still share one after the copy.
func TestSaveCapture(t *testing.T) {
	ctx := context.Background()
	durable, err := sqlite.Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer durable.Close()

	svc := New(durable, nil, "/tmp/ca.crt")
	svc.current = newTestCapture(t)
	mem := svc.current.mem

	// Nothing captured yet — durable stays empty.
	if _, err := svc.SaveCapture(ctx); !errors.Is(err, ErrEmptyCapture) {
		t.Fatalf("save of an empty capture: err = %v, want ErrEmptyCapture", err)
	}

	conn, err := mem.CreateConnection(ctx, "s1", model.Connection{ClientHelloHex: "1603"})
	if err != nil {
		t.Fatal(err)
	}
	for _, url := range []string{"https://a/1", "https://a/2"} {
		if _, err := mem.CreateEntry(ctx, "s1", conn, testEntry(url)); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := svc.SaveCapture(ctx); err != nil || n != 2 {
		t.Fatalf("save = %d, %v; want 2, nil", n, err)
	}
	d, err := durable.Session(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Entries) != 2 {
		t.Fatalf("durable entries after save = %d, want 2", len(d.Entries))
	}
	if len(d.Connections) != 1 {
		t.Fatalf("durable connections after save = %d, want 1 (the shared connection)", len(d.Connections))
	}
	for _, e := range d.Entries {
		if e.Connection != d.Connections[0].ID {
			t.Errorf("copied entry %d lost its connection", e.ID)
		}
	}

	// A third entry plus a re-save snapshots the whole session without duplicating.
	if _, err := mem.CreateEntry(ctx, "s1", conn, testEntry("https://a/3")); err != nil {
		t.Fatal(err)
	}
	if n, err := svc.SaveCapture(ctx); err != nil || n != 3 {
		t.Fatalf("re-save = %d, %v; want 3, nil (overwrite, no dupes)", n, err)
	}
	d, err = durable.Session(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Entries) != 3 {
		t.Fatalf("durable entries after re-save = %d, want 3", len(d.Entries))
	}
}

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
	if _, err := c.mem.CreateEntry(context.Background(), "s1", 0, testEntry("https://a/1")); err != nil {
		t.Fatal(err)
	}

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
