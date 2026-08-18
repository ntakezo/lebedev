package repl

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ntakezo/lebedev/har"
	"github.com/ntakezo/lebedev/internal/service"
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

// seed builds a service over a durable store holding one session with entries on
// a shared connection.
func seed(t *testing.T) *service.Service {
	t.Helper()
	durable, err := sqlite.Open("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { durable.Close() })

	ctx := context.Background()
	if _, err := durable.CreateSession(ctx, repository.Session{Name: "alpha"}); err != nil {
		t.Fatal(err)
	}
	conn, err := durable.CreateConnection(ctx, "alpha", model.Connection{
		ClientHelloHex: "16030100ff",
		HTTP2:          &model.HTTP2{PseudoOrder: []string{":method", ":path"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, url := range []string{"https://a/1", "https://a/2"} {
		if _, err := durable.CreateEntry(ctx, "alpha", conn, testEntry(url)); err != nil {
			t.Fatal(err)
		}
	}
	return service.New(durable, nil, "/tmp/ca.crt")
}

// run drives the REPL with a script and returns everything it printed.
func run(t *testing.T, svc *service.Service, lines ...string) string {
	t.Helper()
	var out bytes.Buffer
	if err := New(svc, &out).Run(strings.NewReader(strings.Join(append(lines, "quit"), "\n"))); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// TestReplSessionCRUD drives the store-management commands (no proxy) and checks
// that list, rename, and delete take effect and are reported.
func TestReplSessionCRUD(t *testing.T) {
	got := run(t, seed(t), "sessions", "rename alpha beta", "show beta", "rm beta", "sessions")

	for _, want := range []string{
		"alpha",
		`renamed "alpha" to "beta"`,
		"https://a/1",
		`deleted stored session "beta"`,
		"no sessions",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected output to contain %q:\n%s", want, got)
		}
	}
}

// TestReplReadsEntryAndConnection covers the single-record reads, which are what
// make a listing actionable.
func TestReplReadsEntryAndConnection(t *testing.T) {
	got := run(t, seed(t), "show alpha", "entry alpha 1", "conn alpha 1")

	if !strings.Contains(got, "conn 1") {
		t.Errorf("show should report each entry's connection:\n%s", got)
	}
	if !strings.Contains(got, `"url": "https://a/1"`) {
		t.Errorf("entry should print the HAR entry as JSON:\n%s", got)
	}
	if !strings.Contains(got, "16030100ff") || !strings.Contains(got, ":method, :path") {
		t.Errorf("conn should print the fingerprint:\n%s", got)
	}
}

// TestReplDeleteEntryKeepsConnection asserts the REPL surfaces the repository's
// rule that an entry's connection outlives it.
func TestReplDeleteEntryKeepsConnection(t *testing.T) {
	svc := seed(t)
	got := run(t, svc, "rm-entry alpha 1", "show alpha", "conn alpha 1")

	if !strings.Contains(got, `deleted entry 1 from session "alpha"`) {
		t.Errorf("expected delete confirmation:\n%s", got)
	}
	if strings.Contains(got, "https://a/1") {
		t.Errorf("deleted entry should be gone from the listing:\n%s", got)
	}
	if !strings.Contains(got, "https://a/2") {
		t.Errorf("sibling entry should survive:\n%s", got)
	}
	if !strings.Contains(got, "16030100ff") {
		t.Errorf("the shared connection should survive:\n%s", got)
	}
}

// TestReplReportsErrors checks that a failing service call is reported rather
// than swallowed.
func TestReplReportsErrors(t *testing.T) {
	got := run(t, seed(t), "show missing", "entry alpha 999", "save", "browser")

	for _, want := range []string{"show: ", "entry: ", "save: ", "browser: "} {
		if !strings.Contains(got, want) {
			t.Errorf("expected an error prefixed %q:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "no active capture") {
		t.Errorf("save and browser should report there is no capture:\n%s", got)
	}
}
