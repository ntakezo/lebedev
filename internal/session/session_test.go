package session

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ntakezo/lebedev/internal/capture"
	"github.com/ntakezo/lebedev/internal/proxy"
	"github.com/ntakezo/lebedev/model"
)

func TestEntryFromTransactionIsFaithful(t *testing.T) {
	req, err := capture.Read(strings.NewReader(
		"POST /submit?q=hi&n=1 HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nabc"))
	if err != nil {
		t.Fatal(err)
	}

	tx := proxy.Transaction{
		Conn:    proxy.Conn{ID: 1, ClientHello: []byte{0x16, 0x03, 0x01, 0x00, 0x01, 0xff}},
		Request: req,
		Response: capture.Response{
			Status:  200,
			Headers: []capture.Header{{Name: "Content-Type", Value: "text/plain"}},
			Body:    []byte("ok"),
		},
	}

	e := entryFromTransaction(tx, time.Unix(0, 0).UTC())

	if e.Request.Method != "POST" || e.Request.URL != "https://example.com/submit?q=hi&n=1" {
		t.Errorf("request line = %q %q", e.Request.Method, e.Request.URL)
	}
	if e.Request.HTTPVersion != "HTTP/1.1" {
		t.Errorf("httpVersion = %q", e.Request.HTTPVersion)
	}
	if len(e.Request.QueryString) != 2 || e.Request.QueryString[0].Name != "q" || e.Request.QueryString[1].Value != "1" {
		t.Errorf("queryString = %+v", e.Request.QueryString)
	}
	if e.Request.PostData == nil || e.Request.PostData.Text != "abc" || e.Request.PostData.MimeType != "text/plain" {
		t.Errorf("postData = %+v", e.Request.PostData)
	}
	if e.Response.Status != 200 || e.Response.StatusText != "OK" {
		t.Errorf("response status = %d %q", e.Response.Status, e.Response.StatusText)
	}
	if e.Response.Content.Text != "ok" || e.Response.Content.MimeType != "text/plain" || e.Response.Content.Size != 2 {
		t.Errorf("content = %+v", e.Response.Content)
	}
	// The fingerprint belongs to the connection, not the entry.
	if e.Lebedev != nil {
		t.Errorf("entry should carry no _lebedev field: %+v", e.Lebedev)
	}

	c := connectionFromTransaction("s1", tx)
	if c.Session != "s1" || c.ClientHelloHex != "1603010001ff" {
		t.Errorf("connection = %+v", c)
	}
	if c.HTTP2 != nil {
		t.Errorf("h1 connection should carry no http2 fingerprint: %+v", c.HTTP2)
	}
	if c.UpstreamProto != "" {
		t.Errorf("upstream proto should be empty when it matches the client: %q", c.UpstreamProto)
	}
}

func TestEntryBinaryBodyIsBase64(t *testing.T) {
	req, err := capture.Read(strings.NewReader("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	binary := []byte{0x00, 0xff, 0xfe, 0x80}
	e := entryFromTransaction(proxy.Transaction{
		Request:  req,
		Response: capture.Response{Status: 200, Body: binary},
	}, time.Unix(0, 0).UTC())

	if e.Response.Content.Encoding != "base64" {
		t.Fatalf("non-UTF-8 body should be base64-flagged, got encoding %q", e.Response.Content.Encoding)
	}
	if e.Response.Content.Text != "AP/+gA==" {
		t.Errorf("base64 text = %q", e.Response.Content.Text)
	}
}

// TestConnectionSurfacesDivergentUpstreamProto asserts that an upstream protocol
// differing from the client's is recorded on the connection, while the entry's
// client-facing httpVersion reflects the protocol actually spoken.
func TestConnectionSurfacesDivergentUpstreamProto(t *testing.T) {
	req, err := capture.Read(strings.NewReader("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	tx := proxy.Transaction{
		Request:  req,
		Response: capture.Response{Status: 200, Proto: "HTTP/3.0"},
	}
	if got := connectionFromTransaction("s1", tx).UpstreamProto; got != "HTTP/3.0" {
		t.Errorf("upstream proto = %q, want HTTP/3.0", got)
	}
	if got := entryFromTransaction(tx, time.Unix(0, 0).UTC()).Response.HTTPVersion; got != "HTTP/3.0" {
		t.Errorf("response httpVersion = %q, want HTTP/3.0", got)
	}
}

// TestRecordStoresOneConnectionPerClientConnection asserts the normalization the
// storage layout depends on: transactions sharing a client connection produce one
// connection record, and a second connection produces another.
func TestRecordStoresOneConnectionPerClientConnection(t *testing.T) {
	req, err := capture.Read(strings.NewReader("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	rec := &stubRecorder{}
	s := New(Config{ID: "s1"}, nil, rec)

	tx := func(conn int64) proxy.Transaction {
		return proxy.Transaction{
			Conn:     proxy.Conn{ID: conn, ClientHello: []byte{0x16}},
			Request:  req,
			Response: capture.Response{Status: 200},
		}
	}
	s.record(tx(1))
	s.record(tx(1))
	s.record(tx(2))

	if rec.connections != 2 {
		t.Errorf("connection records = %d, want 2 (one per client connection)", rec.connections)
	}
	if len(rec.entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(rec.entries))
	}
	if rec.entries[0] != rec.entries[1] {
		t.Errorf("entries on one connection referenced %d and %d", rec.entries[0], rec.entries[1])
	}
	if rec.entries[2] == rec.entries[0] {
		t.Errorf("a second client connection reused connection %d", rec.entries[2])
	}
}

// stubRecorder counts connection records and remembers which connection each
// entry was attributed to.
type stubRecorder struct {
	connections int
	entries     []int64
}

func (r *stubRecorder) CreateConnection(_ context.Context, _ string, _ model.Connection) (int64, error) {
	r.connections++
	return int64(r.connections), nil
}

func (r *stubRecorder) CreateEntry(_ context.Context, _ string, connection int64, _ model.Entry) (int64, error) {
	r.entries = append(r.entries, connection)
	return int64(len(r.entries)), nil
}
