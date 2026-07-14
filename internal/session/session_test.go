package session

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ntakezo/lebedev/internal/capture"
	"github.com/ntakezo/lebedev/internal/proxy"
)

func TestSinkEmitsFaithfulJSONLine(t *testing.T) {
	req, err := capture.Read(strings.NewReader(
		"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc"))
	if err != nil {
		t.Fatal(err)
	}

	tx := proxy.Transaction{
		ClientHello: []byte{0x16, 0x03, 0x01, 0x00, 0x01, 0xff},
		Request:     req,
		Response: capture.Response{
			Status:  200,
			Headers: []capture.Header{{Name: "Content-Type", Value: "text/plain"}},
			Body:    []byte("ok"),
		},
	}

	var buf bytes.Buffer
	sink := NewSink(&buf)
	if err := sink.Emit(toRecord("s1", tx)); err != nil {
		t.Fatal(err)
	}
	if err := sink.Emit(toRecord("s1", tx)); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSON lines, got %d", len(lines))
	}

	var rec Record
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("record is not valid JSON: %v", err)
	}
	if rec.Session != "s1" || rec.Protocol != "HTTP/1.1" {
		t.Errorf("session/protocol = %q %q", rec.Session, rec.Protocol)
	}
	if rec.Request.Method != "POST" || rec.Request.Target != "/submit" || rec.Request.Authority != "example.com" {
		t.Errorf("request = %+v", rec.Request)
	}
	if rec.Request.Body != "abc" {
		t.Errorf("request body = %q", rec.Request.Body)
	}
	if rec.Response.Status != 200 || rec.Response.Body != "ok" {
		t.Errorf("response = %+v", rec.Response)
	}
	if rec.TLS.ClientHelloHex != "1603010001ff" {
		t.Errorf("clientHelloHex = %q", rec.TLS.ClientHelloHex)
	}
	if rec.HTTP2 != nil {
		t.Errorf("h1 record should not carry http2 details: %+v", rec.HTTP2)
	}
	// Upstream spoke the same protocol as the client, so proto is omitted.
	if rec.Response.Proto != "" {
		t.Errorf("response proto should be empty when it matches the client: %q", rec.Response.Proto)
	}
}

// TestRecordSurfacesUpstreamHTTP3 asserts that when the mirror upgrades the origin
// to HTTP/3, the record surfaces the diverging upstream protocol, and that a
// matching upstream protocol stays omitted.
func TestRecordSurfacesUpstreamHTTP3(t *testing.T) {
	req, err := capture.Read(strings.NewReader("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	upgraded := toRecord("s1", proxy.Transaction{
		Request:  req,
		Response: capture.Response{Status: 200, Proto: "HTTP/3.0"},
	})
	if upgraded.Response.Proto != "HTTP/3.0" {
		t.Errorf("upgraded response proto = %q, want HTTP/3.0", upgraded.Response.Proto)
	}

	same := toRecord("s1", proxy.Transaction{
		Request:  req,
		Response: capture.Response{Status: 200, Proto: "HTTP/1.1"},
	})
	if same.Response.Proto != "" {
		t.Errorf("matching upstream proto should be omitted, got %q", same.Response.Proto)
	}
}
