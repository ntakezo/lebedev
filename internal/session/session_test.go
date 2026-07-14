package session

import (
	"strings"
	"testing"
	"time"

	"github.com/ntakezo/lebedev/internal/capture"
	"github.com/ntakezo/lebedev/internal/proxy"
)

func TestEntryFromTransactionIsFaithful(t *testing.T) {
	req, err := capture.Read(strings.NewReader(
		"POST /submit?q=hi&n=1 HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nabc"))
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

	e := entryFromTransaction("s1", tx, time.Unix(0, 0).UTC())

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
	if e.Lebedev == nil || e.Lebedev.ClientHelloHex != "1603010001ff" || e.Lebedev.Session != "s1" {
		t.Errorf("lebedev = %+v", e.Lebedev)
	}
	if e.Lebedev.HTTP2 != nil {
		t.Errorf("h1 entry should carry no http2 fingerprint: %+v", e.Lebedev.HTTP2)
	}
	if e.Lebedev.UpstreamProto != "" {
		t.Errorf("upstream proto should be empty when it matches the client: %q", e.Lebedev.UpstreamProto)
	}
}

func TestEntryBinaryBodyIsBase64(t *testing.T) {
	req, err := capture.Read(strings.NewReader("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	binary := []byte{0x00, 0xff, 0xfe, 0x80}
	e := entryFromTransaction("s1", proxy.Transaction{
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

// TestEntrySurfacesUpstreamHTTP3 asserts that an upstream HTTP/3 upgrade is
// surfaced on the custom _lebedev field while the client-facing httpVersion
// reflects the actual protocol spoken.
func TestEntrySurfacesUpstreamHTTP3(t *testing.T) {
	req, err := capture.Read(strings.NewReader("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	e := entryFromTransaction("s1", proxy.Transaction{
		Request:  req,
		Response: capture.Response{Status: 200, Proto: "HTTP/3.0"},
	}, time.Unix(0, 0).UTC())
	if e.Lebedev.UpstreamProto != "HTTP/3.0" {
		t.Errorf("upstream proto = %q, want HTTP/3.0", e.Lebedev.UpstreamProto)
	}
	if e.Response.HTTPVersion != "HTTP/3.0" {
		t.Errorf("response httpVersion = %q, want HTTP/3.0", e.Response.HTTPVersion)
	}
}
