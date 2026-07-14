package capture

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestReadPreservesOrderCasingAndBody(t *testing.T) {
	// Non-canonical order and casing on purpose: a browser's real header order
	// and lowercase h2-style names must survive the parse verbatim.
	raw := "POST /submit HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"user-agent: Mozilla/5.0\r\n" +
		"Accept: */*\r\n" +
		"content-type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 11\r\n" +
		"\r\n" +
		"a=1&b=2&c=3"

	got, err := Read(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if got.Method() != "POST" || got.Target() != "/submit" || got.Proto() != "HTTP/1.1" {
		t.Fatalf("request line: %q %q %q", got.Method(), got.Target(), got.Proto())
	}

	want := []Header{
		{"Host", "example.com"},
		{"user-agent", "Mozilla/5.0"},
		{"Accept", "*/*"},
		{"content-type", "application/x-www-form-urlencoded"},
		{"Content-Length", "11"},
	}
	hs := got.Headers()
	if len(hs) != len(want) {
		t.Fatalf("header count = %d, want %d", len(hs), len(want))
	}
	for i, h := range hs {
		if h != want[i] {
			t.Errorf("header[%d] = %+v, want %+v", i, h, want[i])
		}
	}

	if string(got.Body()) != "a=1&b=2&c=3" {
		t.Errorf("body = %q", got.Body())
	}
}

func TestReadStopsAtBodyBoundary(t *testing.T) {
	// A second pipelined request must remain untouched on the reader.
	raw := "POST /a HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcGET /b HTTP/1.1\r\n\r\n"
	br := bufio.NewReader(strings.NewReader(raw))

	first, err := read(br)
	if err != nil {
		t.Fatalf("read first: %v", err)
	}
	if string(first.Body()) != "abc" {
		t.Fatalf("first body = %q", first.Body())
	}

	rest, _ := br.ReadString('\n')
	if !strings.HasPrefix(rest, "GET /b HTTP/1.1") {
		t.Errorf("reader over-consumed; next line = %q", rest)
	}
}

func TestBodyReturnsCopy(t *testing.T) {
	got, err := Read(strings.NewReader("POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi"))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	b := got.Body()
	b[0] = 'X'
	if bytes.Equal(got.Body(), b) {
		t.Error("Body() did not return a copy; internal state was mutated")
	}
}

func TestReadDecodesChunkedBody(t *testing.T) {
	// Two chunks (5 + 6 bytes) then a zero chunk, followed by a pipelined
	// request the reader must not consume.
	raw := "POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n" +
		"GET /b HTTP/1.1\r\n\r\n"
	br := bufio.NewReader(strings.NewReader(raw))

	first, err := read(br)
	if err != nil {
		t.Fatalf("read chunked: %v", err)
	}
	if string(first.Body()) != "hello world" {
		t.Errorf("decoded body = %q", first.Body())
	}

	rest, _ := br.ReadString('\n')
	if !strings.HasPrefix(rest, "GET /b HTTP/1.1") {
		t.Errorf("reader over-consumed past chunked body; next line = %q", rest)
	}
}

func TestReadDecodesChunkedWithTrailer(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"3\r\nabc\r\n0\r\nX-Trailer: v\r\n\r\n"
	got, err := Read(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got.Body()) != "abc" {
		t.Errorf("decoded body = %q", got.Body())
	}
}
