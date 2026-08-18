package upstream

import (
	"bytes"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	http "github.com/bogdanfinn/fhttp"
	xh2 "golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/ntakezo/lebedev/internal/capture"
)

func TestBuildRequestH1WireFraming(t *testing.T) {
	req, err := capture.Read(strings.NewReader(
		"POST /submit HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"User-Agent: UA\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 5\r\n" +
			"Accept: */*\r\n\r\nhello"))
	if err != nil {
		t.Fatal(err)
	}

	hr, err := Client{usedH2: false}.buildRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := hr.Write(&buf); err != nil {
		t.Fatal(err)
	}
	wire := buf.String()

	if n := strings.Count(wire, "Content-Length:"); n != 1 {
		t.Errorf("Content-Length appears %d times, want 1:\n%s", n, wire)
	}
	if strings.Contains(strings.ToLower(wire), "transfer-encoding") {
		t.Errorf("transfer-encoding should be dropped:\n%s", wire)
	}

	ua, ct, ac := strings.Index(wire, "User-Agent:"), strings.Index(wire, "Content-Type:"), strings.Index(wire, "Accept:")
	if ua < 0 || ct < 0 || ac < 0 {
		t.Fatalf("headers missing or recased:\n%s", wire)
	}
	if !(ua < ct && ct < ac) {
		t.Errorf("captured order not preserved (ua=%d ct=%d ac=%d):\n%s", ua, ct, ac, wire)
	}
	if !strings.HasSuffix(wire, "\r\n\r\nhello") {
		t.Errorf("body altered:\n%s", wire)
	}
}

func TestBuildRequestH1PreservesFramingHeaderOrder(t *testing.T) {
	req, err := capture.Read(strings.NewReader(
		"POST /submit HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"User-Agent: UA\r\n" +
			"Accept: */*\r\n" +
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			"Content-Length: 5\r\n" +
			"Origin: https://example.com\r\n\r\nhello"))
	if err != nil {
		t.Fatal(err)
	}

	hr, err := Client{usedH2: false}.buildRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := hr.Write(&buf); err != nil {
		t.Fatal(err)
	}
	wire := buf.String()

	// Host and Content-Length are framed by fhttp, but must appear at the client's
	// captured positions, not sorted to the end of the header block.
	names := []string{"Host:", "User-Agent:", "Accept:", "Content-Type:", "Content-Length:", "Origin:"}
	idx := make([]int, len(names))
	for i, n := range names {
		if idx[i] = strings.Index(wire, n); idx[i] < 0 {
			t.Fatalf("header %q missing:\n%s", n, wire)
		}
	}
	for i := 1; i < len(idx); i++ {
		if idx[i-1] >= idx[i] {
			t.Errorf("header order not preserved: %q at %d before %q at %d:\n%s",
				names[i], idx[i], names[i-1], idx[i-1], wire)
		}
	}
	if strings.Count(wire, "Content-Length:") != 1 {
		t.Errorf("Content-Length must be emitted exactly once:\n%s", wire)
	}
}

func TestBuildRequestH1PreservesChunkedFraming(t *testing.T) {
	req, err := capture.Read(strings.NewReader(
		"POST /u HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"User-Agent: UA\r\n" +
			"Transfer-Encoding: chunked\r\n\r\n" +
			"5\r\nhello\r\n0\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !req.Chunked() {
		t.Fatal("capture should mark the request chunked")
	}

	hr, err := Client{usedH2: false}.buildRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := hr.Write(&buf); err != nil {
		t.Fatal(err)
	}
	wire := buf.String()

	if !strings.Contains(strings.ToLower(wire), "transfer-encoding: chunked") {
		t.Errorf("chunked framing not preserved:\n%s", wire)
	}
	if strings.Contains(strings.ToLower(wire), "content-length:") {
		t.Errorf("chunked request must not carry Content-Length:\n%s", wire)
	}
	if !strings.HasSuffix(wire, "5\r\nhello\r\n0\r\n\r\n") {
		t.Errorf("chunked body framing altered:\n%s", wire)
	}
}

func TestBuildRequestContentLengthByProtocol(t *testing.T) {
	req := captureH2Request(t, []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/p"},
		{Name: "content-type", Value: "text/plain"},
		{Name: "content-length", Value: "3"},
	}, []byte("abc"))

	hr2, err := Client{usedH2: true}.buildRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := hr2.Header["content-length"]; !ok {
		t.Error("h2: content-length should be kept in the header map")
	}
	if !slices.Contains(hr2.Header[http.HeaderOrderKey], "content-length") {
		t.Error("h2: content-length should appear in the header order")
	}

	hr1, err := Client{usedH2: false}.buildRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := hr1.Header["content-length"]; ok {
		t.Error("h1: content-length should be dropped from the header map")
	}
}

// captureH2Request drives a synthetic h2 client through capture and returns the
// single request it produced.
func captureH2Request(t *testing.T, fields []hpack.HeaderField, body []byte) capture.Request {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	got := make(chan capture.Request, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		capture.ServeHTTP2(conn, func(r capture.Request, _ capture.HTTP2Fingerprint) (capture.Response, error) {
			got <- r
			return capture.Response{Status: 200, Body: []byte("ok")}, nil
		})
	}()

	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	cc.SetDeadline(time.Now().Add(5 * time.Second))
	cc.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))

	cf := xh2.NewFramer(cc, cc)
	cf.WriteSettings()
	var hb bytes.Buffer
	he := hpack.NewEncoder(&hb)
	for _, f := range fields {
		he.WriteField(f)
	}
	cf.WriteHeaders(xh2.HeadersFrameParam{StreamID: 1, BlockFragment: hb.Bytes(), EndStream: body == nil, EndHeaders: true})
	if body != nil {
		cf.WriteData(1, true, body)
	}

	select {
	case r := <-got:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("no request captured")
		return capture.Request{}
	}
}

// TestBuildProfileMirrorsFingerprint drives a real h2 client into capture to
// obtain a genuine fingerprint, then asserts buildProfile reproduces every
// mirrored trait and derives a usable ClientHello spec from raw ClientHello
// bytes.
func TestNewStockChromeBuildsClient(t *testing.T) {
	for _, h2 := range []bool{true, false} {
		c, err := NewStockChrome(h2, "")
		if err != nil {
			t.Fatal(err)
		}
		if c.http == nil {
			t.Fatalf("h2=%v: no client built", h2)
		}
		if c.usedH2 != h2 {
			t.Errorf("h2=%v: usedH2 = %v, want %v", h2, c.usedH2, h2)
		}
	}
	if got := stockChromeProfile.GetClientHelloStr(); got != "Chrome-150_PSK" {
		t.Errorf("stock profile = %q, want the latest Chrome PSK profile", got)
	}
}

// The stock profile carries its own pseudo-header order, so a captured one is
// never replayed over it.
func TestBuildRequestLeavesPseudoOrderToProfile(t *testing.T) {
	req := captureH2Request(t, []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/p"},
		{Name: "user-agent", Value: "UA"},
	}, nil)

	hr, err := Client{usedH2: true}.buildRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if po, ok := hr.Header[http.PHeaderOrderKey]; ok {
		t.Errorf("pseudo order should come from the profile, got %v", po)
	}
	if !slices.Contains(hr.Header[http.HeaderOrderKey], "user-agent") {
		t.Error("captured header order should still be reproduced")
	}
}
