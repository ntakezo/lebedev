package capture

import (
	"bytes"
	"net"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestServeHTTP2CapturesOrderAndFingerprint(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type captured struct {
		req Request
		fp  HTTP2Fingerprint
	}
	got := make(chan captured, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		ServeHTTP2(conn, func(r Request, fp HTTP2Fingerprint) (Response, error) {
			got <- captured{r, fp}
			return Response{
				Status:  200,
				Headers: []Header{{"content-type", "text/plain"}},
				Body:    []byte("ok"),
			}, nil
		})
	}()

	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	cc.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := cc.Write([]byte(clientPreface)); err != nil {
		t.Fatal(err)
	}
	cf := http2.NewFramer(cc, cc)
	cf.ReadMetaHeaders = hpack.NewDecoder(4096, nil)

	// Distinctive SETTINGS order + values, a connection WINDOW_UPDATE, and a
	// PRIORITY frame — all must be captured verbatim for upstream mirroring.
	cf.WriteSettings(
		http2.Setting{ID: http2.SettingHeaderTableSize, Val: 65536},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 6291456},
		http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: 262144},
	)
	cf.WriteWindowUpdate(0, 15663105)
	cf.WritePriority(1, http2.PriorityParam{StreamDep: 0, Weight: 255, Exclusive: false})

	var hb bytes.Buffer
	he := hpack.NewEncoder(&hb)
	// Chrome-style pseudo order: method, authority, scheme, path.
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/submit"},
		{Name: "content-type", Value: "application/x-www-form-urlencoded"},
		{Name: "user-agent", Value: "Mozilla/5.0"},
	} {
		he.WriteField(f)
	}
	cf.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hb.Bytes(),
		EndStream:     false,
		EndHeaders:    true,
	})
	cf.WriteData(1, true, []byte("a=1&b=2&c=3"))

	var c captured
	select {
	case c = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("handler never invoked")
	}

	r := c.req
	if r.Method() != "POST" || r.Target() != "/submit" || r.Scheme() != "https" || r.Authority() != "example.com" {
		t.Fatalf("request line: %q %q %q %q", r.Method(), r.Target(), r.Scheme(), r.Authority())
	}
	if r.Proto() != "HTTP/2.0" {
		t.Errorf("proto = %q", r.Proto())
	}
	wantPseudo := []string{":method", ":authority", ":scheme", ":path"}
	if !equalStrings(r.PseudoOrder(), wantPseudo) {
		t.Errorf("pseudoOrder = %v, want %v", r.PseudoOrder(), wantPseudo)
	}
	wantHeaders := []Header{
		{"content-type", "application/x-www-form-urlencoded"},
		{"user-agent", "Mozilla/5.0"},
	}
	hs := r.Headers()
	if len(hs) != len(wantHeaders) {
		t.Fatalf("headers = %+v", hs)
	}
	for i := range hs {
		if hs[i] != wantHeaders[i] {
			t.Errorf("header[%d] = %+v, want %+v", i, hs[i], wantHeaders[i])
		}
	}
	if string(r.Body()) != "a=1&b=2&c=3" {
		t.Errorf("body = %q", r.Body())
	}

	fp := c.fp
	wantSettings := []Setting{
		{uint16(http2.SettingHeaderTableSize), 65536},
		{uint16(http2.SettingInitialWindowSize), 6291456},
		{uint16(http2.SettingMaxHeaderListSize), 262144},
	}
	ss := fp.Settings()
	if len(ss) != len(wantSettings) {
		t.Fatalf("settings = %+v", ss)
	}
	for i := range ss {
		if ss[i] != wantSettings[i] {
			t.Errorf("setting[%d] = %+v, want %+v", i, ss[i], wantSettings[i])
		}
	}
	if fp.ConnectionFlow() != 15663105 {
		t.Errorf("connectionFlow = %d", fp.ConnectionFlow())
	}
	if ps := fp.Priorities(); len(ps) != 1 || ps[0].Weight != 255 || ps[0].StreamID != 1 {
		t.Errorf("priorities = %+v", ps)
	}
}

// TestServeHTTP2HandlesStreamsConcurrently proves the handler runs for multiple
// in-flight streams at once: both handlers must be entered before either is
// allowed to return. Under a serialized (one-stream-at-a-time) implementation the
// first handler would block the read loop and the second would never be entered,
// so this test would time out.
func TestServeHTTP2HandlesStreamsConcurrently(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		ServeHTTP2(conn, func(_ Request, _ HTTP2Fingerprint) (Response, error) {
			entered <- struct{}{}
			<-release
			return Response{Status: 200, Body: []byte("ok")}, nil
		})
	}()

	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	cc.SetDeadline(time.Now().Add(5 * time.Second))
	cc.Write([]byte(clientPreface))

	cf := http2.NewFramer(cc, cc)
	writeGet := func(id uint32) {
		var hb bytes.Buffer
		he := hpack.NewEncoder(&hb)
		for _, f := range []hpack.HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: ":authority", Value: "example.com"},
			{Name: ":scheme", Value: "https"},
			{Name: ":path", Value: "/"},
		} {
			he.WriteField(f)
		}
		cf.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: hb.Bytes(), EndStream: true, EndHeaders: true})
	}
	cf.WriteSettings()
	writeGet(1)
	writeGet(3)

	for i := range 2 {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of 2 stream handlers ran concurrently", i)
		}
	}
	close(release)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
