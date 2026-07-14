package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/ntakezo/lebedev/internal/ca"
	"github.com/ntakezo/lebedev/internal/capture"
)

// stubDialer records what the proxy captured and returns a canned response,
// standing in for the real fingerprint-mirroring upstream so the proxy can be
// exercised without touching the network.
type stubDialer struct{ rt *stubRT }

func (d stubDialer) forConn(rawHello []byte, fp capture.HTTP2Fingerprint, h2 bool) (roundTripper, error) {
	d.rt.hello = rawHello
	d.rt.h2 = h2
	return d.rt, nil
}

type stubRT struct {
	mu    sync.Mutex
	reqs  []capture.Request
	hello []byte
	h2    bool
	resp  capture.Response
}

func (r *stubRT) RoundTrip(req capture.Request) (capture.Response, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = append(r.reqs, req)
	return r.resp, nil
}

func TestProxyH1EndToEnd(t *testing.T) {
	txs := make(chan Transaction, 1)
	authority, rt, addr := startProxy(t, capture.Response{
		Status:  200,
		Headers: []capture.Header{{Name: "Content-Type", Value: "text/plain"}},
		Body:    []byte("hello"),
	}, Options{OnTransaction: func(tx Transaction) { txs <- tx }})

	tc := connectAndHandshake(t, addr, authority, []string{"http/1.1"})
	defer tc.Close()
	if tc.ConnectionState().NegotiatedProtocol != "http/1.1" {
		t.Fatalf("ALPN = %q", tc.ConnectionState().NegotiatedProtocol)
	}

	io.WriteString(tc, "GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "hello" {
		t.Errorf("response = %d %q", resp.StatusCode, body)
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()
	if len(rt.reqs) != 1 {
		t.Fatalf("captured %d requests", len(rt.reqs))
	}
	r := rt.reqs[0]
	if r.Method() != "GET" || r.Target() != "/path" || r.Authority() != "example.com" {
		t.Errorf("captured %q %q %q", r.Method(), r.Target(), r.Authority())
	}
	if rt.h2 {
		t.Error("expected h1 forwarding")
	}
	if len(rt.hello) == 0 || rt.hello[0] != 0x16 {
		t.Errorf("raw ClientHello not captured: %v", rt.hello[:min(4, len(rt.hello))])
	}

	select {
	case tx := <-txs:
		if tx.Request.Target() != "/path" || string(tx.Response.Body) != "hello" {
			t.Errorf("observed transaction = %q %q", tx.Request.Target(), tx.Response.Body)
		}
	case <-time.After(time.Second):
		t.Error("OnTransaction never fired")
	}
}

func TestProxyH2EndToEnd(t *testing.T) {
	authority, rt, addr := startProxy(t, capture.Response{
		Status:  200,
		Headers: []capture.Header{{Name: "content-type", Value: "text/plain"}},
		Body:    []byte("h2 ok"),
	}, Options{})

	tc := connectAndHandshake(t, addr, authority, []string{"h2"})
	defer tc.Close()
	if tc.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatalf("ALPN = %q", tc.ConnectionState().NegotiatedProtocol)
	}

	io.WriteString(tc, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	cf := http2.NewFramer(tc, tc)
	cf.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	cf.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 6291456})

	var hb bytes.Buffer
	he := hpack.NewEncoder(&hb)
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/h2path"},
		{Name: "user-agent", Value: "test"},
	} {
		he.WriteField(f)
	}
	cf.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hb.Bytes(), EndStream: true, EndHeaders: true})

	status, body := readH2Response(t, cf)
	if status != "200" || body != "h2 ok" {
		t.Errorf("response = %q %q", status, body)
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()
	if len(rt.reqs) != 1 || rt.reqs[0].Target() != "/h2path" || rt.reqs[0].Proto() != "HTTP/2.0" {
		t.Fatalf("captured %+v", rt.reqs)
	}
	if !rt.h2 {
		t.Error("expected h2 forwarding")
	}
}

func startProxy(t *testing.T, resp capture.Response, opts Options) (*ca.Authority, *stubRT, string) {
	t.Helper()
	authority, err := ca.Generate("Lebedev Test CA")
	if err != nil {
		t.Fatal(err)
	}
	rt := &stubRT{resp: resp}
	s := New(authority, opts)
	s.dialer = stubDialer{rt: rt}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go s.Serve(ln)
	return authority, rt, ln.Addr().String()
}

func connectAndHandshake(t *testing.T, addr string, authority *ca.Authority, alpn []string) *tls.Conn {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	raw.SetDeadline(time.Now().Add(5 * time.Second))

	fmt.Fprintf(raw, "CONNECT example.com:443 HTTP/1.1\r\n\r\n")
	br := bufio.NewReader(raw)
	if _, err := http.ReadResponse(br, nil); err != nil {
		t.Fatalf("CONNECT reply: %v", err)
	}
	if br.Buffered() != 0 {
		t.Fatalf("proxy sent %d bytes before TLS", br.Buffered())
	}

	tc := tls.Client(raw, &tls.Config{
		ServerName: "example.com",
		RootCAs:    caPool(t, authority),
		NextProtos: alpn,
	})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return tc
}

func readH2Response(t *testing.T, cf *http2.Framer) (status, body string) {
	t.Helper()
	var buf bytes.Buffer
	for {
		frame, err := cf.ReadFrame()
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		switch f := frame.(type) {
		case *http2.MetaHeadersFrame:
			for _, hf := range f.Fields {
				if hf.Name == ":status" {
					status = hf.Value
				}
			}
			if f.StreamEnded() {
				return status, buf.String()
			}
		case *http2.DataFrame:
			buf.Write(f.Data())
			if f.StreamEnded() {
				return status, buf.String()
			}
		}
	}
}

func caPool(t *testing.T, a *ca.Authority) *x509.CertPool {
	t.Helper()
	block, _ := pem.Decode(a.CertPEM())
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}
