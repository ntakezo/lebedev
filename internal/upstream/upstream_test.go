package upstream

import (
	"bytes"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	http "github.com/bogdanfinn/fhttp"
	bh2 "github.com/bogdanfinn/fhttp/http2"
	utls "github.com/bogdanfinn/utls"
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

	hr, err := Mirror{usedH2: false}.buildRequest(req)
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

	hr, err := Mirror{usedH2: false}.buildRequest(req)
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

	hr, err := Mirror{usedH2: false}.buildRequest(req)
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

	hr2, err := Mirror{usedH2: true}.buildRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := hr2.Header["content-length"]; !ok {
		t.Error("h2: content-length should be kept in the header map")
	}
	if !slices.Contains(hr2.Header[http.HeaderOrderKey], "content-length") {
		t.Error("h2: content-length should appear in the header order")
	}

	hr1, err := Mirror{usedH2: false}.buildRequest(req)
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
func TestBuildProfileMirrorsFingerprint(t *testing.T) {
	fp := captureFingerprint(t)

	profile, err := buildProfile(chromeHelloRecord(t), fp)
	if err != nil {
		t.Fatalf("buildProfile: %v", err)
	}

	settings := profile.GetSettings()
	if settings[bh2.SettingHeaderTableSize] != 65536 ||
		settings[bh2.SettingInitialWindowSize] != 6291456 ||
		settings[bh2.SettingMaxHeaderListSize] != 262144 {
		t.Errorf("settings = %+v", settings)
	}
	wantOrder := []bh2.SettingID{
		bh2.SettingHeaderTableSize,
		bh2.SettingInitialWindowSize,
		bh2.SettingMaxHeaderListSize,
	}
	if got := profile.GetSettingsOrder(); !equalSettingIDs(got, wantOrder) {
		t.Errorf("settingsOrder = %v, want %v", got, wantOrder)
	}
	if profile.GetConnectionFlow() != 15663105 {
		t.Errorf("connectionFlow = %d", profile.GetConnectionFlow())
	}
	if ps := profile.GetPriorities(); len(ps) != 1 || ps[0].PriorityParam.Weight != 255 {
		t.Errorf("priorities = %+v", ps)
	}
	wantPseudo := []string{":method", ":authority", ":scheme", ":path"}
	if got := profile.GetPseudoHeaderOrder(); !equalStrings(got, wantPseudo) {
		t.Errorf("pseudoOrder = %v, want %v", got, wantPseudo)
	}

	spec, err := profile.GetClientHelloSpec()
	if err != nil {
		t.Fatalf("GetClientHelloSpec: %v", err)
	}
	if len(spec.CipherSuites) == 0 || len(spec.Extensions) == 0 {
		t.Errorf("spec looks empty: %d suites, %d extensions", len(spec.CipherSuites), len(spec.Extensions))
	}
}

// TestNeedsResumptionPSK checks the gate that decides whether a PSK extension
// must be added to enable upstream session resumption.
func TestNeedsResumptionPSK(t *testing.T) {
	firstVisit := &utls.ClientHelloSpec{Extensions: []utls.TLSExtension{
		&utls.SNIExtension{},
		&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
	}}
	if !needsResumptionPSK(firstVisit) {
		t.Error("TLS 1.3 hello with psk_key_exchange_modes and no PSK: want add")
	}

	resuming := &utls.ClientHelloSpec{Extensions: []utls.TLSExtension{
		&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
		&utls.UtlsPreSharedKeyExtension{},
	}}
	if needsResumptionPSK(resuming) {
		t.Error("hello already carrying a PSK extension: want no add")
	}

	tls12 := &utls.ClientHelloSpec{Extensions: []utls.TLSExtension{&utls.SNIExtension{}}}
	if needsResumptionPSK(tls12) {
		t.Error("no psk_key_exchange_modes: want no add")
	}
}

// TestBuildProfileEnablesResumption asserts that a first-visit TLS 1.3 hello ends
// up with a cache-managed UtlsPreSharedKeyExtension as its final extension, which
// is what makes tls-client enable its session-resumption cache upstream.
func TestBuildProfileEnablesResumption(t *testing.T) {
	profile, err := buildProfile(chromeHelloRecord(t), captureFingerprint(t))
	if err != nil {
		t.Fatalf("buildProfile: %v", err)
	}
	spec, err := profile.GetClientHelloSpec()
	if err != nil {
		t.Fatalf("GetClientHelloSpec: %v", err)
	}
	if len(spec.Extensions) == 0 {
		t.Fatal("spec has no extensions")
	}
	last := spec.Extensions[len(spec.Extensions)-1]
	if _, ok := last.(*utls.UtlsPreSharedKeyExtension); !ok {
		t.Errorf("last extension = %T, want *utls.UtlsPreSharedKeyExtension", last)
	}
}

// captureFingerprint runs capture.ServeHTTP2 against a synthetic h2 client and
// returns the fingerprint it observed.
func captureFingerprint(t *testing.T) capture.HTTP2Fingerprint {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	got := make(chan capture.HTTP2Fingerprint, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		capture.ServeHTTP2(conn, func(_ capture.Request, fp capture.HTTP2Fingerprint) (capture.Response, error) {
			got <- fp
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
	cf.WriteSettings(
		xh2.Setting{ID: xh2.SettingHeaderTableSize, Val: 65536},
		xh2.Setting{ID: xh2.SettingInitialWindowSize, Val: 6291456},
		xh2.Setting{ID: xh2.SettingMaxHeaderListSize, Val: 262144},
	)
	cf.WriteWindowUpdate(0, 15663105)
	cf.WritePriority(1, xh2.PriorityParam{StreamDep: 0, Weight: 255})

	var hb bytes.Buffer
	he := hpack.NewEncoder(&hb)
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/"},
		{Name: "user-agent", Value: "Mozilla/5.0"},
	} {
		he.WriteField(f)
	}
	cf.WriteHeaders(xh2.HeadersFrameParam{StreamID: 1, BlockFragment: hb.Bytes(), EndStream: true, EndHeaders: true})

	select {
	case fp := <-got:
		return fp
	case <-time.After(5 * time.Second):
		t.Fatal("capture never produced a fingerprint")
		return capture.HTTP2Fingerprint{}
	}
}

// chromeHelloRecord builds a full ClientHello TLS record (record header +
// handshake) for a Chrome fingerprint, as FingerprintClientHello expects.
func chromeHelloRecord(t *testing.T) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	uc := utls.UClient(c1, &utls.Config{ServerName: "example.com"}, utls.HelloChrome_120, false, false, true)
	if err := uc.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	hello := uc.HandshakeState.Hello.Raw

	rec := make([]byte, 5+len(hello))
	rec[0] = 0x16 // handshake record
	rec[1] = 0x03
	rec[2] = 0x01
	rec[3] = byte(len(hello) >> 8)
	rec[4] = byte(len(hello))
	copy(rec[5:], hello)
	return rec
}

func equalSettingIDs(a, b []bh2.SettingID) bool {
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
