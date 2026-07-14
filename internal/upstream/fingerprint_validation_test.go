package upstream

import (
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	utls "github.com/bogdanfinn/utls"

	"github.com/ntakezo/lebedev/internal/capture"
)

// TestMirrorPreservesJA3JA4 proves the upstream mirror reproduces a browser's TLS
// fingerprint: for each real browser ClientHello, it runs the bytes through the
// actual mirror pipeline (buildProfile → the ClientHello tls-client puts on the
// wire) and asserts the JA3 and JA4 of the reproduced hello equal the browser's.
//
// GREASE, key shares, and the client random differ on every hello, so the raw
// bytes never match — but JA3/JA4 strip exactly those, so equality here is the
// same equality a fingerprinting origin (tls.peet.ws, scrapfly, Cloudflare) sees.
//
// To validate against YOUR OWN browser instead of the synthesized profiles,
// capture a request through lebedev and copy the record from the session's
// tls.clientHelloHex field into internal/upstream/testdata/browser_hello.hex
// (or set LEBEDEV_HELLO_HEX). The captured case then runs automatically.
func TestMirrorPreservesJA3JA4(t *testing.T) {
	cases := []struct {
		name string
		id   utls.ClientHelloID
	}{
		{"Chrome_120", utls.HelloChrome_120},
		{"Chrome_131", utls.HelloChrome_131},
		{"Chrome_133", utls.HelloChrome_133},
		{"Firefox_120", utls.HelloFirefox_120},
		{"Safari_16_0", utls.HelloSafari_16_0},
		{"iOS_16_0", utls.HelloIOS_16_0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertReproduced(t, helloRecord(t, tc.id))
		})
	}

	if raw := capturedBrowserHello(t); raw != nil {
		t.Run("captured_browser", func(t *testing.T) {
			assertReproduced(t, raw)
		})
	}
}

// assertReproduced fingerprints the browser ClientHello record, runs it through
// the mirror, fingerprints the reproduced hello, and asserts both match.
func assertReproduced(t *testing.T, browserRecord []byte) {
	t.Helper()

	browser, err := parseClientHello(browserRecord)
	if err != nil {
		t.Fatalf("parse browser hello: %v", err)
	}
	browserJA3Str, browserJA3 := ja3(browser)
	browserJA4 := ja4(browser)

	mirrored, err := parseClientHello(mirroredHello(t, browserRecord))
	if err != nil {
		t.Fatalf("parse mirrored hello: %v", err)
	}
	mirroredJA3Str, mirroredJA3 := ja3(mirrored)
	mirroredJA4 := ja4(mirrored)

	t.Logf("browser  JA3=%s  JA4=%s", browserJA3, browserJA4)
	t.Logf("mirrored JA3=%s  JA4=%s", mirroredJA3, mirroredJA4)

	if mirroredJA3 != browserJA3 {
		t.Errorf("JA3 mismatch:\n  browser  %s = %s\n  mirrored %s = %s",
			browserJA3, browserJA3Str, mirroredJA3, mirroredJA3Str)
	}
	if mirroredJA4 != browserJA4 {
		t.Errorf("JA4 mismatch:\n  browser  %s\n  mirrored %s", browserJA4, mirroredJA4)
	}
}

// mirroredHello returns the exact ClientHello the mirror puts on the wire for a
// captured browser hello. It builds the mirror's ClientProfile from the raw
// record via the real buildProfile, then marshals the reconstructed spec through
// utls with the same Config tls-client's roundtripper uses (OmitEmptyPsk conceals
// the resumption PSK on the first handshake), so these are the bytes an origin
// receives — not a re-derivation of them.
func mirroredHello(t *testing.T, browserRecord []byte) []byte {
	t.Helper()
	// The HTTP/2 fingerprint governs SETTINGS/priorities, not the ClientHello, so a
	// zero value is fine here — this test is about the TLS layer.
	profile, err := buildProfile(browserRecord, capture.HTTP2Fingerprint{})
	if err != nil {
		t.Fatalf("buildProfile: %v", err)
	}
	spec, err := profile.GetClientHelloSpec()
	if err != nil {
		t.Fatalf("GetClientHelloSpec: %v", err)
	}

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	uc := utls.UClient(c1,
		&utls.Config{ServerName: "example.com", OmitEmptyPsk: true, InsecureSkipVerify: true},
		utls.HelloCustom, false, false, true)
	if err := uc.ApplyPreset(&spec); err != nil {
		t.Fatalf("ApplyPreset: %v", err)
	}
	if err := uc.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState: %v", err)
	}
	return uc.HandshakeState.Hello.Raw
}

// helloRecord builds a full ClientHello TLS record for a browser profile, as the
// proxy would peek off the wire and as buildProfile's Fingerprinter expects.
func helloRecord(t *testing.T, id utls.ClientHelloID) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	uc := utls.UClient(c1, &utls.Config{ServerName: "example.com"}, id, false, false, true)
	if err := uc.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	hello := uc.HandshakeState.Hello.Raw

	rec := make([]byte, 5+len(hello))
	rec[0] = 0x16 // handshake
	rec[1], rec[2] = 0x03, 0x01
	rec[3] = byte(len(hello) >> 8)
	rec[4] = byte(len(hello))
	copy(rec[5:], hello)
	return rec
}

// capturedBrowserHello loads a real ClientHello record captured from the user's
// own browser, from LEBEDEV_HELLO_HEX or testdata/browser_hello.hex. It returns
// nil (skipping the case) when neither is present, so the suite passes out of the
// box while still validating a real browser when one is supplied.
func capturedBrowserHello(t *testing.T) []byte {
	t.Helper()
	raw := os.Getenv("LEBEDEV_HELLO_HEX")
	if raw == "" {
		b, err := os.ReadFile(filepath.Join("testdata", "browser_hello.hex"))
		if err != nil {
			return nil
		}
		raw = string(b)
	}
	raw = strings.Join(strings.Fields(raw), "")
	if raw == "" {
		return nil
	}
	rec, err := hex.DecodeString(raw)
	if err != nil {
		t.Fatalf("decode captured hello hex: %v", err)
	}
	return rec
}

// TestJA4ShapeForChrome cross-checks the JA4 implementation against Chrome's known
// shape, so a passing equality test can't be "both sides wrong the same way": a
// TLS 1.3, SNI-bearing, h2-ALPN hello must produce a JA4_a of t13d...h2.
func TestJA4ShapeForChrome(t *testing.T) {
	h, err := parseClientHello(helloRecord(t, utls.HelloChrome_120))
	if err != nil {
		t.Fatal(err)
	}
	fp := ja4(h)
	if !strings.HasPrefix(fp, "t13d") {
		t.Errorf("Chrome JA4 should start with t13d (TLS 1.3, SNI present): %s", fp)
	}
	a := fp[:strings.IndexByte(fp, '_')]
	if !strings.HasSuffix(a, "h2") {
		t.Errorf("Chrome JA4_a should end in h2 (ALPN): %s", a)
	}
}
