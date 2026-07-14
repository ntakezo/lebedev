// Package upstream forwards captured requests to their origin through a
// tls-client whose TLS ClientHello and HTTP/2 traits reproduce the client that
// was captured, so the origin cannot distinguish the proxy from that client.
package upstream

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"sync"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"

	"github.com/ntakezo/lebedev/internal/capture"
)

// Mirror is a per-connection upstream client whose fingerprint reproduces one
// captured client. Reuse it for every request on that client's connection.
//
// h2Client is a deterministic HTTP/2 (or HTTP/1.1) client that never attempts
// QUIC, used for every request until the origin advertises HTTP/3. up, non-nil
// only for h2 clients, carries the Alt-Svc-driven upgrade state and the lazily
// built racing client that mirrors a browser switching an origin to h3.
type Mirror struct {
	h2Client tlsclient.HttpClient
	usedH2   bool
	up       *h3upgrade
}

// h3upgrade holds one authority's HTTP/3 upgrade state, shared across the
// concurrent requests multiplexed on a client connection. advertised records
// whether the origin's Alt-Svc offered h3; the racing client is built once, on
// first use, so origins that never advertise h3 never pay for it. Its zero value
// is not usable; build must be set. All fields are guarded by mu.
type h3upgrade struct {
	mu         sync.Mutex
	advertised bool
	built      bool
	client     tlsclient.HttpClient
	buildErr   error
	build      func() (tlsclient.HttpClient, error)
}

// wantH3 reports whether the origin has advertised HTTP/3, so the next request
// should be sent through the racing client instead of the plain h2 client.
func (u *h3upgrade) wantH3() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.advertised
}

// racingClient returns the shared happy-eyeballs client, building it on first
// use. A build failure is cached so callers fall back to h2 without retrying.
func (u *h3upgrade) racingClient() (tlsclient.HttpClient, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.built {
		u.client, u.buildErr = u.build()
		u.built = true
	}
	return u.client, u.buildErr
}

// observe folds an origin response's Alt-Svc header into the upgrade decision:
// a response advertising h3 arms the racing client for subsequent requests, and
// one that carries Alt-Svc without an h3 token (including "clear") disarms it.
// Responses with no Alt-Svc leave the current decision untouched.
func (u *h3upgrade) observe(h http.Header) {
	if !altSvcPresent(h) {
		return
	}
	offers := altSvcOffersH3(h)
	u.mu.Lock()
	u.advertised = offers
	u.mu.Unlock()
}

// NewMirror builds an upstream client that reproduces the captured client's TLS
// ClientHello (from the full ClientHello TLS record in rawClientHello) and its
// h2 traits (fp). clientUsedH2 selects the origin-facing protocol so an h1
// client is mirrored over h1 and an h2 client over h2. When proxyURL is
// non-empty, origin traffic is routed through that outbound proxy. For TLS 1.3
// clients the mirror enables session resumption so repeat connections to an
// origin resume like a real revisiting browser instead of always full-handshaking.
// The client neither follows redirects nor manages cookies, so both are
// forwarded to the caller.
// The origin-facing protocol tracks the client but can also upgrade: an h2
// client starts on HTTP/2 and, once an origin's Alt-Svc advertises HTTP/3, its
// subsequent requests to that origin race h3 against h2 and prefer whichever
// connects first, mirroring a browser that discovers h3 in-band and switches to
// it (falling back to h2 when QUIC is blocked). Because a TCP capture carries no
// QUIC fingerprint, the h3 traits are synthesized from the client's browser
// family (see buildProfile). An h1 client is never upgraded.
func NewMirror(rawClientHello []byte, fp capture.HTTP2Fingerprint, clientUsedH2 bool, proxyURL string) (Mirror, error) {
	profile, err := buildProfile(rawClientHello, fp)
	if err != nil {
		return Mirror{}, err
	}

	base := []tlsclient.HttpClientOption{
		tlsclient.WithClientProfile(profile),
		tlsclient.WithNotFollowRedirects(),
		// Disable transport compression handling: without it the client injects an
		// "Accept-Encoding: gzip" header the captured client never sent (when the
		// client omitted the header) and transparently decompresses responses. Both
		// break fidelity — the origin must see exactly the client's Accept-Encoding,
		// and the response body must be forwarded on the wire as the origin sent it.
		tlsclient.WithTransportOptions(&tlsclient.TransportOptions{DisableCompression: true}),
	}
	if proxyURL != "" {
		base = append(base, tlsclient.WithProxyUrl(proxyURL))
	}

	if !clientUsedH2 {
		// WithForceHttp1 also rewrites the mirrored ALPN to ["http/1.1"], but this
		// path is only reached when the client never offered h2 (the proxy prefers
		// h2), so the captured ALPN is already http/1.1-only or absent — no mismatch.
		// h1 clients never speak h3, so there is no upgrade path.
		client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), append(slices.Clone(base), tlsclient.WithForceHttp1())...)
		if err != nil {
			return Mirror{}, err
		}
		return Mirror{h2Client: client, usedH2: false}, nil
	}

	// WithDisableHttp3 keeps the default client strictly on h2/h1: the mirror only
	// touches QUIC after an origin advertises h3, never speculatively on first
	// contact, so an origin that never sends Alt-Svc is mirrored exactly as before.
	h2Client, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), append(slices.Clone(base), tlsclient.WithDisableHttp3())...)
	if err != nil {
		return Mirror{}, err
	}
	up := &h3upgrade{
		// WithProtocolRacing is tls-client's Chrome-style happy-eyeballs racer: it
		// prefers h3 but falls back to h2 when QUIC cannot connect, and caches the
		// winning protocol per origin so only the first post-upgrade request races.
		build: func() (tlsclient.HttpClient, error) {
			return tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), append(slices.Clone(base), tlsclient.WithProtocolRacing())...)
		},
	}
	return Mirror{h2Client: h2Client, usedH2: true, up: up}, nil
}

// RoundTrip sends req to its origin and returns the origin's response. Request
// header order and pseudo-header order are reproduced via fhttp's order keys
// (which match case-insensitively, so order entries are lowercased while the
// map preserves the original casing); the body is forwarded byte-for-byte with
// framing derived from its length.
func (m Mirror) RoundTrip(req capture.Request) (capture.Response, error) {
	hr, err := m.buildRequest(req)
	if err != nil {
		return capture.Response{}, err
	}

	resp, err := m.do(hr)
	if err != nil {
		return capture.Response{}, err
	}
	defer resp.Body.Close()

	if m.up != nil {
		// Learn the origin's h3 route from this response so later requests on the
		// connection can upgrade; a browser reads Alt-Svc off ordinary responses too.
		m.up.observe(resp.Header)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return capture.Response{}, err
	}
	return capture.Response{
		Status:  resp.StatusCode,
		Headers: flattenHeaders(resp.Header),
		Proto:   resp.Proto,
		Body:    respBody,
	}, nil
}

// do sends hr over the origin-facing client, using the racing (h3-capable)
// client once the origin has advertised HTTP/3 and the plain h2 client
// otherwise. If the racing client cannot be built, it falls back to h2 so a
// mirrored request is never dropped over an h3 setup failure.
func (m Mirror) do(hr *http.Request) (*http.Response, error) {
	if m.up != nil && m.up.wantH3() {
		if client, err := m.up.racingClient(); err == nil {
			return client.Do(hr)
		}
	}
	return m.h2Client.Do(hr)
}

// buildRequest turns a captured request into an fhttp request that reproduces
// its header order (via the lowercased order key), header casing (via the map
// keys), pseudo-header order, and body. Framing headers that fhttp writes itself
// (Host and, on h1, Content-Length/Transfer-Encoding) are kept out of the header
// map to avoid duplicate emission but kept in the order key at their captured
// position: fhttp's writer places its own value by looking the lowercased name up
// in that order, so a POST's Host and Content-Length land where the client put
// them instead of being sorted to the end of the block.
func (m Mirror) buildRequest(req capture.Request) (*http.Request, error) {
	b := req.Body()
	var body io.Reader
	if b != nil {
		body = bytes.NewReader(b)
	}

	target := req.Scheme() + "://" + req.Authority() + req.Target()
	hr, err := http.NewRequest(req.Method(), target, body)
	if err != nil {
		return nil, err
	}
	hr.Host = req.Authority()
	if !m.usedH2 && req.Chunked() {
		// Preserve the client's chunked framing instead of collapsing the body to
		// Content-Length. fhttp re-chunks the decoded body; exact chunk boundaries
		// are not reproduced, but the Transfer-Encoding framing the origin sees is.
		hr.TransferEncoding = []string{"chunked"}
		hr.ContentLength = 0
	} else {
		hr.ContentLength = int64(len(b))
	}

	order := make([]string, 0, len(req.Headers()))
	for _, h := range req.Headers() {
		order = append(order, strings.ToLower(h.Name))
		if m.framedByTransport(h.Name) {
			continue
		}
		hr.Header[h.Name] = append(hr.Header[h.Name], h.Value)
	}
	hr.Header[http.HeaderOrderKey] = order
	if po := req.PseudoOrder(); po != nil {
		hr.Header[http.PHeaderOrderKey] = po
	}
	return hr, nil
}

// framedByTransport reports whether a captured header's value is written by fhttp
// rather than copied from the request map, so it must be excluded from the map to
// avoid being emitted twice. Its position is still preserved via the order key.
// Host is carried by the URL; on h1 Content-Length and Transfer-Encoding are
// derived from the body's framing. On h2 the transport dedups Content-Length, so
// it is kept in the map (h2 requests carry no Host or Transfer-Encoding header).
func (m Mirror) framedByTransport(name string) bool {
	switch strings.ToLower(name) {
	case "host", "transfer-encoding":
		return true
	case "content-length":
		return !m.usedH2
	}
	return false
}

func buildProfile(rawClientHello []byte, fp capture.HTTP2Fingerprint) (profiles.ClientProfile, error) {
	// RealPSKResumption makes a captured pre_shared_key extension reconstruct as a
	// cache-managed UtlsPreSharedKeyExtension instead of a FakePreSharedKeyExtension
	// that would replay the client's stale (proxy-session) PSK binder to the origin.
	spec, err := (&utls.Fingerprinter{RealPSKResumption: true}).FingerprintClientHello(rawClientHello)
	if err != nil {
		return profiles.ClientProfile{}, err
	}
	addPSK := needsResumptionPSK(spec)

	helloID := utls.ClientHelloID{
		Client:  "Mirror",
		Version: "0",
		// SpecFactory is called once per handshake and once by tls-client to decide
		// whether to enable its session cache. Append a fresh, empty PSK extension
		// for TLS 1.3 clients that advertise psk_key_exchange_modes but sent no PSK
		// (a first-visit hello): it turns on tls-client's session resumption cache so
		// reconnects to the origin resume like a real revisiting browser, and (with
		// tls-client's OmitEmptyPsk) it is concealed on the wire until a real ticket
		// exists, so the first handshake's fingerprint is unchanged. A fresh instance
		// per call keeps per-connection PSK state from being shared.
		SpecFactory: func() (utls.ClientHelloSpec, error) {
			s := *spec
			if addPSK {
				exts := make([]utls.TLSExtension, len(spec.Extensions), len(spec.Extensions)+1)
				copy(exts, spec.Extensions)
				s.Extensions = append(exts, &utls.UtlsPreSharedKeyExtension{})
			}
			return s, nil
		},
	}

	settings, order := h2Settings(fp)
	// A TCP capture has no QUIC transport parameters or h3 SETTINGS to mirror, so
	// the h3 fingerprint is synthesized from the client's browser family (inferred
	// from the h2 pseudo-header order). It is applied to every profile but only
	// takes effect once the mirror actually upgrades an origin to h3.
	h3 := h3ProfileFor(matchFamily(fp.PseudoOrder()))
	return profiles.NewClientProfile(
		helloID,
		settings,
		order,
		fp.PseudoOrder(),
		fp.ConnectionFlow(),
		h2Priorities(fp),
		nil,   // headerPriority
		1,     // streamID
		false, // allowHTTP
		h3.settings,
		h3.settingsOrder,
		h3.priorityParam,
		h3.pseudoOrder,
		h3.sendGrease,
	), nil
}

// needsResumptionPSK reports whether spec is a TLS 1.3 hello that advertises
// psk_key_exchange_modes but carries no pre_shared_key extension — i.e. a
// first-visit hello for which a PSK extension must be added to enable upstream
// session resumption. It returns false when a PSK extension is already present
// (resumption is enabled) or when the client is not TLS 1.3 (no PSK modes).
func needsResumptionPSK(spec *utls.ClientHelloSpec) bool {
	hasModes := false
	for _, ext := range spec.Extensions {
		switch ext.(type) {
		case utls.PreSharedKeyExtension:
			return false
		case *utls.PSKKeyExchangeModesExtension:
			hasModes = true
		}
	}
	return hasModes
}

func h2Settings(fp capture.HTTP2Fingerprint) (map[http2.SettingID]uint32, []http2.SettingID) {
	captured := fp.Settings()
	settings := make(map[http2.SettingID]uint32, len(captured))
	order := make([]http2.SettingID, 0, len(captured))
	for _, s := range captured {
		id := http2.SettingID(s.ID)
		settings[id] = s.Value
		order = append(order, id)
	}
	return settings, order
}

func h2Priorities(fp capture.HTTP2Fingerprint) []http2.Priority {
	captured := fp.Priorities()
	out := make([]http2.Priority, 0, len(captured))
	for _, p := range captured {
		out = append(out, http2.Priority{
			StreamID: p.StreamID,
			PriorityParam: http2.PriorityParam{
				StreamDep: p.StreamDep,
				Exclusive: p.Exclusive,
				Weight:    p.Weight,
			},
		})
	}
	return out
}

func flattenHeaders(h http.Header) []capture.Header {
	out := make([]capture.Header, 0, len(h))
	for name, vals := range h {
		for _, v := range vals {
			out = append(out, capture.Header{Name: name, Value: v})
		}
	}
	return out
}
