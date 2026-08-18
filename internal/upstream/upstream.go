// Package upstream forwards captured requests to their origin through an fhttp
// tls-client wearing the stock latest-Chrome profile, so the origin sees a real
// browser's TLS ClientHello and HTTP/2 traits rather than a proxy's.
//
// The captured client's own fingerprint is recorded but no longer replayed; what
// the caller hands over — header order, casing, and body bytes — is still sent
// verbatim. This package is a placeholder for a fuller rewrite.
package upstream

import (
	"bytes"
	"io"
	"slices"
	"strings"

	http "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"

	"github.com/ntakezo/lebedev/internal/capture"
)

// stockChromeProfile is the newest Chrome profile tls-client ships: Chrome 150
// with real PSK resumption, so the client resumes sessions upstream the way a
// revisiting browser does. Bump it when a newer profile lands.
var stockChromeProfile = profiles.Chrome_150_PSK

// Client is a per-connection upstream client. Reuse it for every request on the
// client connection it was built for. The zero value is not usable; construct
// one with NewStockChrome.
type Client struct {
	http   tlsclient.HttpClient
	usedH2 bool
}

// NewStockChrome builds an upstream client that sends every request with the
// stock latest-Chrome profile: the ClientHello, h2 SETTINGS, and pseudo-header
// order all come from the profile. clientUsedH2 keeps an h1 client on h1, and a
// non-empty proxyURL routes origin traffic through that outbound proxy. The
// client neither follows redirects nor manages cookies, so both are forwarded to
// the caller.
func NewStockChrome(clientUsedH2 bool, proxyURL string) (Client, error) {
	opts := []tlsclient.HttpClientOption{
		tlsclient.WithClientProfile(stockChromeProfile),
		tlsclient.WithNotFollowRedirects(),
		// Disable transport compression handling: without it the client injects an
		// "Accept-Encoding: gzip" header the captured client never sent (when the
		// client omitted the header) and transparently decompresses responses. Both
		// break fidelity — the origin must see exactly the client's Accept-Encoding,
		// and the response body must be forwarded on the wire as the origin sent it.
		tlsclient.WithTransportOptions(&tlsclient.TransportOptions{DisableCompression: true}),
		// Stay on h2/h1: QUIC is left to the rewrite rather than raced here.
		tlsclient.WithDisableHttp3(),
	}
	if proxyURL != "" {
		opts = append(opts, tlsclient.WithProxyUrl(proxyURL))
	}
	if !clientUsedH2 {
		opts = append(slices.Clone(opts), tlsclient.WithForceHttp1())
	}

	c, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), opts...)
	if err != nil {
		return Client{}, err
	}
	return Client{http: c, usedH2: clientUsedH2}, nil
}

// RoundTrip sends req to its origin and returns the origin's response. Request
// header order is reproduced via fhttp's order key (which matches
// case-insensitively, so order entries are lowercased while the map preserves the
// original casing); the body is forwarded byte-for-byte with framing derived from
// its length.
func (c Client) RoundTrip(req capture.Request) (capture.Response, error) {
	hr, err := c.buildRequest(req)
	if err != nil {
		return capture.Response{}, err
	}

	resp, err := c.http.Do(hr)
	if err != nil {
		return capture.Response{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return capture.Response{}, err
	}
	return capture.Response{
		Status:  resp.StatusCode,
		Headers: flattenHeaders(resp.Header),
		Proto:   resp.Proto,
		Body:    body,
	}, nil
}

// buildRequest turns a captured request into an fhttp request that reproduces its
// header order (via the lowercased order key), header casing (via the map keys),
// and body. The pseudo-header order is left to the profile, which carries its
// own. Framing headers that fhttp writes itself (Host and, on h1,
// Content-Length/Transfer-Encoding) are kept out of the header map to avoid
// duplicate emission but kept in the order key at their captured position:
// fhttp's writer places its own value by looking the lowercased name up in that
// order, so a POST's Host and Content-Length land where the client put them
// instead of being sorted to the end of the block.
func (c Client) buildRequest(req capture.Request) (*http.Request, error) {
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
	if !c.usedH2 && req.Chunked() {
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
		if c.framedByTransport(h.Name) {
			continue
		}
		hr.Header[h.Name] = append(hr.Header[h.Name], h.Value)
	}
	hr.Header[http.HeaderOrderKey] = order
	return hr, nil
}

// framedByTransport reports whether a captured header's value is written by fhttp
// rather than copied from the request map, so it must be excluded from the map to
// avoid being emitted twice. Its position is still preserved via the order key.
// Host is carried by the URL; on h1 Content-Length and Transfer-Encoding are
// derived from the body's framing. On h2 the transport dedups Content-Length, so
// it is kept in the map (h2 requests carry no Host or Transfer-Encoding header).
func (c Client) framedByTransport(name string) bool {
	switch strings.ToLower(name) {
	case "host", "transfer-encoding":
		return true
	case "content-length":
		return !c.usedH2
	}
	return false
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
