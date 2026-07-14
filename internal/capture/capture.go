// Package capture reads HTTP/1.1 requests off a client connection without
// canonicalizing header order, header casing, or the body, so the proxy can
// replay them upstream exactly as the client sent them.
package capture

import (
	"bufio"
	"fmt"
	"io"
	"net/http/httputil"
	"strconv"
	"strings"
)

// Header is one request header, preserving the client's original name casing
// and value bytes. A name/value pair has no invariants, so fields are exported.
type Header struct {
	Name  string
	Value string
}

// Response is the origin's reply, written back to the client. The client does
// not fingerprint the proxy, so this side is not order-preserved with the same
// rigor as the request path. Proto is the protocol the upstream mirror actually
// spoke to the origin (e.g. "HTTP/2.0" or "HTTP/3.0"), which can differ from the
// client-facing request protocol once the mirror upgrades an origin to HTTP/3;
// it is empty for locally synthesized responses such as upstream errors.
type Response struct {
	Status  int
	Headers []Header
	Proto   string
	Body    []byte
}

// Request is a parsed request with header order, header casing, and body bytes
// preserved, uniform across HTTP/1.1 and HTTP/2. For h1, scheme is https (the
// proxy terminates TLS), authority comes from the Host header, and pseudoOrder
// is empty; for h2 they come from the :scheme/:authority pseudo-headers and the
// wire order of all pseudo-headers. Fields stay unexported to keep the value
// immutable; accessors hand back copies so callers cannot mutate the original.
type Request struct {
	method      string
	target      string
	proto       string
	scheme      string
	authority   string
	headers     []Header
	pseudoOrder []string
	body        []byte
	chunked     bool
}

func (r Request) Method() string    { return r.method }
func (r Request) Target() string    { return r.target }
func (r Request) Proto() string     { return r.proto }
func (r Request) Scheme() string    { return r.scheme }
func (r Request) Authority() string { return r.authority }

// Chunked reports whether the client framed the request body with
// Transfer-Encoding: chunked. The body is stored decoded, but this lets the
// upstream mirror re-send it chunked instead of collapsing it to Content-Length,
// which would change the request framing the origin sees. Always false for h2.
func (r Request) Chunked() bool { return r.chunked }

// PseudoOrder returns a copy of the h2 pseudo-header order, or nil for h1.
func (r Request) PseudoOrder() []string {
	if r.pseudoOrder == nil {
		return nil
	}
	out := make([]string, len(r.pseudoOrder))
	copy(out, r.pseudoOrder)
	return out
}

// Headers returns a copy of the ordered headers.
func (r Request) Headers() []Header {
	out := make([]Header, len(r.headers))
	copy(out, r.headers)
	return out
}

// Body returns a copy of the raw request body, or nil when there is none.
func (r Request) Body() []byte {
	if r.body == nil {
		return nil
	}
	out := make([]byte, len(r.body))
	copy(out, r.body)
	return out
}

// read parses a single HTTP/1.1 request from r, consuming exactly the bytes the
// request occupies (request line, header block, and Content-Length body) so a
// following pipelined request is left intact on the reader.
func read(r *bufio.Reader) (Request, error) {
	line, err := readLine(r)
	if err != nil {
		return Request{}, err
	}
	method, target, proto, err := parseRequestLine(line)
	if err != nil {
		return Request{}, err
	}

	headers, err := readHeaders(r)
	if err != nil {
		return Request{}, err
	}

	body, err := readBody(r, headers)
	if err != nil {
		return Request{}, err
	}

	return Request{
		method:    method,
		target:    target,
		proto:     proto,
		scheme:    "https",
		authority: firstHeader(headers, "Host"),
		headers:   headers,
		body:      body,
		chunked:   hasChunked(headers),
	}, nil
}

func firstHeader(headers []Header, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// Read parses a single HTTP/1.1 request from conn.
func Read(conn io.Reader) (Request, error) {
	return read(bufio.NewReader(conn))
}

// ReadFrom parses a single HTTP/1.1 request from br, leaving any following
// pipelined request buffered for the next call. Loop over it to serve a
// keep-alive connection.
func ReadFrom(br *bufio.Reader) (Request, error) {
	return read(br)
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func parseRequestLine(line string) (method, target, proto string, err error) {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("capture: malformed request line %q", line)
	}
	return parts[0], parts[1], parts[2], nil
}

func readHeaders(r *bufio.Reader) ([]Header, error) {
	var headers []Header
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			return headers, nil
		}
		name, rawValue, ok := strings.Cut(trimmed, ":")
		if !ok {
			return nil, fmt.Errorf("capture: malformed header line %q", trimmed)
		}
		value := strings.TrimLeft(rawValue, " \t")
		headers = append(headers, Header{Name: name, Value: value})
	}
}

func readBody(r *bufio.Reader, headers []Header) ([]byte, error) {
	if hasChunked(headers) {
		return readChunked(r)
	}
	n, ok := contentLength(headers)
	if !ok || n == 0 {
		return nil, nil
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

// readChunked decodes a chunked-encoded body and then consumes the trailer
// section (any trailer headers and the terminating blank line) so the reader is
// left at the start of the next request.
func readChunked(r *bufio.Reader) ([]byte, error) {
	body, err := io.ReadAll(httputil.NewChunkedReader(r))
	if err != nil {
		return nil, err
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return body, nil
			}
			return nil, err
		}
		if strings.TrimRight(line, "\r\n") == "" {
			return body, nil
		}
	}
}

func contentLength(headers []Header) (int, bool) {
	for _, h := range headers {
		if strings.EqualFold(h.Name, "Content-Length") {
			n, err := strconv.Atoi(strings.TrimSpace(h.Value))
			if err != nil || n < 0 {
				return 0, false
			}
			return n, true
		}
	}
	return 0, false
}

func hasChunked(headers []Header) bool {
	for _, h := range headers {
		if strings.EqualFold(h.Name, "Transfer-Encoding") &&
			strings.Contains(strings.ToLower(h.Value), "chunked") {
			return true
		}
	}
	return false
}
