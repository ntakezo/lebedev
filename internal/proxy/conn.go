package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	nethttp "net/http"
	"strings"

	"github.com/ntakezo/lebedev/internal/capture"
)

// prefixConn is a net.Conn whose reads are served from r (typically the peeked
// ClientHello bytes followed by the live connection) while writes and the
// connection's other behavior pass through to the embedded conn.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// readConnect reads a CONNECT request line and its headers from br and returns
// the tunnel target (host:port). It leaves the reader positioned at the client's
// first post-CONNECT byte, i.e. the start of the TLS ClientHello.
func readConnect(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.EqualFold(fields[0], "CONNECT") {
		return "", fmt.Errorf("proxy: expected CONNECT, got %q", strings.TrimSpace(line))
	}
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(h) == "" {
			return fields[1], nil
		}
	}
}

// peekClientHello reads the first TLS record (the ClientHello) from br without
// discarding it: it returns the raw record bytes for fingerprinting plus a conn
// that replays those bytes before continuing from the live connection, so a
// TLS server can complete the handshake normally.
func peekClientHello(br *bufio.Reader, conn net.Conn) ([]byte, net.Conn, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(br, header); err != nil {
		return nil, nil, err
	}
	if header[0] != 0x16 {
		return nil, nil, fmt.Errorf("proxy: expected TLS handshake record, got type %d", header[0])
	}

	length := int(header[3])<<8 | int(header[4])
	body := make([]byte, length)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, nil, err
	}

	raw := make([]byte, 0, len(header)+len(body))
	raw = append(raw, header...)
	raw = append(raw, body...)

	prefixed := &prefixConn{Conn: conn, r: io.MultiReader(bytes.NewReader(raw), br)}
	return raw, prefixed, nil
}

// writeH1Response writes resp as an HTTP/1.1 message, framing the body with an
// authoritative Content-Length and dropping hop-by-hop headers that would
// conflict with that framing.
func writeH1Response(w io.Writer, resp capture.Response) error {
	status := resp.Status
	if status == 0 {
		status = nethttp.StatusBadGateway
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, statusText(status))
	for _, h := range resp.Headers {
		if isHopByHop(h.Name) {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\r\n", h.Name, h.Value)
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(resp.Body))
	b.WriteString("Connection: keep-alive\r\n\r\n")
	b.Write(resp.Body)

	_, err := w.Write(b.Bytes())
	return err
}

func errorResponse(err error) capture.Response {
	return capture.Response{
		Status:  nethttp.StatusBadGateway,
		Headers: []capture.Header{{Name: "Content-Type", Value: "text/plain"}},
		Body:    []byte(err.Error()),
	}
}

func isHopByHop(name string) bool {
	switch strings.ToLower(name) {
	case "content-length", "transfer-encoding", "connection":
		return true
	}
	return false
}

func statusText(code int) string {
	if t := nethttp.StatusText(code); t != "" {
		return t
	}
	return "Status"
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
