// Package proxy is the MITM core: it accepts CONNECT tunnels, peeks the raw
// ClientHello for fingerprinting, terminates TLS with a per-host leaf, captures
// the request faithfully (HTTP/1.1 or HTTP/2), and forwards it upstream through
// a client whose fingerprint is either the stock latest-Chrome profile or a
// mirror of the captured client's own (see Fingerprint).
package proxy

import (
	"bufio"
	"crypto/tls"
	"net"
	"sync/atomic"

	"github.com/ntakezo/lebedev/internal/ca"
	"github.com/ntakezo/lebedev/internal/capture"
	"github.com/ntakezo/lebedev/internal/upstream"
)

// roundTripper forwards one captured request to its origin.
type roundTripper interface {
	RoundTrip(capture.Request) (capture.Response, error)
}

// dialer builds a per-connection round tripper. h2 selects the origin-facing
// protocol so an h1 client is forwarded over h1. It is an interface so tests can
// forward without touching the network.
type dialer interface {
	forConn(h2 bool) (roundTripper, error)
}

// stockChromeDialer sends every request with the stock latest-Chrome profile.
type stockChromeDialer struct{ proxyURL string }

func (d stockChromeDialer) forConn(h2 bool) (roundTripper, error) {
	return upstream.NewStockChrome(h2, d.proxyURL)
}

// Conn identifies one client TLS connection and the fingerprint it was observed
// under. Every transaction multiplexed on that connection carries the same
// value, so a recorder can store the fingerprint once instead of per request.
// H2 is the zero value for HTTP/1.1 connections.
type Conn struct {
	ID          int64
	ClientHello []byte
	H2          capture.HTTP2Fingerprint
}

// Transaction is one captured request together with the response returned to
// the client and the connection it was observed on.
type Transaction struct {
	Conn     Conn
	Request  capture.Request
	Response capture.Response
}

// Options configures a Server. OutboundProxy, when set, routes all origin
// traffic through that proxy. OnTransaction, when set, is called once per
// completed request/response for streaming or logging.
type Options struct {
	OutboundProxy string
	OnTransaction func(Transaction)
}

// Server terminates client TLS with authority's leaves and forwards each request
// upstream. The zero value is not usable; construct one with New.
type Server struct {
	authority *ca.Authority
	dialer    dialer
	onTx      func(Transaction)
	// conns numbers accepted client connections, so the transactions multiplexed
	// on one connection can be tied back to it.
	conns atomic.Int64
}

// New returns a proxy that mints leaves from authority and forwards through a
// stock-Chrome upstream client, honoring opts.
func New(authority *ca.Authority, opts Options) *Server {
	return &Server{
		authority: authority,
		dialer:    stockChromeDialer{proxyURL: opts.OutboundProxy},
		onTx:      opts.OnTransaction,
	}
}

func (s *Server) emit(tx Transaction) {
	if s.onTx != nil {
		s.onTx(tx)
	}
}

// Serve accepts connections until ln fails, handling each in its own goroutine.
func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	host, err := readConnect(br)
	if err != nil {
		return
	}
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	rawHello, tlsConn, err := s.terminate(br, conn, host)
	if err != nil {
		return
	}
	defer tlsConn.Close()

	client := Conn{ID: s.conns.Add(1), ClientHello: rawHello}
	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		s.serveH2(tlsConn, client)
		return
	}
	s.serveH1(tlsConn, client)
}

// terminate peeks the ClientHello (returning its raw bytes for fingerprinting),
// then completes a TLS handshake using a leaf for the client's SNI, falling
// back to the CONNECT host when SNI is absent.
func (s *Server) terminate(br *bufio.Reader, conn net.Conn, connectHost string) ([]byte, *tls.Conn, error) {
	rawHello, prefixed, err := peekClientHello(br, conn)
	if err != nil {
		return nil, nil, err
	}

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = stripPort(connectHost)
			}
			return s.authority.LeafFor(name)
		},
	}

	tlsConn := tls.Server(prefixed, cfg)
	if err := tlsConn.Handshake(); err != nil {
		return nil, nil, err
	}
	return rawHello, tlsConn, nil
}

func (s *Server) serveH1(conn net.Conn, c Conn) {
	rt, err := s.dialer.forConn(false)
	if err != nil {
		return
	}
	br := bufio.NewReader(conn)
	for {
		req, err := capture.ReadFrom(br)
		if err != nil {
			return
		}
		resp, err := rt.RoundTrip(req)
		if err != nil {
			resp = errorResponse(err)
		}
		s.emit(Transaction{Conn: c, Request: req, Response: resp})
		if err := writeH1Response(conn, resp); err != nil {
			return
		}
	}
}

// serveH2 forwards every stream on an h2 connection through one upstream client,
// which is safe for concurrent use. The client no longer depends on the
// connection fingerprint, so it is built up front; the fingerprint each stream
// observed still rides along on the emitted transaction.
func (s *Server) serveH2(conn net.Conn, c Conn) {
	rt, err := s.dialer.forConn(true)
	if err != nil {
		return
	}
	capture.ServeHTTP2(conn, func(req capture.Request, fp capture.HTTP2Fingerprint) (capture.Response, error) {
		resp, err := rt.RoundTrip(req)
		if err != nil {
			resp = errorResponse(err)
		}
		observed := c
		observed.H2 = fp
		s.emit(Transaction{Conn: observed, Request: req, Response: resp})
		return resp, nil
	})
}
