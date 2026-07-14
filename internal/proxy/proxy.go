// Package proxy is the MITM core: it accepts CONNECT tunnels, peeks the raw
// ClientHello for fingerprinting, terminates TLS with a per-host leaf, captures
// the request faithfully (HTTP/1.1 or HTTP/2), and forwards it upstream through
// a client that mirrors the captured fingerprint.
package proxy

import (
	"bufio"
	"crypto/tls"
	"net"
	"sync"

	"github.com/ntakezo/lebedev/internal/ca"
	"github.com/ntakezo/lebedev/internal/capture"
	"github.com/ntakezo/lebedev/internal/upstream"
)

// roundTripper forwards one captured request to its origin.
type roundTripper interface {
	RoundTrip(capture.Request) (capture.Response, error)
}

// dialer builds a per-connection round tripper from the captured client
// fingerprint: the raw ClientHello, the h2 traits, and whether the client used
// h2. It is an interface so tests can forward without touching the network.
type dialer interface {
	forConn(rawHello []byte, fp capture.HTTP2Fingerprint, h2 bool) (roundTripper, error)
}

type mirrorDialer struct{ proxyURL string }

func (d mirrorDialer) forConn(rawHello []byte, fp capture.HTTP2Fingerprint, h2 bool) (roundTripper, error) {
	return upstream.NewMirror(rawHello, fp, h2, d.proxyURL)
}

// Transaction is one captured request together with the response returned to
// the client and the client fingerprint it was served under. H2 is the zero
// value for HTTP/1.1 connections.
type Transaction struct {
	ClientHello []byte
	H2          capture.HTTP2Fingerprint
	Request     capture.Request
	Response    capture.Response
}

// Options configures a Server. OutboundProxy, when set, routes all origin
// traffic through that proxy. OnTransaction, when set, is called once per
// completed request/response for streaming or logging.
type Options struct {
	OutboundProxy string
	OnTransaction func(Transaction)
}

// Server terminates client TLS with authority's leaves and mirrors each client
// upstream. The zero value is not usable; construct one with New.
type Server struct {
	authority *ca.Authority
	dialer    dialer
	onTx      func(Transaction)
}

// New returns a proxy that mints leaves from authority and forwards through a
// fingerprint-mirroring upstream client, honoring opts.
func New(authority *ca.Authority, opts Options) *Server {
	return &Server{
		authority: authority,
		dialer:    mirrorDialer{proxyURL: opts.OutboundProxy},
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

	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		s.serveH2(tlsConn, rawHello)
		return
	}
	s.serveH1(tlsConn, rawHello)
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

func (s *Server) serveH1(conn net.Conn, rawHello []byte) {
	rt, err := s.dialer.forConn(rawHello, capture.HTTP2Fingerprint{}, false)
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
		s.emit(Transaction{ClientHello: rawHello, Request: req, Response: resp})
		if err := writeH1Response(conn, resp); err != nil {
			return
		}
	}
}

// serveH2 builds the upstream round tripper lazily on the first request, once
// the connection fingerprint is complete. ServeHTTP2 runs each stream's handler
// concurrently, so the build is guarded by a sync.Once and the resulting client
// (safe for concurrent use) is shared across streams.
func (s *Server) serveH2(conn net.Conn, rawHello []byte) {
	var (
		once     sync.Once
		rt       roundTripper
		buildErr error
	)
	capture.ServeHTTP2(conn, func(req capture.Request, fp capture.HTTP2Fingerprint) (capture.Response, error) {
		once.Do(func() { rt, buildErr = s.dialer.forConn(rawHello, fp, true) })
		if buildErr != nil {
			return errorResponse(buildErr), nil
		}
		resp, err := rt.RoundTrip(req)
		if err != nil {
			resp = errorResponse(err)
		}
		s.emit(Transaction{ClientHello: rawHello, H2: fp, Request: req, Response: resp})
		return resp, nil
	})
}
