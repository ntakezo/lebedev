// Package session ties a proxy run to a data stream: it configures a Server
// (including an optional per-session outbound proxy) and serializes every
// captured request/response as a structured, faithful record to a sink.
package session

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"sync"

	"github.com/ntakezo/lebedev/internal/ca"
	"github.com/ntakezo/lebedev/internal/capture"
	"github.com/ntakezo/lebedev/internal/proxy"
)

// Config is the per-session configuration. OutboundProxy, when set, routes this
// session's origin traffic through that proxy. URLFilters and TypeFilters, when
// non-empty, restrict which transactions are written: a record is emitted only if
// its request URL matches one of URLFilters (globs with "*") and its response
// content type matches one of TypeFilters (categories or MIME globs). An empty
// list imposes no constraint on that dimension.
type Config struct {
	ID            string
	OutboundProxy string
	URLFilters    []string
	TypeFilters   []string
}

// Session serves a MITM proxy and streams its transactions to a sink.
type Session struct {
	config    Config
	authority *ca.Authority
	sink      *Sink
	filter    filter
}

// New builds a session that mints leaves from authority and writes records to
// sink, subject to the output filters in config.
func New(config Config, authority *ca.Authority, sink *Sink) *Session {
	return &Session{
		config:    config,
		authority: authority,
		sink:      sink,
		filter:    newFilter(config.URLFilters, config.TypeFilters),
	}
}

// Serve runs the proxy on ln until it fails, streaming a record per transaction.
func (s *Session) Serve(ln net.Listener) error {
	srv := proxy.New(s.authority, proxy.Options{
		OutboundProxy: s.config.OutboundProxy,
		OnTransaction: s.record,
	})
	return srv.Serve(ln)
}

// record streams one transaction if it passes the session's output filters;
// emission is best-effort so a slow or broken sink never stalls proxying. The
// transaction is still captured and mirrored upstream regardless — filtering only
// controls what is written to the sink.
func (s *Session) record(tx proxy.Transaction) {
	rec := toRecord(s.config.ID, tx)
	if !s.filter.allows(rec) {
		return
	}
	_ = s.sink.Emit(rec)
}

// Sink serializes records as JSON Lines to an underlying writer. It is safe for
// concurrent use across connections.
type Sink struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewSink returns a sink that writes one JSON record per line to w.
func NewSink(w io.Writer) *Sink {
	return &Sink{enc: json.NewEncoder(w)}
}

// Emit writes one record followed by a newline.
func (s *Sink) Emit(r Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(r)
}

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Setting struct {
	ID    uint16 `json:"id"`
	Value uint32 `json:"value"`
}

type TLSInfo struct {
	ClientHelloHex string `json:"clientHelloHex"`
}

type HTTP2 struct {
	Settings       []Setting `json:"settings,omitempty"`
	ConnectionFlow uint32    `json:"connectionFlow,omitempty"`
	PseudoOrder    []string  `json:"pseudoOrder,omitempty"`
	HeaderOrder    []string  `json:"headerOrder,omitempty"`
}

type Request struct {
	Method    string   `json:"method"`
	Target    string   `json:"target"`
	Scheme    string   `json:"scheme"`
	Authority string   `json:"authority"`
	Proto     string   `json:"proto"`
	Headers   []Header `json:"headers"`
	Body      string   `json:"body,omitempty"`
}

type Response struct {
	Status  int      `json:"status"`
	Headers []Header `json:"headers"`
	// Proto is the protocol the upstream mirror spoke to the origin, recorded
	// when it differs meaningfully — notably "HTTP/3.0" after an Alt-Svc upgrade.
	Proto string `json:"proto,omitempty"`
	Body  string `json:"body,omitempty"`
}

// Record is the faithful, structured form of one transaction streamed to the
// sink. HTTP2 is present only for h2 connections.
type Record struct {
	Session  string   `json:"session"`
	Protocol string   `json:"protocol"`
	TLS      TLSInfo  `json:"tls"`
	Request  Request  `json:"request"`
	Response Response `json:"response"`
	HTTP2    *HTTP2   `json:"http2,omitempty"`
}

func toRecord(id string, tx proxy.Transaction) Record {
	req := tx.Request
	rec := Record{
		Session:  id,
		Protocol: req.Proto(),
		TLS:      TLSInfo{ClientHelloHex: hex.EncodeToString(tx.ClientHello)},
		Request:  toRequest(req),
		Response: toResponse(tx.Response),
	}
	if req.Proto() == "HTTP/2.0" {
		rec.HTTP2 = toHTTP2(tx.H2)
	}
	// The upstream protocol normally matches the client's; surface it only when it
	// diverges — i.e. the mirror upgraded the origin to HTTP/3 — so existing h2/h1
	// records are unchanged and an h3 upgrade is visible.
	if rec.Response.Proto == rec.Protocol {
		rec.Response.Proto = ""
	}
	return rec
}

func toRequest(req capture.Request) Request {
	return Request{
		Method:    req.Method(),
		Target:    req.Target(),
		Scheme:    req.Scheme(),
		Authority: req.Authority(),
		Proto:     req.Proto(),
		Headers:   toHeaders(req.Headers()),
		Body:      string(req.Body()),
	}
}

func toResponse(resp capture.Response) Response {
	return Response{
		Status:  resp.Status,
		Headers: toHeaders(resp.Headers),
		Proto:   resp.Proto,
		Body:    string(resp.Body),
	}
}

func toHTTP2(fp capture.HTTP2Fingerprint) *HTTP2 {
	settings := make([]Setting, 0, len(fp.Settings()))
	for _, s := range fp.Settings() {
		settings = append(settings, Setting{ID: s.ID, Value: s.Value})
	}
	return &HTTP2{
		Settings:       settings,
		ConnectionFlow: fp.ConnectionFlow(),
		PseudoOrder:    fp.PseudoOrder(),
		HeaderOrder:    fp.HeaderOrder(),
	}
}

func toHeaders(in []capture.Header) []Header {
	out := make([]Header, len(in))
	for i, h := range in {
		out[i] = Header{Name: h.Name, Value: h.Value}
	}
	return out
}
