// Package session ties a proxy run to a recorder: it configures a Server
// (including an optional per-session outbound proxy) and hands every captured
// request/response to the recorder as a faithful HAR entry.
//
// It is also where a client connection becomes a stored one. The proxy observes
// each TLS connection once and tags every transaction multiplexed on it with the
// same id; the session turns the first sighting into a connection record and
// attributes the entries that follow to it, so a fingerprint is stored once
// rather than copied onto every entry.
package session

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/ntakezo/lebedev/internal/ca"
	"github.com/ntakezo/lebedev/internal/proxy"
	"github.com/ntakezo/lebedev/model"
)

// Recorder persists a capture's connections and entries. It is the write half of
// repository.Repository, so *sqlite.Repository satisfies it directly.
type Recorder interface {
	CreateConnection(ctx context.Context, session string, c model.Connection) (int64, error)
	CreateEntry(ctx context.Context, session string, connection int64, e model.Entry) (int64, error)
}

// Config is the per-session configuration. OutboundProxy, when set, routes this
// session's origin traffic through that proxy.
type Config struct {
	ID            string
	OutboundProxy string
}

// Session serves a MITM proxy and records its transactions into a recorder.
type Session struct {
	config    Config
	authority *ca.Authority
	recorder  Recorder
	now       func() time.Time

	// conns maps a proxy connection id to the connection row it was stored as, so
	// the transactions sharing a connection all reference one record. Streams on an
	// h2 connection are served concurrently, so it is guarded.
	mu    sync.Mutex
	conns map[int64]int64
}

// New builds a session that mints leaves from authority and records entries into
// rec.
func New(config Config, authority *ca.Authority, rec Recorder) *Session {
	return &Session{
		config:    config,
		authority: authority,
		recorder:  rec,
		now:       time.Now,
		conns:     map[int64]int64{},
	}
}

// Serve runs the proxy on ln until it fails, recording a HAR entry per
// transaction.
func (s *Session) Serve(ln net.Listener) error {
	srv := proxy.New(s.authority, proxy.Options{
		OutboundProxy: s.config.OutboundProxy,
		OnTransaction: s.record,
	})
	return srv.Serve(ln)
}

// record hands one transaction to the recorder, creating its connection record
// first if this is the connection's first transaction. Recording is best-effort:
// a recorder error never stalls proxying, and the transaction is captured and
// forwarded regardless.
func (s *Session) record(tx proxy.Transaction) {
	ctx := context.Background()
	conn, err := s.connectionID(ctx, tx)
	if err != nil {
		// The connection could not be stored; keep the entry rather than drop it,
		// unattributed.
		conn = 0
	}
	_, _ = s.recorder.CreateEntry(ctx, s.config.ID, conn, entryFromTransaction(tx, s.now()))
}

// connectionID returns the stored connection for a transaction's client
// connection, creating the record on first sight. A transaction the proxy did not
// attribute to a connection returns 0, which stores the entry unattributed.
func (s *Session) connectionID(ctx context.Context, tx proxy.Transaction) (int64, error) {
	if tx.Conn.ID == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.conns[tx.Conn.ID]; ok {
		return id, nil
	}
	id, err := s.recorder.CreateConnection(ctx, s.config.ID, connectionFromTransaction(s.config.ID, tx))
	if err != nil {
		return 0, err
	}
	s.conns[tx.Conn.ID] = id
	return id, nil
}
