// Package session ties a proxy run to a recorder: it configures a Server
// (including an optional per-session outbound proxy) and hands every captured
// request/response to the recorder as a faithful HAR entry. Where those entries
// are stored — an in-memory buffer, a durable store, or both — is the recorder's
// concern, not the session's.
package session

import (
	"context"
	"net"
	"time"

	"github.com/ntakezo/lebedev/internal/ca"
	"github.com/ntakezo/lebedev/internal/proxy"
	"github.com/ntakezo/lebedev/internal/store"
)

// Recorder receives one HAR entry per completed transaction. *store.Store
// satisfies it directly; callers that need dual-writing (memory plus a durable
// store) provide their own implementation.
type Recorder interface {
	Insert(ctx context.Context, session string, e store.Entry, at int64) (int64, error)
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
}

// New builds a session that mints leaves from authority and records entries into
// rec.
func New(config Config, authority *ca.Authority, rec Recorder) *Session {
	return &Session{
		config:    config,
		authority: authority,
		recorder:  rec,
		now:       time.Now,
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

// record hands one transaction to the recorder. Recording is best-effort: a
// recorder error never stalls proxying, and the transaction is captured and
// mirrored upstream regardless.
func (s *Session) record(tx proxy.Transaction) {
	entry := entryFromTransaction(s.config.ID, tx, s.now())
	_, _ = s.recorder.Insert(context.Background(), s.config.ID, entry, s.now().UnixMilli())
}
