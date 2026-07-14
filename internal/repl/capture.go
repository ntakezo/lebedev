package repl

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/ntakezo/lebedev/internal/ca"
	"github.com/ntakezo/lebedev/internal/session"
	"github.com/ntakezo/lebedev/internal/store"
)

// capture is one proxy run. Its entries accumulate in an in-memory store and are
// discarded when the capture is closed; use export or import against the durable
// store to keep anything worth keeping.
type capture struct {
	id  string
	mem *store.Store

	mu       sync.Mutex
	ln       net.Listener
	serveErr chan error
	running  bool
}

// startCapture opens an in-memory store for the session and begins serving the
// MITM proxy on addr. Entries live only in memory for the life of the capture.
func startCapture(id, addr, upstreamProxy string, authority *ca.Authority) (*capture, error) {
	mem, err := store.Open("")
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		mem.Close()
		return nil, err
	}
	c := &capture{
		id:       id,
		mem:      mem,
		ln:       ln,
		serveErr: make(chan error, 1),
		running:  true,
	}
	sess := session.New(session.Config{ID: id, OutboundProxy: upstreamProxy}, authority, c)
	go func() { c.serveErr <- sess.Serve(ln) }()
	return c, nil
}

// Insert records an entry into the in-memory store.
func (c *capture) Insert(ctx context.Context, sessionID string, e store.Entry, at int64) (int64, error) {
	return c.mem.Insert(ctx, sessionID, e, at)
}

// addr returns the address the proxy is listening on.
func (c *capture) addr() string { return c.ln.Addr().String() }

// count returns how many entries the live session currently holds in memory.
func (c *capture) count(ctx context.Context) (int, error) {
	return c.mem.Count(ctx, store.Query{Session: c.id})
}

// stop shuts the proxy listener down and waits for the serve loop to return. The
// in-memory session remains queryable until the capture is closed.
func (c *capture) stop() error {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return nil
	}
	c.running = false
	c.mu.Unlock()
	c.ln.Close()
	err := <-c.serveErr
	// Closing the listener is how we stop Serve, so its resulting "closed
	// connection" error is the expected clean-shutdown signal, not a failure.
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// close stops the proxy if needed and releases the in-memory store, discarding
// its entries.
func (c *capture) close() error {
	if err := c.stop(); err != nil {
		// Report the serve error but still release the store.
		_ = c.mem.Close()
		return fmt.Errorf("stop: %w", err)
	}
	return c.mem.Close()
}
