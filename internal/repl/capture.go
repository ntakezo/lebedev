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
	"github.com/ntakezo/lebedev/model"
)

// capture is one proxy run. Its entries accumulate in an in-memory store and are
// discarded when the capture is closed; use save or export to keep anything worth
// keeping. A stopped capture can be resumed: it retains the CA authority, upstream
// proxy, and bound address needed to re-serve the same in-memory session.
type capture struct {
	id            string
	mem           *store.Store
	authority     *ca.Authority
	upstreamProxy string

	mu       sync.Mutex
	bindAddr string // concrete bound address, reused when resuming
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
	c := &capture{
		id:            id,
		mem:           mem,
		authority:     authority,
		upstreamProxy: upstreamProxy,
		bindAddr:      addr,
	}
	if err := c.serve(); err != nil {
		mem.Close()
		return nil, err
	}
	return c, nil
}

// serve opens the listener on c.bindAddr and starts the proxy serve loop, pinning
// the concrete bound address so a later resume rebinds the same endpoint. Callers
// must ensure the capture is not already running.
func (c *capture) serve() error {
	ln, err := net.Listen("tcp", c.bindAddr)
	if err != nil {
		return err
	}
	c.bindAddr = ln.Addr().String()
	c.ln = ln
	c.serveErr = make(chan error, 1)
	c.running = true
	sess := session.New(session.Config{ID: c.id, OutboundProxy: c.upstreamProxy}, c.authority, c)
	go func() { c.serveErr <- sess.Serve(ln) }()
	return nil
}

// resume re-serves a stopped capture on its original address, appending new
// transactions to the same in-memory session.
func (c *capture) resume() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return errors.New("capture is already running")
	}
	return c.serve()
}

// Insert records an entry into the in-memory store.
func (c *capture) Insert(ctx context.Context, sessionID string, e model.Entry, at int64) (int64, error) {
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
