// Package service is lebedev's control surface, independent of how it is driven.
// It owns the durable repository, the CA authority, and the capture that is
// currently running, and exposes one method per operation: start and stop a
// capture, save it, read and manage stored sessions, move HAR documents in and
// out, and launch a browser through the proxy.
//
// Every front end derives from this package rather than reimplementing it — the
// interactive REPL and the MCP server are both thin translations of these
// methods into their own vocabulary. Methods return data, not prose, so each
// front end formats for its own audience.
package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/ntakezo/lebedev/internal/browser"
	"github.com/ntakezo/lebedev/internal/ca"
	"github.com/ntakezo/lebedev/model"
	"github.com/ntakezo/lebedev/repository"
	"github.com/ntakezo/lebedev/repository/sqlite"
)

var (
	// ErrNoCapture is returned when an operation needs an active capture and none
	// has been started.
	ErrNoCapture = errors.New("service: no active capture")
	// ErrCaptureRunning is returned when starting a capture while one is already
	// serving, since a run replaces the live in-memory session.
	ErrCaptureRunning = errors.New("service: a capture is already running")
	// ErrCaptureStopped is returned when an operation needs the capture to be
	// serving and it is paused.
	ErrCaptureStopped = errors.New("service: the capture is stopped")
	// ErrEmptyCapture is returned when saving a capture that has recorded nothing.
	ErrEmptyCapture = errors.New("service: the capture has no entries yet")
)

// Service is the shared control surface. It is safe for concurrent use. The zero
// value is not usable; construct one with New.
type Service struct {
	durable   *sqlite.Repository
	authority *ca.Authority
	caCert    string

	// mu guards the capture and the browser cancels, so two front ends (or two
	// concurrent MCP calls) cannot start or tear down captures at the same time.
	mu       sync.Mutex
	current  *capture
	browsers []func()
}

// New builds a service over a durable repository and CA authority. caCert is the
// certificate path reported by CertInfo for trust instructions.
func New(durable *sqlite.Repository, authority *ca.Authority, caCert string) *Service {
	return &Service{durable: durable, authority: authority, caCert: caCert}
}

// Capture describes the live capture: where it is listening, whether it is
// serving, and how much it has recorded.
type Capture struct {
	ID          string
	Addr        string
	Running     bool
	Entries     int
	Connections int
}

// RunOptions configures a capture. A zero ID or Addr takes the default.
type RunOptions struct {
	ID            string
	Addr          string
	OutboundProxy string
}

// StartCapture begins serving the MITM proxy and records into a fresh in-memory
// session. It replaces any stopped capture — whose entries are discarded — and
// refuses to displace one that is still running.
func (s *Service) StartCapture(ctx context.Context, opts RunOptions) (Capture, error) {
	if opts.ID == "" {
		opts.ID = "default"
	}
	if opts.Addr == "" {
		opts.Addr = ":8080"
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != nil && s.current.running {
		return Capture{}, fmt.Errorf("%w: %q on %s", ErrCaptureRunning, s.current.id, s.current.addr())
	}
	if s.current != nil {
		s.current.close()
		s.current = nil
	}

	c, err := startCapture(opts.ID, opts.Addr, opts.OutboundProxy, s.authority)
	if err != nil {
		return Capture{}, err
	}
	s.current = c
	return s.describe(ctx, c)
}

// ActiveCapture returns the live capture and whether there is one.
func (s *Service) ActiveCapture(ctx context.Context) (Capture, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil {
		return Capture{}, false, nil
	}
	c, err := s.describe(ctx, s.current)
	return c, err == nil, err
}

// StopCapture pauses the capture named by id. Its in-memory session stays
// queryable and can be resumed on the same address.
func (s *Service) StopCapture(ctx context.Context, id string) (Capture, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil || s.current.id != id {
		return Capture{}, fmt.Errorf("%w named %q", ErrNoCapture, id)
	}
	if !s.current.running {
		return s.describe(ctx, s.current)
	}
	if err := s.current.stop(); err != nil {
		return Capture{}, err
	}
	return s.describe(ctx, s.current)
}

// ResumeCapture re-serves a stopped capture on its original address, appending
// new transactions to the same in-memory session.
func (s *Service) ResumeCapture(ctx context.Context, id string) (Capture, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil || s.current.id != id {
		return Capture{}, fmt.Errorf("%w named %q", ErrNoCapture, id)
	}
	if s.current.running {
		return Capture{}, fmt.Errorf("%w: %q is already running on %s", ErrCaptureRunning, id, s.current.addr())
	}
	if err := s.current.resume(); err != nil {
		return Capture{}, err
	}
	return s.describe(ctx, s.current)
}

// SaveCapture copies the live session into the durable store and returns how many
// entries it wrote. It overwrites any stored copy of the same name, so re-running
// it snapshots the growing session rather than duplicating it. Entries that
// shared a connection still share one after the copy.
func (s *Service) SaveCapture(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil {
		return 0, ErrNoCapture
	}
	id := s.current.id
	n, err := s.current.count(ctx)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, fmt.Errorf("%w: %q", ErrEmptyCapture, id)
	}
	if err := s.durable.DeleteSession(ctx, id); err != nil && !errors.Is(err, repository.ErrNotFound) {
		return 0, err
	}
	return copySession(ctx, s.durable, s.current.mem, id)
}

// describe reads a capture's current shape. Callers must hold s.mu.
func (s *Service) describe(ctx context.Context, c *capture) (Capture, error) {
	d, err := c.mem.Session(ctx, c.id)
	if err != nil {
		return Capture{}, err
	}
	return Capture{
		ID:          c.id,
		Addr:        c.addr(),
		Running:     c.running,
		Entries:     len(d.Entries),
		Connections: len(d.Connections),
	}, nil
}

// Sessions lists the durable store's sessions with their entry and connection
// counts, ordered by name. The live capture is not among them until it is saved;
// read it with ActiveCapture.
func (s *Service) Sessions(ctx context.Context) ([]repository.SessionInfo, error) {
	return s.durable.Sessions(ctx)
}

// Session returns one session in detail: its log metadata, the TLS connections
// its traffic was captured over, and a summary of every entry in capture order.
// The live capture answers for its own name; every other name reads from the
// durable store.
func (s *Service) Session(ctx context.Context, id string) (repository.SessionDetails, error) {
	return s.repoFor(id).Session(ctx, id)
}

// Entry returns one stored entry in full, byte-faithful, with its _lebedev field
// rebuilt from the connection it was captured over. The entry must belong to the
// named session.
func (s *Service) Entry(ctx context.Context, session string, id int64) (model.Stored, error) {
	st, err := s.repoFor(session).Entry(ctx, id)
	if err != nil {
		return model.Stored{}, err
	}
	if st.Session != session {
		return model.Stored{}, fmt.Errorf("%w: entry %d belongs to session %q", repository.ErrNotFound, id, st.Session)
	}
	return st, nil
}

// Connection returns one stored TLS connection: the raw ClientHello, the HTTP/2
// traits negotiated over it, and the protocol spoken upstream. It must belong to
// the named session.
func (s *Service) Connection(ctx context.Context, session string, id int64) (model.Connection, error) {
	c, err := s.repoFor(session).Connection(ctx, id)
	if err != nil {
		return model.Connection{}, err
	}
	if c.Session != session {
		return model.Connection{}, fmt.Errorf("%w: connection %d belongs to session %q", repository.ErrNotFound, id, c.Session)
	}
	return c, nil
}

// DeleteEntry removes one entry from a session. The connection it was captured
// over stays, since the other entries on that connection still need it.
func (s *Service) DeleteEntry(ctx context.Context, session string, id int64) error {
	if _, err := s.Entry(ctx, session, id); err != nil {
		return err
	}
	return s.repoFor(session).DeleteEntry(ctx, id)
}

// RenameSession moves a stored session to a new name. It refuses to rename onto a
// stored name, so it never merges two sessions.
func (s *Service) RenameSession(ctx context.Context, old, name string) error {
	return s.durable.RenameSession(ctx, old, name)
}

// DeleteSession removes a stored session with its connections and entries. It
// does not touch the live capture.
func (s *Service) DeleteSession(ctx context.Context, id string) error {
	return s.durable.DeleteSession(ctx, id)
}

// Export writes a session to w as a HAR 1.3 document. Entries are streamed, so a
// capture with large bodies costs one entry of memory rather than the session.
func (s *Service) Export(ctx context.Context, id string, w io.Writer) error {
	return exportHAR(ctx, s.repoFor(id), id, w)
}

// ExportFile writes a session as HAR 1.3 to path, creating or truncating it.
func (s *Service) ExportFile(ctx context.Context, id, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := s.Export(ctx, id, f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Import reads a HAR 1.3 document into a new durable session and returns how many
// entries it stored. The _lebedev block the document repeats on every entry is
// collapsed back into one connection record per distinct fingerprint.
func (s *Service) Import(ctx context.Context, id string, r io.Reader) (int, error) {
	return importHAR(ctx, s.durable, id, r)
}

// ImportFile reads the HAR document at path. An empty id names the session after
// the file.
func (s *Service) ImportFile(ctx context.Context, path, id string) (int, error) {
	if id == "" {
		id = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return s.Import(ctx, id, f)
}

// CertInfo is the root CA's location and the command that trusts it, which a
// client machine needs before lebedev can terminate its TLS.
type CertInfo struct {
	Path        string
	TrustCmd    string
	Instruction string
}

// CertInfo reports where the root CA lives and how to trust it on this platform.
func (s *Service) CertInfo() CertInfo {
	cmd, instruction := installHint(s.caCert)
	return CertInfo{Path: s.caCert, TrustCmd: cmd, Instruction: instruction}
}

// LaunchBrowser starts a fresh, isolated Chrome — a clean profile with no
// cookies, history, or extensions — pointed at url through the active capture. It
// returns the proxy URL Chrome was given. The browser is torn down when the
// service closes.
func (s *Service) LaunchBrowser(url string) (string, error) {
	if url == "" {
		url = "https://tls.peet.ws/api/all"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil {
		return "", ErrNoCapture
	}
	if !s.current.running {
		return "", fmt.Errorf("%w: 'resume %s' before launching a browser", ErrCaptureStopped, s.current.id)
	}

	proxyURL := "http://" + s.current.addr()
	ctx, cancel := context.WithCancel(context.Background())
	s.browsers = append(s.browsers, cancel)
	go func() {
		// Launch blocks until Chrome exits; the error is only interesting when the
		// service did not ask for the teardown.
		_ = browser.Launch(ctx, browser.Options{
			ProxyURL: proxyURL,
			URL:      url,
			Stdout:   io.Discard,
			Stderr:   io.Discard,
		})
	}()
	return proxyURL, nil
}

// repoFor returns the repository holding a session: the live in-memory one when
// the name matches the active capture, otherwise the durable one.
func (s *Service) repoFor(id string) *sqlite.Repository {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != nil && s.current.id == id {
		return s.current.mem
	}
	return s.durable
}

// Close tears down any browser the service launched and releases the live
// capture, discarding its in-memory entries. The durable repository belongs to
// the caller and is left open.
func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, cancel := range s.browsers {
		cancel()
	}
	s.browsers = nil
	if s.current == nil {
		return nil
	}
	err := s.current.close()
	s.current = nil
	return err
}

// installHint returns the command that trusts the root CA on this platform and a
// one-line instruction to go with it.
func installHint(certPath string) (cmd, instruction string) {
	switch runtime.GOOS {
	case "darwin":
		return "sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain " + certPath,
			"Trust it (admin required):"
	case "linux":
		return "sudo cp " + certPath + " /usr/local/share/ca-certificates/lebedev.crt && sudo update-ca-certificates",
			"Trust it (admin required):"
	case "windows":
		return "certutil -addstore -f ROOT " + certPath, "Trust it (run as administrator):"
	}
	return "", "Import " + certPath + " into your system or browser trust store as a trusted root."
}
