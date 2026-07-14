// Package repl is Lebedev's interactive control surface. A single durable store
// (the "system state") is opened for the life of the process; from the prompt the
// user starts capture runs and performs CRUD over stored sessions. A capture run's
// entries live in memory and are discarded on exit; use export or import to move
// data between a live session and the durable store.
package repl

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ntakezo/lebedev/har"
	"github.com/ntakezo/lebedev/internal/browser"
	"github.com/ntakezo/lebedev/internal/ca"
	"github.com/ntakezo/lebedev/internal/store"
	"github.com/ntakezo/lebedev/model"
)

// REPL holds the durable store, the CA used to mint leaves, and the current
// capture (if any). It reads commands from in and writes output to out.
type REPL struct {
	durable   *store.Store
	authority *ca.Authority
	caCert    string
	out       io.Writer

	current       *capture
	browserCancel []func()
}

// New builds a REPL over a durable store and CA authority. caCert is reported by
// the cert command for trust instructions.
func New(durable *store.Store, authority *ca.Authority, caCert string, out io.Writer) *REPL {
	return &REPL{durable: durable, authority: authority, caCert: caCert, out: out}
}

// Run reads and executes commands until EOF or a quit command, then tears down
// any active capture. It returns the first fatal I/O error, if any.
func (r *REPL) Run(in io.Reader) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	r.prompt()
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			if quit := r.dispatch(line); quit {
				break
			}
		}
		r.prompt()
	}
	r.shutdown()
	return sc.Err()
}

func (r *REPL) prompt() { fmt.Fprint(r.out, "lebedev> ") }

func (r *REPL) printf(format string, a ...any) { fmt.Fprintf(r.out, format+"\n", a...) }

// dispatch runs one command line and reports whether the REPL should exit.
func (r *REPL) dispatch(line string) (quit bool) {
	fields := strings.Fields(line)
	cmd, args := fields[0], fields[1:]
	ctx := context.Background()
	switch cmd {
	case "help", "?":
		r.help()
	case "run":
		r.cmdRun(args)
	case "save":
		r.cmdSave(ctx)
	case "stop":
		r.cmdStop(args)
	case "resume":
		r.cmdResume(args)
	case "sessions", "ls":
		r.cmdSessions(ctx)
	case "show", "cat":
		r.cmdShow(ctx, args)
	case "rename", "mv":
		r.cmdRename(ctx, args)
	case "rm", "delete", "del":
		r.cmdDelete(ctx, args)
	case "export":
		r.cmdExport(ctx, args)
	case "import":
		r.cmdImport(ctx, args)
	case "cert":
		r.cmdCert()
	case "browser":
		r.cmdBrowser(args)
	case "quit", "exit":
		return true
	default:
		r.printf("unknown command %q — try 'help'", cmd)
	}
	return false
}

func (r *REPL) help() {
	fmt.Fprint(r.out, `commands:
  run [id] [--addr :8080] [--upstream-proxy URL]
                         start a capture; entries stay in memory only
  save                   write the live session to the durable store
  stop <id>              stop the capture (its session stays queryable)
  resume <id>            resume a stopped capture on its address
  sessions | ls          list stored sessions (and the live one, if any)
  show <id> [limit]      list a session's entries
  export <id> [file]     write a session as HAR 1.3 (stdout if no file)
  import <file> [as id]  load a HAR 1.3 document into the durable store
  rename <old> <new>     rename a stored session
  rm <id>                delete a stored session
  cert                   print CA trust instructions
  browser [url]          launch a fresh Chrome through the active capture
  help | quit
`)
}

func (r *REPL) cmdRun(args []string) {
	id, addr, upstream := "default", ":8080", ""
	positional := true
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--addr":
			if i+1 < len(args) {
				i++
				addr = args[i]
			}
		case "--upstream-proxy":
			if i+1 < len(args) {
				i++
				upstream = args[i]
			}
		default:
			if positional && !strings.HasPrefix(args[i], "--") {
				id = args[i]
			}
		}
		positional = false
	}

	if r.current != nil && r.current.running {
		r.printf("capture %q is already active on %s — 'stop %s' first", r.current.id, r.current.addr(), r.current.id)
		return
	}
	if r.current != nil {
		r.current.close()
		r.current = nil
	}

	c, err := startCapture(id, addr, upstream, r.authority)
	if err != nil {
		r.printf("run: %v", err)
		return
	}
	r.current = c
	r.printf("capturing session %q on %s — entries are in memory only ('save' to keep them)", id, c.addr())
}

// cmdSave writes the live session's in-memory entries to the durable store. It
// overwrites any existing stored copy of the same id, so re-running it snapshots
// the growing session without duplicating entries.
func (r *REPL) cmdSave(ctx context.Context) {
	if r.current == nil {
		r.printf("no active session — 'run' one first")
		return
	}
	id := r.current.id
	stored, err := r.current.mem.List(ctx, store.Query{Session: id, Ascending: true})
	if err != nil {
		r.printf("save: %v", err)
		return
	}
	if len(stored) == 0 {
		r.printf("save: session %q has no entries yet", id)
		return
	}
	if err := r.durable.DeleteSession(ctx, id); err != nil {
		r.printf("save: %v", err)
		return
	}
	if err := r.durable.PutLog(ctx, id, model.Log{Version: "1.3", Creator: har.Creator{Name: "lebedev", Version: "1.3"}}); err != nil {
		r.printf("save: %v", err)
		return
	}
	for i, st := range stored {
		if _, err := r.durable.Insert(ctx, id, st.Entry, int64(i)); err != nil {
			r.printf("save: %v", err)
			return
		}
	}
	r.printf("saved session %q to the durable store (%d entries)", id, len(stored))
}

func (r *REPL) cmdStop(args []string) {
	if len(args) == 0 {
		r.printf("stop: need a session id")
		return
	}
	id := args[0]
	if r.current == nil || r.current.id != id {
		r.printf("no active capture %q", id)
		return
	}
	if !r.current.running {
		r.printf("capture %q is already stopped", id)
		return
	}
	if err := r.current.stop(); err != nil {
		r.printf("stop: %v", err)
		return
	}
	r.printf("stopped capture %q (still queryable; 'resume %s' to continue, 'save' to keep it)", id, id)
}

func (r *REPL) cmdResume(args []string) {
	if len(args) == 0 {
		r.printf("resume: need a session id")
		return
	}
	id := args[0]
	if r.current == nil || r.current.id != id {
		r.printf("no stopped capture %q to resume", id)
		return
	}
	if r.current.running {
		r.printf("capture %q is already running on %s", id, r.current.addr())
		return
	}
	if err := r.current.resume(); err != nil {
		r.printf("resume: %v", err)
		return
	}
	r.printf("resumed capture %q on %s", id, r.current.addr())
}

func (r *REPL) cmdSessions(ctx context.Context) {
	infos, err := r.durable.SessionInfos(ctx)
	if err != nil {
		r.printf("sessions: %v", err)
		return
	}
	if len(infos) == 0 && r.current == nil {
		r.printf("no sessions")
		return
	}
	for _, si := range infos {
		r.printf("  %-20s %d entries  [stored]", si.Session, si.Entries)
	}
	if r.current != nil {
		n, _ := r.current.count(ctx)
		live := "stopped"
		if r.current.running {
			live = "live"
		}
		r.printf("* %-20s %d entries  [%s, memory only]", r.current.id, n, live)
	}
}

func (r *REPL) cmdShow(ctx context.Context, args []string) {
	if len(args) == 0 {
		r.printf("show: need a session id")
		return
	}
	id := args[0]
	limit := 0
	if len(args) > 1 {
		fmt.Sscanf(args[1], "%d", &limit)
	}
	st := r.storeFor(id)
	entries, err := st.List(ctx, store.Query{Session: id, Ascending: true, Limit: limit})
	if err != nil {
		r.printf("show: %v", err)
		return
	}
	if len(entries) == 0 {
		r.printf("no entries for session %q", id)
		return
	}
	for i, e := range entries {
		r.printf("  %3d  %-6s %3d  %s", i+1, e.Entry.Request.Method, e.Entry.Response.Status, e.Entry.Request.URL)
	}
}

func (r *REPL) cmdRename(ctx context.Context, args []string) {
	if len(args) < 2 {
		r.printf("rename: need <old> <new>")
		return
	}
	if err := r.durable.RenameSession(ctx, args[0], args[1]); err != nil {
		r.printf("rename: %v", err)
		return
	}
	r.printf("renamed %q to %q", args[0], args[1])
}

func (r *REPL) cmdDelete(ctx context.Context, args []string) {
	if len(args) == 0 {
		r.printf("rm: need a session id")
		return
	}
	if err := r.durable.DeleteSession(ctx, args[0]); err != nil {
		r.printf("rm: %v", err)
		return
	}
	r.printf("deleted stored session %q", args[0])
}

func (r *REPL) cmdExport(ctx context.Context, args []string) {
	if len(args) == 0 {
		r.printf("export: need a session id")
		return
	}
	id := args[0]
	st := r.storeFor(id)
	var w io.Writer = r.out
	var closer io.Closer
	if len(args) > 1 {
		f, err := os.Create(args[1])
		if err != nil {
			r.printf("export: %v", err)
			return
		}
		w, closer = f, f
	}
	if err := st.Export(ctx, store.Query{Session: id}, w); err != nil {
		r.printf("export: %v", err)
	}
	if closer != nil {
		closer.Close()
		r.printf("exported session %q to %s", id, args[1])
	}
}

func (r *REPL) cmdImport(ctx context.Context, args []string) {
	if len(args) == 0 {
		r.printf("import: need a HAR file")
		return
	}
	path := args[0]
	id := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if len(args) >= 3 && args[1] == "as" {
		id = args[2]
	}
	f, err := os.Open(path)
	if err != nil {
		r.printf("import: %v", err)
		return
	}
	defer f.Close()
	n, err := r.durable.Import(ctx, id, f)
	if err != nil {
		r.printf("import: %v", err)
		return
	}
	r.printf("imported %d entries into session %q", n, id)
}

func (r *REPL) cmdCert() {
	fmt.Fprintf(r.out, "CA certificate: %s\n\n%s", r.caCert, installHint(r.caCert))
}

func (r *REPL) cmdBrowser(args []string) {
	if r.current == nil || !r.current.running {
		r.printf("browser: no active capture to route through — 'run' one first")
		return
	}
	url := "https://tls.peet.ws/api/all"
	if len(args) > 0 {
		url = args[0]
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.browserCancel = append(r.browserCancel, cancel)
	proxyURL := "http://" + r.current.addr()
	go func() {
		err := browser.Launch(ctx, browser.Options{
			ProxyURL: proxyURL,
			URL:      url,
			Stdout:   io.Discard,
			Stderr:   io.Discard,
		})
		if err != nil && ctx.Err() == nil {
			r.printf("browser: %v", err)
		}
	}()
	r.printf("launched Chrome at %s through %s", url, proxyURL)
}

// storeFor returns the store that holds a session: the live in-memory store when
// the id names the active capture, otherwise the durable store.
func (r *REPL) storeFor(id string) *store.Store {
	if r.current != nil && r.current.id == id {
		return r.current.mem
	}
	return r.durable
}

func (r *REPL) shutdown() {
	for _, cancel := range r.browserCancel {
		cancel()
	}
	if r.current != nil {
		r.current.close()
		r.current = nil
	}
}

func installHint(certPath string) string {
	switch runtime.GOOS {
	case "darwin":
		return fmt.Sprintf("Trust it (admin required):\n"+
			"  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s\n", certPath)
	case "linux":
		return fmt.Sprintf("Trust it (Debian/Ubuntu):\n"+
			"  sudo cp %s /usr/local/share/ca-certificates/lebedev.crt && sudo update-ca-certificates\n", certPath)
	default:
		return fmt.Sprintf("Import %s into your system or browser trust store as a trusted root.\n", certPath)
	}
}
