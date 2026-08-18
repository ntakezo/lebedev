// Package repl is Lebedev's interactive control surface: a prompt that parses a
// command line, calls the shared service, and formats the result for a person at
// a keyboard. It holds no capture or storage logic of its own — everything it can
// do, package service can do, which is what keeps it and the MCP server in step.
package repl

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ntakezo/lebedev/internal/service"
)

// REPL reads commands from an input stream and writes results to out.
type REPL struct {
	svc *service.Service
	out io.Writer
}

// New builds a REPL over a service.
func New(svc *service.Service, out io.Writer) *REPL {
	return &REPL{svc: svc, out: out}
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
	r.svc.Close()
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
		r.cmdRun(ctx, args)
	case "save":
		r.cmdSave(ctx)
	case "stop":
		r.cmdStop(ctx, args)
	case "resume":
		r.cmdResume(ctx, args)
	case "sessions", "ls":
		r.cmdSessions(ctx)
	case "show", "cat":
		r.cmdShow(ctx, args)
	case "entry":
		r.cmdEntry(ctx, args)
	case "conn":
		r.cmdConnection(ctx, args)
	case "rename", "mv":
		r.cmdRename(ctx, args)
	case "rm", "delete", "del":
		r.cmdDelete(ctx, args)
	case "rm-entry":
		r.cmdDeleteEntry(ctx, args)
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
  save                      write the live session to the durable store
  stop <id>                 stop the capture (its session stays queryable)
  resume <id>               resume a stopped capture on its address
  sessions | ls             list stored sessions (and the live one, if any)
  show <id> [limit]         list a session's entries
  entry <session> <id>      print one entry as HAR JSON
  conn <session> <id>       print one TLS connection's fingerprint
  export <id> [file]        write a session as HAR 1.3 (stdout if no file)
  import <file> [as id]     load a HAR 1.3 document into the durable store
  rename <old> <new>        rename a stored session
  rm <id>                   delete a stored session
  rm-entry <session> <id>   delete one entry
  cert                      print CA trust instructions
  browser [url]             launch a fresh Chrome through the active capture
  help | quit
`)
}

func (r *REPL) cmdRun(ctx context.Context, args []string) {
	opts := service.RunOptions{}
	positional := true
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--addr":
			if i+1 < len(args) {
				i++
				opts.Addr = args[i]
			}
		case "--upstream-proxy":
			if i+1 < len(args) {
				i++
				opts.OutboundProxy = args[i]
			}
		default:
			if positional && !strings.HasPrefix(args[i], "--") {
				opts.ID = args[i]
			}
		}
		positional = false
	}

	c, err := r.svc.StartCapture(ctx, opts)
	if err != nil {
		r.printf("run: %v", err)
		return
	}
	r.printf("capturing session %q on %s — entries are in memory only ('save' to keep them)", c.ID, c.Addr)
}

func (r *REPL) cmdSave(ctx context.Context) {
	n, err := r.svc.SaveCapture(ctx)
	if err != nil {
		r.printf("save: %v", err)
		return
	}
	c, _, _ := r.svc.ActiveCapture(ctx)
	r.printf("saved session %q to the durable store (%d entries)", c.ID, n)
}

func (r *REPL) cmdStop(ctx context.Context, args []string) {
	if len(args) == 0 {
		r.printf("stop: need a session id")
		return
	}
	c, err := r.svc.StopCapture(ctx, args[0])
	if err != nil {
		r.printf("stop: %v", err)
		return
	}
	r.printf("stopped capture %q (still queryable; 'resume %s' to continue, 'save' to keep it)", c.ID, c.ID)
}

func (r *REPL) cmdResume(ctx context.Context, args []string) {
	if len(args) == 0 {
		r.printf("resume: need a session id")
		return
	}
	c, err := r.svc.ResumeCapture(ctx, args[0])
	if err != nil {
		r.printf("resume: %v", err)
		return
	}
	r.printf("resumed capture %q on %s", c.ID, c.Addr)
}

func (r *REPL) cmdSessions(ctx context.Context) {
	infos, err := r.svc.Sessions(ctx)
	if err != nil {
		r.printf("sessions: %v", err)
		return
	}
	live, hasLive, err := r.svc.ActiveCapture(ctx)
	if err != nil {
		r.printf("sessions: %v", err)
		return
	}
	if len(infos) == 0 && !hasLive {
		r.printf("no sessions")
		return
	}
	for _, si := range infos {
		r.printf("  %-20s %d entries, %d connections  [stored]", si.Name, si.Entries, si.Connections)
	}
	if hasLive {
		state := "stopped"
		if live.Running {
			state = "live"
		}
		r.printf("* %-20s %d entries, %d connections  [%s, memory only]", live.ID, live.Entries, live.Connections, state)
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
	d, err := r.svc.Session(ctx, id)
	if err != nil {
		r.printf("show: %v", err)
		return
	}
	if len(d.Entries) == 0 {
		r.printf("no entries for session %q", id)
		return
	}
	for i, e := range d.Entries {
		if limit > 0 && i >= limit {
			break
		}
		r.printf("  %3d  %-6s %3d  conn %-3d  %s", e.ID, e.Method, e.Status, e.Connection, e.URL)
	}
}

func (r *REPL) cmdEntry(ctx context.Context, args []string) {
	session, id, ok := r.parseTarget("entry", args)
	if !ok {
		return
	}
	st, err := r.svc.Entry(ctx, session, id)
	if err != nil {
		r.printf("entry: %v", err)
		return
	}
	b, err := json.MarshalIndent(st.Entry, "", "  ")
	if err != nil {
		r.printf("entry: %v", err)
		return
	}
	fmt.Fprintf(r.out, "%s\n", b)
}

func (r *REPL) cmdConnection(ctx context.Context, args []string) {
	session, id, ok := r.parseTarget("conn", args)
	if !ok {
		return
	}
	c, err := r.svc.Connection(ctx, session, id)
	if err != nil {
		r.printf("conn: %v", err)
		return
	}
	r.printf("connection %d of session %q", c.ID, c.Session)
	r.printf("  clientHello  %s", elide(c.ClientHelloHex, 96))
	if c.UpstreamProto != "" {
		r.printf("  upstream     %s", c.UpstreamProto)
	}
	if c.HTTP2 == nil {
		r.printf("  http2        none (HTTP/1.1 connection)")
		return
	}
	r.printf("  settings     %v", c.HTTP2.Settings)
	r.printf("  flow         %d", c.HTTP2.ConnectionFlow)
	r.printf("  pseudoOrder  %s", strings.Join(c.HTTP2.PseudoOrder, ", "))
	r.printf("  headerOrder  %s", strings.Join(c.HTTP2.HeaderOrder, ", "))
}

func (r *REPL) cmdRename(ctx context.Context, args []string) {
	if len(args) < 2 {
		r.printf("rename: need <old> <new>")
		return
	}
	if err := r.svc.RenameSession(ctx, args[0], args[1]); err != nil {
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
	if err := r.svc.DeleteSession(ctx, args[0]); err != nil {
		r.printf("rm: %v", err)
		return
	}
	r.printf("deleted stored session %q", args[0])
}

func (r *REPL) cmdDeleteEntry(ctx context.Context, args []string) {
	session, id, ok := r.parseTarget("rm-entry", args)
	if !ok {
		return
	}
	if err := r.svc.DeleteEntry(ctx, session, id); err != nil {
		r.printf("rm-entry: %v", err)
		return
	}
	r.printf("deleted entry %d from session %q", id, session)
}

func (r *REPL) cmdExport(ctx context.Context, args []string) {
	if len(args) == 0 {
		r.printf("export: need a session id")
		return
	}
	id := args[0]
	if len(args) == 1 {
		if err := r.svc.Export(ctx, id, r.out); err != nil {
			r.printf("export: %v", err)
		}
		return
	}
	if err := r.svc.ExportFile(ctx, id, args[1]); err != nil {
		r.printf("export: %v", err)
		return
	}
	r.printf("exported session %q to %s", id, args[1])
}

func (r *REPL) cmdImport(ctx context.Context, args []string) {
	if len(args) == 0 {
		r.printf("import: need a HAR file")
		return
	}
	id := ""
	if len(args) >= 3 && args[1] == "as" {
		id = args[2]
	}
	n, err := r.svc.ImportFile(ctx, args[0], id)
	if err != nil {
		r.printf("import: %v", err)
		return
	}
	r.printf("imported %d entries", n)
}

func (r *REPL) cmdCert() {
	info := r.svc.CertInfo()
	fmt.Fprintf(r.out, "CA certificate: %s\n\n%s\n", info.Path, info.Instruction)
	if info.TrustCmd != "" {
		fmt.Fprintf(r.out, "  %s\n", info.TrustCmd)
	}
}

func (r *REPL) cmdBrowser(args []string) {
	url := ""
	if len(args) > 0 {
		url = args[0]
	}
	proxyURL, err := r.svc.LaunchBrowser(url)
	if err != nil {
		r.printf("browser: %v", err)
		return
	}
	if url == "" {
		url = "the fingerprint echo"
	}
	r.printf("launched Chrome at %s through %s", url, proxyURL)
}

// parseTarget reads the "<session> <id>" argument pair shared by the commands
// that address a single entry or connection.
func (r *REPL) parseTarget(cmd string, args []string) (session string, id int64, ok bool) {
	if len(args) < 2 {
		r.printf("%s: need <session> <id>", cmd)
		return "", 0, false
	}
	n, err := strconv.ParseInt(args[1], 10, 64)
	if err != nil {
		r.printf("%s: %q is not an id", cmd, args[1])
		return "", 0, false
	}
	return args[0], n, true
}

// elide shortens a long hex blob for display, keeping the head that identifies it.
func elide(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("… (%d bytes)", len(s)/2)
}
