package mcpserver

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ntakezo/lebedev/internal/service"
	"github.com/ntakezo/lebedev/model"
)

// defaultMaxBodyBytes bounds a body returned by entry_get. Captured bodies run to
// megabytes, which is useful on disk and useless in a reply, so the tool clips
// them by default and says so.
const defaultMaxBodyBytes = 8 * 1024

// captureInfo is the live capture as tools report it.
type captureInfo struct {
	Active      bool   `json:"active" jsonschema:"whether a capture exists at all"`
	ID          string `json:"id,omitempty" jsonschema:"the session name the capture records into"`
	Addr        string `json:"addr,omitempty" jsonschema:"the address the proxy is listening on"`
	Running     bool   `json:"running" jsonschema:"whether the proxy is currently serving"`
	Entries     int    `json:"entries" jsonschema:"entries recorded so far, in memory only"`
	Connections int    `json:"connections" jsonschema:"distinct client TLS connections recorded so far"`
	ProxyURL    string `json:"proxyUrl,omitempty" jsonschema:"the HTTPS proxy URL a client should be pointed at"`
}

func describeCapture(c service.Capture) captureInfo {
	return captureInfo{
		Active:      true,
		ID:          c.ID,
		Addr:        c.Addr,
		Running:     c.Running,
		Entries:     c.Entries,
		Connections: c.Connections,
		ProxyURL:    "http://" + c.Addr,
	}
}

type captureStartInput struct {
	ID            string `json:"id,omitempty" jsonschema:"name for the session this capture records into (default \"default\")"`
	Addr          string `json:"addr,omitempty" jsonschema:"listen address for the proxy, e.g. \":8080\" (default \":8080\")"`
	OutboundProxy string `json:"outboundProxy,omitempty" jsonschema:"optional upstream proxy URL to route origin traffic through"`
}

func (h *handlers) captureStart(ctx context.Context, _ *mcp.CallToolRequest, in captureStartInput) (*mcp.CallToolResult, captureInfo, error) {
	c, err := h.svc.StartCapture(ctx, service.RunOptions{ID: in.ID, Addr: in.Addr, OutboundProxy: in.OutboundProxy})
	if err != nil {
		return fail[captureInfo](err)
	}
	info := describeCapture(c)
	return ok(info, "capturing session %q on %s; point a client at %s. Entries are in memory only until capture_save.", info.ID, info.Addr, info.ProxyURL)
}

func (h *handlers) captureStatus(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, captureInfo, error) {
	c, active, err := h.svc.ActiveCapture(ctx)
	if err != nil {
		return fail[captureInfo](err)
	}
	if !active {
		return ok(captureInfo{}, "no active capture; start one with capture_start")
	}
	info := describeCapture(c)
	state := "stopped"
	if info.Running {
		state = "running"
	}
	return ok(info, "capture %q is %s on %s with %d entries over %d connections", info.ID, state, info.Addr, info.Entries, info.Connections)
}

type captureTargetInput struct {
	ID string `json:"id" jsonschema:"name of the capture to act on"`
}

func (h *handlers) captureStop(ctx context.Context, _ *mcp.CallToolRequest, in captureTargetInput) (*mcp.CallToolResult, captureInfo, error) {
	c, err := h.svc.StopCapture(ctx, in.ID)
	if err != nil {
		return fail[captureInfo](err)
	}
	info := describeCapture(c)
	return ok(info, "stopped capture %q; its %d entries stay readable and capture_resume re-serves it on %s", info.ID, info.Entries, info.Addr)
}

func (h *handlers) captureResume(ctx context.Context, _ *mcp.CallToolRequest, in captureTargetInput) (*mcp.CallToolResult, captureInfo, error) {
	c, err := h.svc.ResumeCapture(ctx, in.ID)
	if err != nil {
		return fail[captureInfo](err)
	}
	info := describeCapture(c)
	return ok(info, "resumed capture %q on %s", info.ID, info.Addr)
}

type saveResult struct {
	Session string `json:"session" jsonschema:"the session name written to the durable store"`
	Entries int    `json:"entries" jsonschema:"how many entries were written"`
}

func (h *handlers) captureSave(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, saveResult, error) {
	c, _, err := h.svc.ActiveCapture(ctx)
	if err != nil {
		return fail[saveResult](err)
	}
	n, err := h.svc.SaveCapture(ctx)
	if err != nil {
		return fail[saveResult](err)
	}
	out := saveResult{Session: c.ID, Entries: n}
	return ok(out, "saved session %q to the durable store (%d entries)", out.Session, out.Entries)
}

type sessionSummary struct {
	Name        string `json:"name"`
	Entries     int    `json:"entries"`
	Connections int    `json:"connections"`
	CreatedAt   string `json:"createdAt" jsonschema:"RFC 3339 timestamp of when the session was created"`
}

type sessionsListResult struct {
	Sessions []sessionSummary `json:"sessions"`
}

func (h *handlers) sessionsList(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, sessionsListResult, error) {
	infos, err := h.svc.Sessions(ctx)
	if err != nil {
		return fail[sessionsListResult](err)
	}
	out := sessionsListResult{Sessions: make([]sessionSummary, 0, len(infos))}
	for _, si := range infos {
		out.Sessions = append(out.Sessions, sessionSummary{
			Name:        si.Name,
			Entries:     si.Entries,
			Connections: si.Connections,
			CreatedAt:   si.CreatedAt.UTC().Format(rfc3339Millis),
		})
	}
	if len(out.Sessions) == 0 {
		return ok(out, "no stored sessions")
	}
	return ok(out, "%d stored sessions", len(out.Sessions))
}

const rfc3339Millis = "2006-01-02T15:04:05.000Z07:00"

type sessionShowInput struct {
	Session string `json:"session" jsonschema:"name of the session to list"`
	Limit   int    `json:"limit,omitempty" jsonschema:"maximum entries to return (default 100, 0 means the default)"`
	Offset  int    `json:"offset,omitempty" jsonschema:"how many entries to skip, for paging through a long session"`
}

type entrySummary struct {
	ID              int64  `json:"id" jsonschema:"pass this to entry_get"`
	Connection      int64  `json:"connection" jsonschema:"the TLS connection this entry was captured over; 0 if none"`
	Method          string `json:"method"`
	URL             string `json:"url"`
	Status          int    `json:"status"`
	MimeType        string `json:"mimeType,omitempty"`
	BodySize        int    `json:"bodySize"`
	StartedDateTime string `json:"startedDateTime"`
}

type connectionSummary struct {
	ID            int64  `json:"id" jsonschema:"pass this to connection_get"`
	UpstreamProto string `json:"upstreamProto,omitempty"`
	HasHTTP2      bool   `json:"hasHttp2" jsonschema:"false for an HTTP/1.1 connection"`
	Entries       int    `json:"entries" jsonschema:"how many of this session's entries were captured over it"`
}

type sessionShowResult struct {
	Session     string              `json:"session"`
	Live        bool                `json:"live" jsonschema:"true when this is the in-memory capture rather than a stored session"`
	Entries     []entrySummary      `json:"entries"`
	Total       int                 `json:"total" jsonschema:"how many entries the session holds in all"`
	Returned    int                 `json:"returned"`
	Offset      int                 `json:"offset"`
	Connections []connectionSummary `json:"connections"`
}

func (h *handlers) sessionShow(ctx context.Context, _ *mcp.CallToolRequest, in sessionShowInput) (*mcp.CallToolResult, sessionShowResult, error) {
	d, err := h.svc.Session(ctx, in.Session)
	if err != nil {
		return fail[sessionShowResult](err)
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 100
	}

	perConn := map[int64]int{}
	for _, e := range d.Entries {
		perConn[e.Connection]++
	}

	out := sessionShowResult{
		Session: d.Name,
		Live:    h.isLive(ctx, d.Name),
		Total:   len(d.Entries),
		Offset:  in.Offset,
	}
	for i := in.Offset; i < len(d.Entries) && len(out.Entries) < limit; i++ {
		e := d.Entries[i]
		out.Entries = append(out.Entries, entrySummary{
			ID: e.ID, Connection: e.Connection, Method: e.Method, URL: e.URL,
			Status: e.Status, MimeType: e.MimeType, BodySize: e.BodySize,
			StartedDateTime: e.StartedDateTime,
		})
	}
	out.Returned = len(out.Entries)
	for _, c := range d.Connections {
		out.Connections = append(out.Connections, connectionSummary{
			ID: c.ID, UpstreamProto: c.UpstreamProto, HasHTTP2: c.HTTP2 != nil, Entries: perConn[c.ID],
		})
	}

	summary := fmt.Sprintf("session %q: %d entries over %d connections", out.Session, out.Total, len(out.Connections))
	if out.Returned < out.Total {
		summary += fmt.Sprintf("; returned %d starting at offset %d — raise limit or offset for the rest", out.Returned, out.Offset)
	}
	return ok(out, "%s", summary)
}

// isLive reports whether a name refers to the in-memory capture rather than a
// stored session, which tells a caller its entries vanish unless saved.
func (h *handlers) isLive(ctx context.Context, name string) bool {
	c, active, err := h.svc.ActiveCapture(ctx)
	return err == nil && active && c.ID == name
}

type sessionRenameInput struct {
	From string `json:"from" jsonschema:"current session name"`
	To   string `json:"to" jsonschema:"new session name; must not already exist"`
}

type actionResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

func (h *handlers) sessionRename(ctx context.Context, _ *mcp.CallToolRequest, in sessionRenameInput) (*mcp.CallToolResult, actionResult, error) {
	if err := h.svc.RenameSession(ctx, in.From, in.To); err != nil {
		return fail[actionResult](err)
	}
	msg := fmt.Sprintf("renamed %q to %q", in.From, in.To)
	return ok(actionResult{OK: true, Message: msg}, "%s", msg)
}

type sessionDeleteInput struct {
	Session string `json:"session" jsonschema:"name of the stored session to delete"`
}

func (h *handlers) sessionDelete(ctx context.Context, _ *mcp.CallToolRequest, in sessionDeleteInput) (*mcp.CallToolResult, actionResult, error) {
	if err := h.svc.DeleteSession(ctx, in.Session); err != nil {
		return fail[actionResult](err)
	}
	msg := fmt.Sprintf("deleted stored session %q", in.Session)
	return ok(actionResult{OK: true, Message: msg}, "%s", msg)
}

type sessionExportInput struct {
	Session string `json:"session" jsonschema:"name of the session to export"`
	Path    string `json:"path" jsonschema:"file path to write the HAR 1.3 document to; created or truncated"`
}

type exportResult struct {
	Session string `json:"session"`
	Path    string `json:"path"`
	Entries int    `json:"entries"`
}

func (h *handlers) sessionExport(ctx context.Context, _ *mcp.CallToolRequest, in sessionExportInput) (*mcp.CallToolResult, exportResult, error) {
	if in.Path == "" {
		return fail[exportResult](fmt.Errorf("path is required: a capture's HAR is routinely hundreds of megabytes, so it is written to a file"))
	}
	d, err := h.svc.Session(ctx, in.Session)
	if err != nil {
		return fail[exportResult](err)
	}
	if err := h.svc.ExportFile(ctx, in.Session, in.Path); err != nil {
		return fail[exportResult](err)
	}
	out := exportResult{Session: in.Session, Path: in.Path, Entries: len(d.Entries)}
	return ok(out, "exported session %q (%d entries) to %s", out.Session, out.Entries, out.Path)
}

type sessionImportInput struct {
	Path    string `json:"path" jsonschema:"path to a HAR 1.3 file to read"`
	Session string `json:"session,omitempty" jsonschema:"name for the imported session (defaults to the file's base name)"`
}

type importResult struct {
	Session string `json:"session"`
	Entries int    `json:"entries"`
}

func (h *handlers) sessionImport(ctx context.Context, _ *mcp.CallToolRequest, in sessionImportInput) (*mcp.CallToolResult, importResult, error) {
	n, err := h.svc.ImportFile(ctx, in.Path, in.Session)
	if err != nil {
		return fail[importResult](err)
	}
	name := in.Session
	if name == "" {
		name = baseName(in.Path)
	}
	out := importResult{Session: name, Entries: n}
	return ok(out, "imported %d entries into session %q", out.Entries, out.Session)
}

type entryGetInput struct {
	Session      string `json:"session" jsonschema:"name of the session the entry belongs to"`
	ID           int64  `json:"id" jsonschema:"entry id, as reported by session_show"`
	MaxBodyBytes int    `json:"maxBodyBytes,omitempty" jsonschema:"clip request and response bodies to this many bytes (default 8192; -1 returns them whole)"`
}

type entryGetResult struct {
	Session       string      `json:"session"`
	ID            int64       `json:"id"`
	Connection    int64       `json:"connection" jsonschema:"the TLS connection this entry was captured over; pass to connection_get"`
	Entry         model.Entry `json:"entry" jsonschema:"the HAR 1.3 entry, with lebedev's _lebedev fingerprint extension"`
	BodiesClipped bool        `json:"bodiesClipped" jsonschema:"true when a body was shortened to fit maxBodyBytes; the full bytes are still stored"`
}

func (h *handlers) entryGet(ctx context.Context, _ *mcp.CallToolRequest, in entryGetInput) (*mcp.CallToolResult, entryGetResult, error) {
	st, err := h.svc.Entry(ctx, in.Session, in.ID)
	if err != nil {
		return fail[entryGetResult](err)
	}
	max := in.MaxBodyBytes
	if max == 0 {
		max = defaultMaxBodyBytes
	}
	clipped := clipBodies(&st.Entry, max)

	out := entryGetResult{
		Session: st.Session, ID: st.ID, Connection: st.Connection,
		Entry: st.Entry, BodiesClipped: clipped,
	}
	summary := fmt.Sprintf("%s %s → %d", st.Entry.Request.Method, st.Entry.Request.URL, st.Entry.Response.Status)
	if clipped {
		summary += fmt.Sprintf(" (bodies clipped to %d bytes; raise maxBodyBytes or use session_export for the full bytes)", max)
	}
	return ok(out, "%s", summary)
}

// clipBodies shortens an entry's request and response bodies in place, reporting
// whether anything was cut. It marks a clipped body in its encoding field so a
// reader cannot mistake the result for the bytes on the wire.
func clipBodies(e *model.Entry, max int) bool {
	if max < 0 {
		return false
	}
	clipped := false
	if p := e.Request.PostData; p != nil && len(p.Text) > max {
		p.Text = p.Text[:max]
		p.Encoding = clipMark(p.Encoding)
		clipped = true
	}
	if c := &e.Response.Content; len(c.Text) > max {
		c.Text = c.Text[:max]
		c.Encoding = clipMark(c.Encoding)
		clipped = true
	}
	return clipped
}

func clipMark(encoding string) string {
	if encoding == "" {
		return "clipped"
	}
	return encoding + "+clipped"
}

type entryDeleteInput struct {
	Session string `json:"session" jsonschema:"name of the session the entry belongs to"`
	ID      int64  `json:"id" jsonschema:"entry id to delete"`
}

func (h *handlers) entryDelete(ctx context.Context, _ *mcp.CallToolRequest, in entryDeleteInput) (*mcp.CallToolResult, actionResult, error) {
	if err := h.svc.DeleteEntry(ctx, in.Session, in.ID); err != nil {
		return fail[actionResult](err)
	}
	msg := fmt.Sprintf("deleted entry %d from session %q", in.ID, in.Session)
	return ok(actionResult{OK: true, Message: msg}, "%s", msg)
}

type connectionGetInput struct {
	Session string `json:"session" jsonschema:"name of the session the connection belongs to"`
	ID      int64  `json:"id" jsonschema:"connection id, as reported by session_show or entry_get"`
}

type connectionGetResult struct {
	Session        string       `json:"session"`
	ID             int64        `json:"id"`
	ClientHelloHex string       `json:"clientHelloHex" jsonschema:"the intercepted client's raw TLS ClientHello record, hex-encoded"`
	UpstreamProto  string       `json:"upstreamProto,omitempty" jsonschema:"set only when the protocol spoken upstream differed from the client's"`
	HTTP2          *model.HTTP2 `json:"http2,omitempty" jsonschema:"the HTTP/2 fingerprint observed on this connection; absent for HTTP/1.1"`
}

func (h *handlers) connectionGet(ctx context.Context, _ *mcp.CallToolRequest, in connectionGetInput) (*mcp.CallToolResult, connectionGetResult, error) {
	c, err := h.svc.Connection(ctx, in.Session, in.ID)
	if err != nil {
		return fail[connectionGetResult](err)
	}
	out := connectionGetResult{
		Session: c.Session, ID: c.ID, ClientHelloHex: c.ClientHelloHex,
		UpstreamProto: c.UpstreamProto, HTTP2: c.HTTP2,
	}
	proto := "HTTP/1.1"
	if c.HTTP2 != nil {
		proto = "HTTP/2"
	}
	return ok(out, "connection %d of session %q: %s, %d-byte ClientHello", out.ID, out.Session, proto, len(out.ClientHelloHex)/2)
}

type certInfoResult struct {
	Path        string `json:"path" jsonschema:"where the root CA certificate lives"`
	TrustCmd    string `json:"trustCmd,omitempty" jsonschema:"the command that adds it to this platform's trust store"`
	Instruction string `json:"instruction"`
}

func (h *handlers) certInfo(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, certInfoResult, error) {
	info := h.svc.CertInfo()
	out := certInfoResult{Path: info.Path, TrustCmd: info.TrustCmd, Instruction: info.Instruction}
	return ok(out, "CA certificate at %s. %s %s", out.Path, out.Instruction, out.TrustCmd)
}

type browserLaunchInput struct {
	URL string `json:"url,omitempty" jsonschema:"page to open (defaults to a TLS fingerprint echo service)"`
}

type browserLaunchResult struct {
	URL      string `json:"url"`
	ProxyURL string `json:"proxyUrl"`
}

func (h *handlers) browserLaunch(_ context.Context, _ *mcp.CallToolRequest, in browserLaunchInput) (*mcp.CallToolResult, browserLaunchResult, error) {
	proxyURL, err := h.svc.LaunchBrowser(in.URL)
	if err != nil {
		return fail[browserLaunchResult](err)
	}
	out := browserLaunchResult{URL: in.URL, ProxyURL: proxyURL}
	if out.URL == "" {
		out.URL = "https://tls.peet.ws/api/all"
	}
	return ok(out, "launched a clean Chrome at %s through %s", out.URL, out.ProxyURL)
}

// baseName is the session name an import defaults to, matching the service's own
// rule so the reported name is the one actually used.
func baseName(path string) string {
	base := filepath.Base(path)
	return strings.TrimSuffix(base, filepath.Ext(base))
}
