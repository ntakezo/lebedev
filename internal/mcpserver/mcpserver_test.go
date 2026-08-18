package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ntakezo/lebedev/har"
	"github.com/ntakezo/lebedev/internal/service"
	"github.com/ntakezo/lebedev/model"
	"github.com/ntakezo/lebedev/repository"
	"github.com/ntakezo/lebedev/repository/sqlite"
)

// connect stands the MCP server up over an in-memory transport and returns a
// client session speaking to it, so tools are exercised over the real protocol
// rather than called directly.
func connect(t *testing.T) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	durable, err := sqlite.Open("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { durable.Close() })
	seed(t, durable)

	svc := service.New(durable, nil, "/tmp/ca.crt")
	t.Cleanup(func() { svc.Close() })

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	if _, err := New(svc).Connect(ctx, serverTransport, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0"}, nil).Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func seed(t *testing.T, repo *sqlite.Repository) {
	t.Helper()
	ctx := context.Background()
	if _, err := repo.CreateSession(ctx, repository.Session{Name: "alpha"}); err != nil {
		t.Fatal(err)
	}
	conn, err := repo.CreateConnection(ctx, "alpha", model.Connection{
		ClientHelloHex: "16030100ff",
		HTTP2:          &model.HTTP2{PseudoOrder: []string{":method", ":path"}, ConnectionFlow: 15663105},
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, url := range []string{"https://a/1", "https://a/2"} {
		e := model.Entry{
			StartedDateTime: "2026-07-13T00:00:00.000Z",
			Request: har.Request{
				Method: "GET", URL: url, HTTPVersion: "HTTP/2.0",
				Cookies: []har.Cookie{}, Headers: []har.NVP{{Name: "user-agent", Value: "UA"}},
				QueryString: []har.NVP{}, HeadersSize: -1,
			},
			Response: har.Response{
				Status: 200, StatusText: "OK", HTTPVersion: "HTTP/2.0",
				Cookies: []har.Cookie{}, Headers: []har.NVP{}, HeadersSize: -1,
				Content: har.Content{Size: 4, MimeType: "text/plain", Text: strings.Repeat("x", 100*(i+1))},
			},
			Cache:   har.Cache{},
			Timings: har.Timings{},
		}
		if _, err := repo.CreateEntry(ctx, "alpha", conn, e); err != nil {
			t.Fatal(err)
		}
	}
}

// call invokes a tool and decodes its structured output into out.
func call(t *testing.T, cs *mcp.ClientSession, name string, args any, out any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if out != nil && !res.IsError {
		b, err := json.Marshal(res.StructuredContent)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	return res
}

func text(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// TestToolsAreAdvertised checks that every operation the REPL offers is reachable
// over MCP, which is the point of the shared service.
func TestToolsAreAdvertised(t *testing.T) {
	cs := connect(t)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, tool := range res.Tools {
		got[tool.Name] = true
		if tool.Description == "" {
			t.Errorf("tool %q has no description", tool.Name)
		}
	}
	for _, want := range []string{
		"capture_start", "capture_status", "capture_stop", "capture_resume", "capture_save",
		"sessions_list", "session_show", "session_rename", "session_delete",
		"session_export", "session_import",
		"entry_get", "entry_delete", "connection_get",
		"cert_info", "browser_launch",
	} {
		if !got[want] {
			t.Errorf("tool %q is not advertised", want)
		}
	}
}

func TestSessionReads(t *testing.T) {
	cs := connect(t)

	var list sessionsListResult
	call(t, cs, "sessions_list", struct{}{}, &list)
	if len(list.Sessions) != 1 || list.Sessions[0].Name != "alpha" || list.Sessions[0].Entries != 2 {
		t.Fatalf("sessions_list = %+v", list.Sessions)
	}
	if list.Sessions[0].Connections != 1 {
		t.Errorf("connection count = %d, want 1", list.Sessions[0].Connections)
	}

	var show sessionShowResult
	call(t, cs, "session_show", map[string]any{"session": "alpha"}, &show)
	if show.Total != 2 || show.Returned != 2 {
		t.Fatalf("session_show total/returned = %d/%d, want 2/2", show.Total, show.Returned)
	}
	if show.Live {
		t.Error("a stored session should not be reported as live")
	}
	if len(show.Connections) != 1 || show.Connections[0].Entries != 2 {
		t.Errorf("connections = %+v, want one carrying both entries", show.Connections)
	}

	var conn connectionGetResult
	call(t, cs, "connection_get", map[string]any{"session": "alpha", "id": show.Connections[0].ID}, &conn)
	if conn.ClientHelloHex != "16030100ff" {
		t.Errorf("clientHello = %q", conn.ClientHelloHex)
	}
	if conn.HTTP2 == nil || conn.HTTP2.ConnectionFlow != 15663105 {
		t.Errorf("http2 fingerprint = %+v", conn.HTTP2)
	}
}

// TestSessionShowPages checks the bound that keeps a large session from flooding
// a reply, and that the tool says what it left out.
func TestSessionShowPages(t *testing.T) {
	cs := connect(t)

	var show sessionShowResult
	res := call(t, cs, "session_show", map[string]any{"session": "alpha", "limit": 1}, &show)
	if show.Returned != 1 || show.Total != 2 {
		t.Fatalf("returned/total = %d/%d, want 1/2", show.Returned, show.Total)
	}
	if !strings.Contains(text(res), "offset") {
		t.Errorf("a clipped listing should say how to read the rest: %q", text(res))
	}

	var page2 sessionShowResult
	call(t, cs, "session_show", map[string]any{"session": "alpha", "limit": 1, "offset": 1}, &page2)
	if len(page2.Entries) != 1 || page2.Entries[0].ID == show.Entries[0].ID {
		t.Errorf("offset did not advance: %+v then %+v", show.Entries, page2.Entries)
	}
}

// TestEntryGetClipsBodies checks that a body is bounded by default, flagged when
// it is cut, and returned whole on request — a faithful store must not quietly
// hand back a shortened observation.
func TestEntryGetClipsBodies(t *testing.T) {
	cs := connect(t)
	var show sessionShowResult
	call(t, cs, "session_show", map[string]any{"session": "alpha"}, &show)
	id := show.Entries[1].ID // the 200-byte body

	var clipped entryGetResult
	res := call(t, cs, "entry_get", map[string]any{"session": "alpha", "id": id, "maxBodyBytes": 10}, &clipped)
	if !clipped.BodiesClipped {
		t.Fatal("a 200-byte body clipped to 10 should be flagged")
	}
	if len(clipped.Entry.Response.Content.Text) != 10 {
		t.Errorf("clipped body = %d bytes, want 10", len(clipped.Entry.Response.Content.Text))
	}
	if !strings.Contains(clipped.Entry.Response.Content.Encoding, "clipped") {
		t.Errorf("a clipped body must be marked in its encoding, got %q", clipped.Entry.Response.Content.Encoding)
	}
	if !strings.Contains(text(res), "clipped") {
		t.Errorf("the summary should mention the clipping: %q", text(res))
	}

	var whole entryGetResult
	call(t, cs, "entry_get", map[string]any{"session": "alpha", "id": id, "maxBodyBytes": -1}, &whole)
	if whole.BodiesClipped || len(whole.Entry.Response.Content.Text) != 200 {
		t.Errorf("maxBodyBytes=-1 should return the whole body, got %d bytes (clipped=%v)",
			len(whole.Entry.Response.Content.Text), whole.BodiesClipped)
	}
	if whole.Entry.Request.Headers[0].Name != "user-agent" {
		t.Errorf("captured headers should come through verbatim: %+v", whole.Entry.Request.Headers)
	}
}

func TestMutations(t *testing.T) {
	cs := connect(t)

	var show sessionShowResult
	call(t, cs, "session_show", map[string]any{"session": "alpha"}, &show)

	var action actionResult
	call(t, cs, "entry_delete", map[string]any{"session": "alpha", "id": show.Entries[0].ID}, &action)
	if !action.OK {
		t.Fatalf("entry_delete = %+v", action)
	}
	var after sessionShowResult
	call(t, cs, "session_show", map[string]any{"session": "alpha"}, &after)
	if after.Total != 1 {
		t.Errorf("entries after delete = %d, want 1", after.Total)
	}
	if len(after.Connections) != 1 {
		t.Errorf("the connection should outlive the entry: %+v", after.Connections)
	}

	call(t, cs, "session_rename", map[string]any{"from": "alpha", "to": "beta"}, &action)
	if !action.OK {
		t.Fatalf("session_rename = %+v", action)
	}
	call(t, cs, "session_delete", map[string]any{"session": "beta"}, &action)
	if !action.OK {
		t.Fatalf("session_delete = %+v", action)
	}
	var list sessionsListResult
	call(t, cs, "sessions_list", struct{}{}, &list)
	if len(list.Sessions) != 0 {
		t.Errorf("sessions after delete = %+v", list.Sessions)
	}
}

// TestExportImportRoundTrip drives a HAR out to disk and back in through the
// tools, which is how an MCP client moves a capture.
func TestExportImportRoundTrip(t *testing.T) {
	cs := connect(t)
	path := t.TempDir() + "/alpha.har"

	var export exportResult
	call(t, cs, "session_export", map[string]any{"session": "alpha", "path": path}, &export)
	if export.Entries != 2 {
		t.Fatalf("export = %+v", export)
	}

	var imported importResult
	call(t, cs, "session_import", map[string]any{"path": path, "session": "copy"}, &imported)
	if imported.Entries != 2 || imported.Session != "copy" {
		t.Fatalf("import = %+v", imported)
	}
	var show sessionShowResult
	call(t, cs, "session_show", map[string]any{"session": "copy"}, &show)
	if len(show.Connections) != 1 {
		t.Errorf("import should collapse the repeated fingerprint back to one connection: %+v", show.Connections)
	}
}

// TestErrorsAreReportedAsToolErrors checks a failing call comes back as a tool
// error the model can read, not a transport failure.
func TestErrorsAreReportedAsToolErrors(t *testing.T) {
	cs := connect(t)

	for _, tc := range []struct {
		tool string
		args any
		want string
	}{
		{"session_show", map[string]any{"session": "missing"}, "not found"},
		{"entry_get", map[string]any{"session": "alpha", "id": 999}, "not found"},
		{"capture_save", struct{}{}, "no active capture"},
		{"browser_launch", struct{}{}, "no active capture"},
		{"session_export", map[string]any{"session": "alpha", "path": ""}, "path is required"},
	} {
		res := call(t, cs, tc.tool, tc.args, nil)
		if !res.IsError {
			t.Errorf("%s should have failed", tc.tool)
			continue
		}
		if !strings.Contains(text(res), tc.want) {
			t.Errorf("%s error = %q, want it to mention %q", tc.tool, text(res), tc.want)
		}
	}
}

// TestCaptureLifecycle runs a capture end to end over MCP: start, observe, stop,
// resume, and report status throughout.
func TestCaptureLifecycle(t *testing.T) {
	cs := connect(t)

	var status captureInfo
	call(t, cs, "capture_status", struct{}{}, &status)
	if status.Active {
		t.Fatalf("no capture should be active yet: %+v", status)
	}

	var started captureInfo
	res := call(t, cs, "capture_start", map[string]any{"id": "live", "addr": "127.0.0.1:0"}, &started)
	if res.IsError {
		t.Fatalf("capture_start: %s", text(res))
	}
	if !started.Running || started.ID != "live" || started.ProxyURL == "" {
		t.Fatalf("capture_start = %+v", started)
	}

	// A second start must not displace a running capture.
	if res := call(t, cs, "capture_start", map[string]any{"id": "other"}, nil); !res.IsError {
		t.Error("starting a second capture should fail while one is running")
	}

	// The live session is readable by name and reports itself as live.
	var show sessionShowResult
	call(t, cs, "session_show", map[string]any{"session": "live"}, &show)
	if !show.Live {
		t.Error("the in-memory capture should be reported as live")
	}

	var stopped captureInfo
	call(t, cs, "capture_stop", map[string]any{"id": "live"}, &stopped)
	if stopped.Running {
		t.Errorf("capture should be stopped: %+v", stopped)
	}
	var resumed captureInfo
	call(t, cs, "capture_resume", map[string]any{"id": "live"}, &resumed)
	if !resumed.Running || resumed.Addr != started.Addr {
		t.Errorf("resume = %+v, want running on %s", resumed, started.Addr)
	}

	// Saving an empty capture is refused rather than writing a hollow session.
	if res := call(t, cs, "capture_save", struct{}{}, nil); !res.IsError {
		t.Error("saving a capture with no entries should fail")
	}
}
