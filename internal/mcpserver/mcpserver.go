// Package mcpserver exposes lebedev over the Model Context Protocol, so an LLM
// can drive a capture the way a developer drives the REPL. It is a translation
// layer and nothing more: every tool is a thin call into package service, which
// is the same surface the REPL uses, so the two front ends cannot drift.
//
// Tools return structured results, and the SDK derives their JSON schemas from
// the Go input and output types. Where a faithful answer would be enormous — an
// entry with a multi-megabyte body, a session with thousands of entries — the
// tool takes an explicit bound and reports what it left out, rather than
// truncating silently.
package mcpserver

import (
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ntakezo/lebedev/internal/service"
)

// version is reported to MCP clients during initialization.
const version = "1.3"

// New builds an MCP server whose tools drive svc. Run it over a transport with
// Server.Run; the caller owns svc and closes it when the server returns.
func New(svc *service.Service) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{
		Name:    "lebedev",
		Version: version,
		Title:   "Lebedev capture proxy",
	}, &mcp.ServerOptions{
		Instructions: instructions,
	})
	h := &handlers{svc: svc}
	h.register(s)
	return s
}

const instructions = `Lebedev is a man-in-the-middle proxy that records HTTPS traffic byte-faithfully.

Typical flow: capture_start opens a proxy port and a live in-memory session;
browser_launch opens a clean Chrome routed through it; session_show lists what was
recorded; entry_get reads one request/response in full; capture_save writes the
live session to the durable store so it survives.

A live capture's entries exist only in memory until capture_save. Sessions are
addressed by name, entries and connections by the numeric id a listing reports.
One TLS connection carries many entries, so connection_get is how you read the
fingerprint a group of entries shared.`

type handlers struct{ svc *service.Service }

func (h *handlers) register(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "capture_start",
		Description: "Start a capture: serve the MITM proxy on an address and record into a fresh in-memory session. Fails if a capture is already running.",
	}, h.captureStart)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "capture_status",
		Description: "Report the live capture: its name, listen address, whether it is serving, and how much it has recorded. Reports active=false when no capture has been started.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, h.captureStatus)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "capture_stop",
		Description: "Pause the live capture. Its in-memory session stays readable and can be resumed on the same address.",
	}, h.captureStop)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "capture_resume",
		Description: "Resume a stopped capture on its original address, appending to the same in-memory session.",
	}, h.captureResume)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "capture_save",
		Description: "Copy the live in-memory session into the durable store so it survives. Overwrites any stored session of the same name rather than duplicating it.",
	}, h.captureSave)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "sessions_list",
		Description: "List the durable store's sessions with their entry and connection counts. The live capture is not listed until it is saved; use capture_status for that.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, h.sessionsList)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "session_show",
		Description: "List a session's entries in capture order, with the connection each was captured over. Bodies are not included; read one entry with entry_get. The live capture answers for its own name.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, h.sessionShow)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "session_rename",
		Description: "Rename a stored session. Fails rather than merging if the new name is taken.",
	}, h.sessionRename)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "session_delete",
		Description: "Delete a stored session with its entries and connections. Does not touch the live capture.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(true)},
	}, h.sessionDelete)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "session_export",
		Description: "Write a session to a file as a HAR 1.3 document. Exports go to a file, not into the reply, because a capture's bodies are routinely hundreds of megabytes.",
	}, h.sessionExport)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "session_import",
		Description: "Load a HAR 1.3 file into a new durable session. The per-entry _lebedev fingerprint block is collapsed back into one connection record per distinct fingerprint.",
	}, h.sessionImport)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "entry_get",
		Description: "Read one entry in full as a HAR entry: request line, headers in captured order, cookies, query and post parameters, response, and bodies. Bodies are bounded by max_body_bytes and the result says whether they were clipped.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, h.entryGet)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "entry_delete",
		Description: "Delete one entry from a session. The connection it was captured over stays, since the other entries on it still need it.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(true)},
	}, h.entryDelete)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "connection_get",
		Description: "Read one TLS connection: the raw ClientHello the intercepted client sent, the HTTP/2 SETTINGS, connection flow, and pseudo-header and header order observed over it, and the protocol spoken upstream.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, h.connectionGet)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "cert_info",
		Description: "Report where lebedev's root CA lives and the command that trusts it. A client machine must trust it before lebedev can terminate its TLS.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, h.certInfo)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "browser_launch",
		Description: "Launch a fresh, isolated Chrome — clean profile, no cookies, history, or extensions — routed through the active capture.",
	}, h.browserLaunch)
}

func ptr[T any](v T) *T { return &v }

// fail turns a service error into a tool error result, so a client sees why a
// call did not work instead of a transport-level failure.
func fail[T any](err error) (*mcp.CallToolResult, T, error) {
	var zero T
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
	}, zero, nil
}

// ok returns a result whose text is a one-line summary; the structured output
// travels alongside it.
func ok[T any](out T, summary string, args ...any) (*mcp.CallToolResult, T, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(summary, args...)}},
	}, out, nil
}
