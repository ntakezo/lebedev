// Command lebedev is a transparent MITM proxy that forwards each intercepted
// request with a stock latest-Chrome fingerprint while recording the traffic
// byte-faithfully. It has two front ends over one control surface (package
// service): an interactive REPL by default, and an MCP server under the "mcp"
// subcommand, so a person and an LLM drive exactly the same operations.
//
// The durable store (system state) persists across runs, while each capture
// session lives in memory and is discarded on exit unless saved or exported.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ntakezo/lebedev/internal/ca"
	"github.com/ntakezo/lebedev/internal/mcpserver"
	"github.com/ntakezo/lebedev/internal/repl"
	"github.com/ntakezo/lebedev/internal/service"
	"github.com/ntakezo/lebedev/repository/sqlite"
)

func main() {
	args := os.Args[1:]
	mode := "repl"
	if len(args) > 0 && args[0] == "mcp" {
		mode, args = "mcp", args[1:]
	}

	fs := flag.NewFlagSet("lebedev", flag.ExitOnError)
	dir := defaultDir()
	// A new filename rather than the old store.db: the schema is a rewrite with no
	// migration from the previous layout, so an existing store is left alone.
	db := fs.String("db", filepath.Join(dir, "lebedev.db"), "path to the durable SQLite store")
	certPath := fs.String("ca-cert", filepath.Join(dir, "ca.crt"), "path to the CA certificate")
	keyPath := fs.String("ca-key", filepath.Join(dir, "ca.key"), "path to the CA private key")
	fs.Usage = usage(fs)
	fs.Parse(args)

	authority, err := ca.LoadOrGenerate(*certPath, *keyPath, "Lebedev CA")
	if err != nil {
		fatal("ca: %v", err)
	}
	repo, err := sqlite.Open(*db)
	if err != nil {
		fatal("store: %v", err)
	}
	defer repo.Close()

	svc := service.New(repo, authority, *certPath)
	defer svc.Close()

	// Startup notes go to stderr in both modes: on stdout they would corrupt the
	// MCP server's JSON-RPC stream.
	fmt.Fprintf(os.Stderr, "lebedev: durable store %s (CA: %s)\n", *db, *certPath)

	if mode == "mcp" {
		fmt.Fprintln(os.Stderr, "lebedev: serving MCP over stdio")
		// A client that disconnects closes stdin; that is how the server is meant to
		// end, so it must not exit non-zero and make the client log a crash.
		if err := mcpserver.New(svc).Run(context.Background(), &mcp.StdioTransport{}); err != nil && !disconnected(err) {
			fatal("mcp: %v", err)
		}
		return
	}

	fmt.Fprintln(os.Stderr, "lebedev: type 'help' for commands")
	if err := repl.New(svc, os.Stdout).Run(os.Stdin); err != nil {
		fatal("repl: %v", err)
	}
}

// disconnected reports whether an MCP session ended because the peer went away
// rather than because something failed. The SDK surfaces a closed stdio pipe as
// an internal JSON-RPC error that wraps no exported sentinel, so the EOF has to
// be recognized by its message as well as by the error chain.
func disconnected(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, mcp.ErrConnectionClosed) ||
		strings.HasSuffix(err.Error(), io.EOF.Error())
}

func usage(fs *flag.FlagSet) func() {
	return func() {
		fmt.Fprint(os.Stderr, `usage:
  lebedev [flags]       interactive REPL (default)
  lebedev mcp [flags]   Model Context Protocol server over stdio

flags:
`)
		fs.PrintDefaults()
	}
}

func defaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".lebedev"
	}
	return filepath.Join(home, ".lebedev")
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "lebedev: "+format+"\n", args...)
	os.Exit(1)
}
