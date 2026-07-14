// Command lebedev is a transparent MITM proxy that mirrors each client's TLS
// and HTTP/2 fingerprint upstream. It presents an interactive REPL: the durable
// store (system state) persists across runs, while each capture session lives in
// memory and is discarded on exit unless exported.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ntakezo/lebedev/internal/ca"
	"github.com/ntakezo/lebedev/internal/repl"
	"github.com/ntakezo/lebedev/internal/store"
)

func main() {
	fs := flag.NewFlagSet("lebedev", flag.ExitOnError)
	dir := defaultDir()
	db := fs.String("db", "sqlite:"+filepath.Join(dir, "store.db"), "durable store DSN: sqlite:PATH or postgres://…")
	certPath := fs.String("ca-cert", filepath.Join(dir, "ca.crt"), "path to the CA certificate")
	keyPath := fs.String("ca-key", filepath.Join(dir, "ca.key"), "path to the CA private key")
	fs.Parse(os.Args[1:])

	authority, err := ca.LoadOrGenerate(*certPath, *keyPath, "Lebedev CA")
	if err != nil {
		fatal("ca: %v", err)
	}
	st, err := store.Open(*db)
	if err != nil {
		fatal("store: %v", err)
	}
	defer st.Close()

	fmt.Fprintf(os.Stderr, "lebedev: durable store %s (CA: %s)\n", *db, *certPath)
	fmt.Fprintln(os.Stderr, "lebedev: type 'help' for commands")

	if err := repl.New(st, authority, *certPath, os.Stdout).Run(os.Stdin); err != nil {
		fatal("repl: %v", err)
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
