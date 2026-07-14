// Command lebedev is a transparent MITM proxy that mirrors each client's TLS
// and HTTP/2 fingerprint upstream while streaming faithful request/response
// records for inspection.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ntakezo/lebedev/internal/browser"
	"github.com/ntakezo/lebedev/internal/ca"
	"github.com/ntakezo/lebedev/internal/session"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		runCommand(os.Args[2:])
	case "cert":
		certCommand(os.Args[2:])
	case "browser":
		browserCommand(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `lebedev - transparent fingerprint-mirroring MITM proxy

usage:
  lebedev run     [flags]   start a proxy session
  lebedev cert    [flags]   ensure the CA exists and print trust instructions
  lebedev browser [flags]   launch a fresh Chrome routed through the proxy
`)
}

func runCommand(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "listen address for the HTTP CONNECT proxy")
	outboundProxy := fs.String("upstream-proxy", "", "outbound proxy URL for this session, e.g. http://host:port")
	out := fs.String("out", "-", "session data output: - for stdout or a file path")
	id := fs.String("session", "default", "session id recorded on each transaction")
	var urlFilters, typeFilters stringList
	fs.Var(&urlFilters, "filter-url", "only record request URLs matching this glob (repeatable; * matches any chars), e.g. '*//*/*.html'")
	fs.Var(&typeFilters, "filter-type", "only record responses of this content type (repeatable): html,image,json,css,js,font,media,video,audio,xml,text or a MIME glob like 'image/*'")
	certPath, keyPath := caFlags(fs)
	fs.Parse(args)

	authority, err := ca.LoadOrGenerate(*certPath, *keyPath, "Lebedev CA")
	if err != nil {
		fatal("ca: %v", err)
	}

	sink, closeSink, err := openSink(*out)
	if err != nil {
		fatal("output: %v", err)
	}
	defer closeSink()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fatal("listen: %v", err)
	}

	sess := session.New(session.Config{
		ID:            *id,
		OutboundProxy: *outboundProxy,
		URLFilters:    urlFilters,
		TypeFilters:   typeFilters,
	}, authority, sink)
	fmt.Fprintf(os.Stderr, "lebedev: session %q listening on %s (CA: %s)\n", *id, ln.Addr(), *certPath)
	if *outboundProxy != "" {
		fmt.Fprintf(os.Stderr, "lebedev: routing origin traffic through %s\n", *outboundProxy)
	}
	if len(urlFilters) > 0 || len(typeFilters) > 0 {
		fmt.Fprintf(os.Stderr, "lebedev: recording only url=%v type=%v\n", []string(urlFilters), []string(typeFilters))
	}
	if err := sess.Serve(ln); err != nil {
		fatal("serve: %v", err)
	}
}

func certCommand(args []string) {
	fs := flag.NewFlagSet("cert", flag.ExitOnError)
	certPath, keyPath := caFlags(fs)
	fs.Parse(args)

	if _, err := ca.LoadOrGenerate(*certPath, *keyPath, "Lebedev CA"); err != nil {
		fatal("ca: %v", err)
	}

	fmt.Printf("CA certificate: %s\n\n", *certPath)
	fmt.Print(installHint(*certPath))
}

func browserCommand(args []string) {
	fs := flag.NewFlagSet("browser", flag.ExitOnError)
	proxy := fs.String("proxy", "http://127.0.0.1:8080", "lebedev proxy URL Chrome routes through")
	execPath := fs.String("chrome", "", "path to the Chrome binary (auto-detected when empty)")
	url := fs.String("url", "https://tls.peet.ws/api/all", "initial URL to open")
	ignoreCert := fs.Bool("ignore-cert-errors", false, "ignore TLS cert errors instead of trusting the CA")
	fs.Parse(args)

	// Cancel the launch (and terminate Chrome) on Ctrl-C.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	err := browser.Launch(ctx, browser.Options{
		ProxyURL: *proxy,

		ExecPath:         *execPath,
		URL:              *url,
		IgnoreCertErrors: *ignoreCert,
		// Chrome logs to stderr; keep stdout free for anything piped from the proxy.
		Stdout: os.Stderr,
		Stderr: os.Stderr,
	})
	if err != nil && ctx.Err() == nil {
		fatal("browser: %v", err)
	}
}

// openSink returns a sink writing to stdout (when out is "-") or to a file,
// along with a close function for any file it opened.
func openSink(out string) (*session.Sink, func(), error) {
	if out == "-" {
		return session.NewSink(os.Stdout), func() {}, nil
	}
	f, err := os.Create(out)
	if err != nil {
		return nil, nil, err
	}
	return session.NewSink(f), func() { f.Close() }, nil
}

func caFlags(fs *flag.FlagSet) (certPath, keyPath *string) {
	dir := defaultCADir()
	certPath = fs.String("ca-cert", filepath.Join(dir, "ca.crt"), "path to the CA certificate")
	keyPath = fs.String("ca-key", filepath.Join(dir, "ca.key"), "path to the CA private key")
	return certPath, keyPath
}

func defaultCADir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".lebedev"
	}
	return filepath.Join(home, ".lebedev")
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

// stringList is a repeatable string flag: each occurrence appends a value, so
// --filter-type html --filter-type image yields ["html", "image"].
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "lebedev: "+format+"\n", args...)
	os.Exit(1)
}
