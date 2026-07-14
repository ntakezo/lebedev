// Package browser launches a fresh, isolated Google Chrome routed through the
// lebedev proxy, so a capture starts from a clean browser whose real TLS and
// HTTP/2 fingerprint is what the proxy mirrors upstream.
package browser

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// Options configures a Chrome launch. ProxyURL is the lebedev proxy Chrome routes
// through (e.g. http://127.0.0.1:8080); empty launches Chrome without a proxy.
// ExecPath overrides Chrome autodetection. URL is the first page to open.
// IgnoreCertErrors skips TLS validation instead of trusting the CA.
type Options struct {
	ProxyURL         string
	ExecPath         string
	URL              string
	IgnoreCertErrors bool
	ExtraArgs        []string
	Stdout           io.Writer
	Stderr           io.Writer
}

// Launch starts Chrome with the given options and blocks until it exits or ctx is
// canceled (which terminates Chrome). It always creates a throwaway profile
// directory and removes it on return, so each launch is a clean browser with no
// cookies, history, or extensions — the state a fingerprint capture should start
// from. It returns an error if Chrome cannot be located or fails to start.
func Launch(ctx context.Context, opts Options) error {
	bin := opts.ExecPath
	if bin == "" {
		found, err := FindChrome()
		if err != nil {
			return err
		}
		bin = found
	}

	dataDir, err := os.MkdirTemp("", "lebedev-chrome-")
	if err != nil {
		return fmt.Errorf("browser: create profile dir: %w", err)
	}
	defer os.RemoveAll(dataDir)

	cmd := exec.CommandContext(ctx, bin, chromeArgs(dataDir, opts)...)
	cmd.Stdout = opts.Stdout
	cmd.Stderr = opts.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("browser: start chrome: %w", err)
	}
	return cmd.Wait()
}

// chromeArgs builds Chrome's command line. A unique user-data-dir forces a fresh,
// independent instance (so Chrome does not hand the URL to an already-running
// browser and return immediately), and proxy-bypass-list=<-loopback> routes even
// loopback requests through the proxy so a local fingerprint echo can be captured.
func chromeArgs(dataDir string, opts Options) []string {
	args := []string{
		"--user-data-dir=" + dataDir,
		"--no-first-run",
		"--no-default-browser-check",
		"--proxy-bypass-list=<-loopback>",
	}
	if opts.ProxyURL != "" {
		args = append(args, "--proxy-server="+opts.ProxyURL)
	}
	if opts.IgnoreCertErrors {
		// --test-type suppresses the banner Chrome otherwise shows for
		// --ignore-certificate-errors, which would alter the window.
		args = append(args, "--ignore-certificate-errors", "--test-type")
	}
	args = append(args, opts.ExtraArgs...)
	if opts.URL != "" {
		args = append(args, opts.URL)
	}
	return args
}

// FindChrome returns the path to an installed Google Chrome (or Chromium)
// executable. It honors the LEBEDEV_CHROME environment variable first, then PATH,
// then the platform's well-known install locations, and errors when none is found.
func FindChrome() (string, error) {
	if env := os.Getenv("LEBEDEV_CHROME"); env != "" {
		return env, nil
	}
	for _, name := range pathNames() {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	for _, p := range knownPaths() {
		if isExecutableFile(p) {
			return p, nil
		}
	}
	return "", fmt.Errorf("browser: Google Chrome not found; set --chrome or LEBEDEV_CHROME")
}

// pathNames lists the Chrome/Chromium executable names to look for on PATH.
func pathNames() []string {
	if runtime.GOOS == "windows" {
		return []string{"chrome.exe"}
	}
	return []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"}
}

// knownPaths lists the platform's default Chrome install locations, most likely
// first.
func knownPaths() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			filepath.Join(os.Getenv("HOME"), "Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
			"/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		}
	case "windows":
		var out []string
		for _, base := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LocalAppData")} {
			if base != "" {
				out = append(out, filepath.Join(base, "Google", "Chrome", "Application", "chrome.exe"))
			}
		}
		return out
	default:
		return []string{
			"/usr/bin/google-chrome",
			"/usr/bin/google-chrome-stable",
			"/usr/bin/chromium",
			"/usr/bin/chromium-browser",
			"/snap/bin/chromium",
		}
	}
}

func isExecutableFile(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}
