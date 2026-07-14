package browser

import (
	"slices"
	"strings"
	"testing"
)

func TestChromeArgsRoutesThroughProxy(t *testing.T) {
	args := chromeArgs("/tmp/profile", Options{
		ProxyURL: "http://127.0.0.1:8080",
		URL:      "https://tls.peet.ws/api/all",
	})

	want := []string{
		"--user-data-dir=/tmp/profile",
		"--no-first-run",
		"--no-default-browser-check",
		"--proxy-bypass-list=<-loopback>",
		"--proxy-server=http://127.0.0.1:8080",
	}
	for _, w := range want {
		if !slices.Contains(args, w) {
			t.Errorf("args missing %q:\n%v", w, args)
		}
	}
	// The URL must be the final positional argument, after all flags.
	if args[len(args)-1] != "https://tls.peet.ws/api/all" {
		t.Errorf("URL should be the last arg, got %v", args)
	}
	if slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(a, "--ignore-certificate-errors") }) {
		t.Errorf("cert errors should not be ignored by default:\n%v", args)
	}
}

func TestChromeArgsOmitsProxyWhenEmpty(t *testing.T) {
	args := chromeArgs("/tmp/profile", Options{URL: "about:blank"})
	if slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(a, "--proxy-server") }) {
		t.Errorf("no --proxy-server expected when ProxyURL is empty:\n%v", args)
	}
}

func TestChromeArgsIgnoreCertErrors(t *testing.T) {
	args := chromeArgs("/tmp/profile", Options{IgnoreCertErrors: true})
	for _, w := range []string{"--ignore-certificate-errors", "--test-type"} {
		if !slices.Contains(args, w) {
			t.Errorf("args missing %q:\n%v", w, args)
		}
	}
}

func TestFindChromeHonorsEnvOverride(t *testing.T) {
	t.Setenv("LEBEDEV_CHROME", "/custom/path/to/chrome")
	got, err := FindChrome()
	if err != nil {
		t.Fatal(err)
	}
	if got != "/custom/path/to/chrome" {
		t.Errorf("FindChrome = %q, want the LEBEDEV_CHROME value", got)
	}
}
