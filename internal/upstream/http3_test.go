package upstream

import (
	"errors"
	"testing"

	http "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
)

func TestMatchFamily(t *testing.T) {
	tests := []struct {
		name        string
		pseudoOrder []string
		want        browserFamily
	}{
		{"chrome order", []string{":method", ":authority", ":scheme", ":path"}, familyChrome},
		{"firefox order", []string{":method", ":path", ":authority", ":scheme"}, familyFirefox},
		{"safari-ish order falls back to chrome", []string{":method", ":scheme", ":path", ":authority"}, familyChrome},
		{"empty falls back to chrome", nil, familyChrome},
		{"short falls back to chrome", []string{":method", ":path"}, familyChrome},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchFamily(tt.pseudoOrder); got != tt.want {
				t.Errorf("matchFamily(%v) = %v, want %v", tt.pseudoOrder, got, tt.want)
			}
		})
	}
}

func TestH3ProfileForFamily(t *testing.T) {
	chrome := h3ProfileFor(familyChrome)
	if chrome.settings[0x1] != 65536 || chrome.settings[0x7] != 100 {
		t.Errorf("chrome h3 settings = %v", chrome.settings)
	}
	if chrome.priorityParam != 984832 {
		t.Errorf("chrome priorityParam = %d, want 984832", chrome.priorityParam)
	}
	wantOrder := []uint64{0x1, 0x6, 0x7, 0x33}
	if len(chrome.settingsOrder) != len(wantOrder) {
		t.Fatalf("chrome settingsOrder = %v, want %v", chrome.settingsOrder, wantOrder)
	}
	for i, v := range wantOrder {
		if chrome.settingsOrder[i] != v {
			t.Errorf("chrome settingsOrder[%d] = %d, want %d", i, chrome.settingsOrder[i], v)
		}
	}

	firefox := h3ProfileFor(familyFirefox)
	if firefox.priorityParam != 0 {
		t.Errorf("firefox priorityParam = %d, want 0", firefox.priorityParam)
	}
	if _, ok := firefox.settings[727725890]; !ok {
		t.Errorf("firefox h3 settings missing reserved setting: %v", firefox.settings)
	}
	if firefox.pseudoOrder[1] != ":scheme" {
		t.Errorf("firefox pseudoOrder = %v, want :scheme second", firefox.pseudoOrder)
	}
}

// TestBuildProfileCarriesH3Fingerprint asserts the synthesized h3 traits reach
// the built client profile, where tls-client's racer reads them. The captured
// fingerprint uses Chrome's pseudo-header order, so the Chrome h3 profile applies.
func TestBuildProfileCarriesH3Fingerprint(t *testing.T) {
	profile, err := buildProfile(chromeHelloRecord(t), captureFingerprint(t))
	if err != nil {
		t.Fatalf("buildProfile: %v", err)
	}
	if got := profile.GetHttp3Settings()[0x1]; got != 65536 {
		t.Errorf("h3 QPACK_MAX_TABLE_CAPACITY = %d, want 65536", got)
	}
	if got := profile.GetHttp3Settings()[0x7]; got != 100 {
		t.Errorf("h3 QPACK_BLOCKED_STREAMS = %d, want 100", got)
	}
	if got := profile.GetHttp3PriorityParam(); got != 984832 {
		t.Errorf("h3 priorityParam = %d, want 984832", got)
	}
	if !profile.GetHttp3SendGreaseFrames() {
		t.Error("h3 sendGreaseFrames = false, want true")
	}
	wantPseudo := []string{":method", ":authority", ":scheme", ":path"}
	if got := profile.GetHttp3PseudoHeaderOrder(); !equalStrings(got, wantPseudo) {
		t.Errorf("h3 pseudoOrder = %v, want %v", got, wantPseudo)
	}
}

func TestAltSvcOffersH3(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   bool
	}{
		{"none", nil, false},
		{"h3 only", []string{`h3=":443"; ma=2592000`}, true},
		{"h3 among others", []string{`h2=":443"; ma=60, h3=":443"; ma=2592000`}, true},
		{"draft h3", []string{`h3-29=":443"; ma=86400`}, true},
		{"quoted id", []string{`"h3"=":443"`}, true},
		{"h2 only", []string{`h2=":443"; ma=3600`}, false},
		{"clear", []string{"clear"}, false},
		{"no h3 substring false positive", []string{`h3x=":443"`}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			for _, v := range tt.values {
				h.Add("Alt-Svc", v)
			}
			if got := altSvcOffersH3(h); got != tt.want {
				t.Errorf("altSvcOffersH3(%v) = %v, want %v", tt.values, got, tt.want)
			}
		})
	}
}

// fakeClient satisfies tlsclient.HttpClient by embedding the interface (only Do
// is exercised) and returns a fixed response tagged with an id so a test can tell
// which client served a request.
type fakeClient struct {
	tlsclient.HttpClient
	id string
}

func (f fakeClient) Do(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: http.Header{"X-Client": []string{f.id}}, Body: http.NoBody}, nil
}

// TestMirrorDoSelectsClientByUpgradeState verifies request routing: the h2 client
// serves until the origin advertises h3, then the racing client takes over.
func TestMirrorDoSelectsClientByUpgradeState(t *testing.T) {
	m := Mirror{
		h2Client: fakeClient{id: "h2"},
		usedH2:   true,
		up:       &h3upgrade{build: func() (tlsclient.HttpClient, error) { return fakeClient{id: "h3"}, nil }},
	}
	hr, err := http.NewRequest("GET", "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}

	served := func() string {
		resp, err := m.do(hr)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		return resp.Header.Get("X-Client")
	}

	if got := served(); got != "h2" {
		t.Errorf("before upgrade served by %q, want h2", got)
	}

	adv := http.Header{}
	adv.Add("Alt-Svc", `h3=":443"; ma=2592000`)
	m.up.observe(adv)

	if got := served(); got != "h3" {
		t.Errorf("after upgrade served by %q, want h3", got)
	}
}

// TestMirrorDoFallsBackWhenRacingBuildFails verifies that an h3-armed mirror whose
// racing client cannot be built still serves the request over h2 rather than failing.
func TestMirrorDoFallsBackWhenRacingBuildFails(t *testing.T) {
	m := Mirror{
		h2Client: fakeClient{id: "h2"},
		usedH2:   true,
		up:       &h3upgrade{advertised: true, build: func() (tlsclient.HttpClient, error) { return nil, errors.New("no quic") }},
	}
	hr, err := http.NewRequest("GET", "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := m.do(hr)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if got := resp.Header.Get("X-Client"); got != "h2" {
		t.Errorf("served by %q, want h2 fallback", got)
	}
}

func TestH3UpgradeObserve(t *testing.T) {
	u := &h3upgrade{}

	// No Alt-Svc: decision stays disarmed.
	u.observe(http.Header{})
	if u.wantH3() {
		t.Error("absent Alt-Svc should not arm h3")
	}

	// Advertising h3 arms the upgrade.
	h := http.Header{}
	h.Add("Alt-Svc", `h3=":443"; ma=2592000`)
	u.observe(h)
	if !u.wantH3() {
		t.Error("Alt-Svc h3 should arm the upgrade")
	}

	// A later response without Alt-Svc leaves the armed decision in place.
	u.observe(http.Header{})
	if !u.wantH3() {
		t.Error("missing Alt-Svc must not disarm a prior h3 advertisement")
	}

	// An explicit clear disarms it.
	cl := http.Header{}
	cl.Add("Alt-Svc", "clear")
	u.observe(cl)
	if u.wantH3() {
		t.Error("Alt-Svc clear should disarm the upgrade")
	}
}

// TestH3UpgradeRacingClientBuiltOnce checks that the racing client is
// constructed lazily, exactly once, and that a build error is cached rather than
// retried so callers fall back to h2 deterministically.
func TestH3UpgradeRacingClientBuiltOnce(t *testing.T) {
	calls := 0
	wantErr := errors.New("build failed")
	u := &h3upgrade{build: func() (tlsclient.HttpClient, error) {
		calls++
		return nil, wantErr
	}}

	if _, err := u.racingClient(); !errors.Is(err, wantErr) {
		t.Fatalf("racingClient err = %v, want %v", err, wantErr)
	}
	if _, err := u.racingClient(); !errors.Is(err, wantErr) {
		t.Fatalf("racingClient (second) err = %v, want %v", err, wantErr)
	}
	if calls != 1 {
		t.Errorf("build called %d times, want 1 (error must be cached)", calls)
	}
}
