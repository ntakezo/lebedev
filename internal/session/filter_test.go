package session

import "testing"

func rec(scheme, authority, target, contentType string) Record {
	var headers []Header
	if contentType != "" {
		headers = []Header{{Name: "Content-Type", Value: contentType}}
	}
	return Record{
		Request:  Request{Scheme: scheme, Authority: authority, Target: target},
		Response: Response{Headers: headers},
	}
}

func TestFilterEmptyAdmitsEverything(t *testing.T) {
	f := newFilter(nil, nil)
	if !f.allows(rec("https", "example.com", "/", "")) {
		t.Error("empty filter should admit all records")
	}
}

func TestFilterURLGlob(t *testing.T) {
	f := newFilter([]string{"*//*/*.html"}, nil)
	cases := []struct {
		url  string
		want bool
	}{
		{"/en/index.html", true},
		{"/a/b/c/page.html", true},
		{"/style.css", false},
		{"/", false},
	}
	for _, c := range cases {
		if got := f.allows(rec("https", "www.fifa.com", c.url, "")); got != c.want {
			t.Errorf("url %q: allows=%v want %v", c.url, got, c.want)
		}
	}
}

func TestFilterURLStarMatchesSlashes(t *testing.T) {
	// The user's example: *//*/* must match a full scheme://host/path URL.
	f := newFilter([]string{"*//*/*"}, nil)
	if !f.allows(rec("https", "www.fifa.com", "/en/tickets", "")) {
		t.Error("*//*/* should match https://www.fifa.com/en/tickets")
	}
	f2 := newFilter([]string{"*fifa.com*"}, nil)
	if !f2.allows(rec("https", "www.fifa.com", "/en/tickets", "")) {
		t.Error("*fifa.com* should match by host substring")
	}
	if f2.allows(rec("https", "example.com", "/", "")) {
		t.Error("*fifa.com* should not match example.com")
	}
}

func TestFilterTypeCategories(t *testing.T) {
	cases := []struct {
		filter      string
		contentType string
		want        bool
	}{
		{"html", "text/html; charset=utf-8", true},
		{"html", "application/json", false},
		{"image", "image/png", true},
		{"image", "image/svg+xml", true},
		{"image", "text/html", false},
		{"json", "application/json", true},
		{"json", "application/vnd.api+json", true},
		{"js", "text/javascript", true},
		{"js", "application/javascript", true},
		{"font", "font/woff2", true},
		{"video", "video/mp4", true},
		{"media", "audio/mpeg", true},
		{"xml", "application/xml", true},
		{"text", "text/plain", true},
		{"text/html", "text/html", true}, // raw MIME literal
		{"application/*", "application/pdf", true},
	}
	for _, c := range cases {
		f := newFilter(nil, []string{c.filter})
		if got := f.allows(rec("https", "x", "/", c.contentType)); got != c.want {
			t.Errorf("filter %q vs %q: allows=%v want %v", c.filter, c.contentType, got, c.want)
		}
	}
}

func TestFilterNoContentTypeExcludedByTypeFilter(t *testing.T) {
	f := newFilter(nil, []string{"html"})
	if f.allows(rec("https", "x", "/", "")) {
		t.Error("a record with no Content-Type should not match a type filter")
	}
}

func TestFilterURLAndTypeAreANDed(t *testing.T) {
	f := newFilter([]string{"*fifa.com*"}, []string{"html"})
	if !f.allows(rec("https", "www.fifa.com", "/en", "text/html")) {
		t.Error("matching url and type should be admitted")
	}
	if f.allows(rec("https", "www.fifa.com", "/en", "image/png")) {
		t.Error("url match but type miss should be rejected")
	}
	if f.allows(rec("https", "other.com", "/en", "text/html")) {
		t.Error("type match but url miss should be rejected")
	}
}
