package session

import (
	"regexp"
	"strings"
)

// filter decides whether a transaction record is written to the sink. It holds
// two independent globs sets — one matched against the request URL, one against
// the response content type. An empty set matches everything, so a filter with no
// patterns of either kind admits every record (the default, unfiltered behavior).
//
// A record is admitted only when it satisfies both non-empty sets (URL AND type),
// and a set is satisfied when the value matches any one of its globs (OR within a
// set). This lets "only HTML from fifa.com" be expressed as one URL glob plus one
// type, while "any image or font" is two type globs and no URL constraint.
type filter struct {
	urls  []*regexp.Regexp
	types []*regexp.Regexp
}

// newFilter compiles URL globs and content-type selectors into a filter. Each URL
// pattern is a glob where "*" matches any run of characters (including "/"), so
// "*//*/*.png" matches any scheme, host, and path ending in .png. Each type entry
// is either a friendly category (html, image, json, css, js, font, media, xml,
// text, ...) or a raw MIME glob (e.g. "image/*", "text/html").
func newFilter(urlPatterns, typePatterns []string) filter {
	var f filter
	for _, p := range urlPatterns {
		if p != "" {
			f.urls = append(f.urls, globToRegexp(p))
		}
	}
	for _, p := range typePatterns {
		for _, mime := range expandType(p) {
			f.types = append(f.types, globToRegexp(mime))
		}
	}
	return f
}

// allows reports whether rec should be written. It short-circuits to true when no
// patterns are configured.
func (f filter) allows(rec Record) bool {
	if len(f.urls) > 0 {
		url := rec.Request.Scheme + "://" + rec.Request.Authority + rec.Request.Target
		if !anyMatch(f.urls, url) {
			return false
		}
	}
	if len(f.types) > 0 {
		if !anyMatch(f.types, contentType(rec.Response.Headers)) {
			return false
		}
	}
	return true
}

func anyMatch(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// contentType returns the lowercased media type from the response's Content-Type
// header, without parameters (the part before any ";"), or "" when absent. A
// record with no content type (e.g. a bodyless redirect) therefore never matches
// a type filter, so type filtering excludes it.
func contentType(headers []Header) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, "Content-Type") {
			mime, _, _ := strings.Cut(h.Value, ";")
			return strings.ToLower(strings.TrimSpace(mime))
		}
	}
	return ""
}

// expandType maps a friendly content-type category to the MIME globs it covers.
// An unrecognized value is treated as a literal MIME glob, so callers may pass
// exact types ("text/html") or globs ("application/*") directly.
func expandType(t string) []string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "":
		return nil
	case "html":
		return []string{"text/html", "application/xhtml+xml"}
	case "json":
		return []string{"application/json", "*+json"}
	case "js", "javascript":
		return []string{"*javascript*", "application/ecmascript"}
	case "css":
		return []string{"text/css"}
	case "image", "images":
		return []string{"image/*"}
	case "font", "fonts":
		return []string{"font/*", "application/font*", "application/vnd.ms-fontobject"}
	case "video":
		return []string{"video/*"}
	case "audio":
		return []string{"audio/*"}
	case "media":
		return []string{"video/*", "audio/*"}
	case "text":
		return []string{"text/*"}
	case "xml":
		return []string{"*xml*"}
	default:
		return []string{strings.ToLower(t)}
	}
}

// globToRegexp compiles a glob into an anchored, case-insensitive regexp in which
// "*" is the only metacharacter and matches any run of characters (including "/").
// Every other character is matched literally, so URL and MIME punctuation is safe.
func globToRegexp(glob string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("(?s)^")
	for i, part := range strings.Split(glob, "*") {
		if i > 0 {
			b.WriteString(".*")
		}
		b.WriteString(regexp.QuoteMeta(part))
	}
	b.WriteString("$")
	// The pattern is built from QuoteMeta'd literals and ".*", so it always
	// compiles; MustCompile keeps the constructor total.
	return regexp.MustCompile("(?i)" + b.String())
}
