package session

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ntakezo/lebedev/har"
	"github.com/ntakezo/lebedev/internal/capture"
	"github.com/ntakezo/lebedev/internal/proxy"
	"github.com/ntakezo/lebedev/model"
)

// harTime formats a capture instant as the ISO 8601 stamp HAR expects, in UTC
// with millisecond precision.
const harTime = "2006-01-02T15:04:05.000Z07:00"

// entryFromTransaction builds a HAR entry from one captured transaction, stamped
// at now. This is where the faithful observation is translated into HAR's model:
// bodies that are not valid UTF-8 are carried base64-encoded (the store never
// touches the bytes) and header and cookie order is preserved. The TLS and HTTP/2
// fingerprint is not part of the entry — it belongs to the connection the entry
// was captured over (see connectionFromTransaction) and is rebuilt into the
// _lebedev field on read.
func entryFromTransaction(tx proxy.Transaction, now time.Time) model.Entry {
	req := tx.Request
	resp := tx.Response

	return model.Entry{
		StartedDateTime: now.UTC().Format(harTime),
		Request:         requestEntry(req),
		Response:        responseEntry(req, resp),
		Cache:           har.Cache{},
		Timings:         har.Timings{Send: 0, Wait: 0, Receive: 0},
	}
}

// connectionFromTransaction builds the connection record for the client
// connection a transaction was observed on: the raw ClientHello, the HTTP/2
// traits negotiated over it, and the protocol actually spoken upstream when it
// differed from the client's.
func connectionFromTransaction(id string, tx proxy.Transaction) model.Connection {
	c := model.Connection{Session: id}
	if len(tx.Conn.ClientHello) > 0 {
		c.ClientHelloHex = hex.EncodeToString(tx.Conn.ClientHello)
	}
	if tx.Response.Proto != "" && tx.Response.Proto != tx.Request.Proto() {
		c.UpstreamProto = tx.Response.Proto
	}
	if tx.Request.Proto() == "HTTP/2.0" {
		c.HTTP2 = http2Fingerprint(tx.Conn.H2)
	}
	return c
}

func requestEntry(req capture.Request) har.Request {
	body := req.Body()
	r := har.Request{
		Method:      req.Method(),
		URL:         req.Scheme() + "://" + req.Authority() + req.Target(),
		HTTPVersion: req.Proto(),
		Cookies:     requestCookies(req.Headers()),
		Headers:     toNVP(req.Headers()),
		QueryString: queryString(req.Target()),
		HeadersSize: -1,
		BodySize:    len(body),
	}
	if len(body) > 0 {
		text, enc := bodyText(body)
		r.PostData = &har.PostData{
			MimeType: headerValue(req.Headers(), "Content-Type"),
			Text:     text,
			Encoding: enc,
		}
	}
	return r
}

func responseEntry(req capture.Request, resp capture.Response) har.Response {
	text, enc := bodyText(resp.Body)
	r := har.Response{
		Status:      resp.Status,
		StatusText:  http.StatusText(resp.Status),
		HTTPVersion: responseProto(req, resp),
		Cookies:     responseCookies(resp.Headers),
		Headers:     toNVP(resp.Headers),
		RedirectURL: headerValue(resp.Headers, "Location"),
		HeadersSize: -1,
		BodySize:    len(resp.Body),
		Content: har.Content{
			Size:     len(resp.Body),
			MimeType: headerValue(resp.Headers, "Content-Type"),
			Text:     text,
			Encoding: enc,
		},
	}
	return r
}

// responseProto is the client-facing response protocol: the upstream protocol
// when known, otherwise the request's.
func responseProto(req capture.Request, resp capture.Response) string {
	if resp.Proto != "" {
		return resp.Proto
	}
	return req.Proto()
}

func http2Fingerprint(fp capture.HTTP2Fingerprint) *model.HTTP2 {
	settings := make([]model.Setting, 0, len(fp.Settings()))
	for _, s := range fp.Settings() {
		settings = append(settings, model.Setting{ID: s.ID, Value: s.Value})
	}
	return &model.HTTP2{
		Settings:       settings,
		ConnectionFlow: fp.ConnectionFlow(),
		PseudoOrder:    fp.PseudoOrder(),
		HeaderOrder:    fp.HeaderOrder(),
	}
}

func toNVP(in []capture.Header) []har.NVP {
	out := make([]har.NVP, len(in))
	for i, h := range in {
		out[i] = har.NVP{Name: h.Name, Value: h.Value}
	}
	return out
}

// queryString parses target's query into ordered name/value pairs, preserving
// order and duplicates. Percent-escapes are decoded per HAR convention; an
// undecodable component is kept verbatim.
func queryString(target string) []har.NVP {
	i := strings.IndexByte(target, '?')
	if i < 0 || i == len(target)-1 {
		return []har.NVP{}
	}
	out := []har.NVP{}
	for _, pair := range strings.Split(target[i+1:], "&") {
		if pair == "" {
			continue
		}
		name, value, _ := strings.Cut(pair, "=")
		out = append(out, har.NVP{Name: unescape(name), Value: unescape(value)})
	}
	return out
}

func unescape(s string) string {
	// Query components use '+' for space; url.QueryUnescape handles that.
	if u, err := url.QueryUnescape(s); err == nil {
		return u
	}
	return s
}

// bodyText renders body for a HAR text field. Valid UTF-8 is stored as-is; other
// bytes are base64-encoded and flagged, so no observation is altered or lost.
func bodyText(body []byte) (text, encoding string) {
	if len(body) == 0 {
		return "", ""
	}
	if utf8.Valid(body) {
		return string(body), ""
	}
	return base64.StdEncoding.EncodeToString(body), "base64"
}

func headerValue(headers []capture.Header, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// requestCookies parses the Cookie header into ordered name/value cookies.
func requestCookies(headers []capture.Header) []har.Cookie {
	out := []har.Cookie{}
	header := http.Header{}
	for _, h := range headers {
		if strings.EqualFold(h.Name, "Cookie") {
			header.Add("Cookie", h.Value)
		}
	}
	r := http.Request{Header: header}
	for _, c := range r.Cookies() {
		out = append(out, har.Cookie{Name: c.Name, Value: c.Value})
	}
	return out
}

// responseCookies parses Set-Cookie headers into cookies with their attributes.
func responseCookies(headers []capture.Header) []har.Cookie {
	out := []har.Cookie{}
	header := http.Header{}
	for _, h := range headers {
		if strings.EqualFold(h.Name, "Set-Cookie") {
			header.Add("Set-Cookie", h.Value)
		}
	}
	resp := http.Response{Header: header}
	for _, c := range resp.Cookies() {
		sc := har.Cookie{Name: c.Name, Value: c.Value, Path: c.Path, Domain: c.Domain}
		if !c.Expires.IsZero() {
			sc.Expires = c.Expires.UTC().Format(harTime)
		}
		httpOnly, secure := c.HttpOnly, c.Secure
		sc.HTTPOnly = &httpOnly
		sc.Secure = &secure
		out = append(out, sc)
	}
	return out
}
