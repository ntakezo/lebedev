// Package store persists captured transactions in SQL (SQLite in-memory by
// default, on-disk SQLite, or PostgreSQL) and marshals them to and from the
// HTTP Archive (HAR) 1.3 format for import and export. The Go types in this file
// mirror the HAR 1.3 object model; their JSON tags define the on-the-wire format.
// Lebedev-specific data that HAR has no home for (the raw TLS ClientHello and the
// HTTP/2 fingerprint) rides along in the custom, underscore-prefixed "_lebedev"
// field permitted by the HAR custom-field rules.
package store

// HAR is the root of a HAR document: a single log wrapper.
type HAR struct {
	Log Log `json:"log"`
}

// Log is the exported data root — creator/browser metadata plus the entries.
type Log struct {
	Version string   `json:"version"`
	Creator Creator  `json:"creator"`
	Browser *Browser `json:"browser,omitempty"`
	Pages   []Page   `json:"pages,omitempty"`
	Entries []Entry  `json:"entries"`
	Comment string   `json:"comment,omitempty"`
}

// Creator names the application that produced the log.
type Creator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Comment string `json:"comment,omitempty"`
}

// Browser names the browser the log was captured from.
type Browser struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Comment string `json:"comment,omitempty"`
}

// Page is one tracked page load that entries may reference via Pageref.
type Page struct {
	StartedDateTime string      `json:"startedDateTime"`
	ID              string      `json:"id"`
	Title           string      `json:"title"`
	PageTimings     PageTimings `json:"pageTimings"`
	Comment         string      `json:"comment,omitempty"`
}

// PageTimings holds page-load event offsets in milliseconds; -1 means N/A.
type PageTimings struct {
	OnContentLoad *float64 `json:"onContentLoad,omitempty"`
	OnLoad        *float64 `json:"onLoad,omitempty"`
	Comment       string   `json:"comment,omitempty"`
}

// Entry is one HTTP request/response round trip. Lebedev carries the TLS and
// HTTP/2 fingerprint in the custom _lebedev field.
type Entry struct {
	Pageref         string   `json:"pageref,omitempty"`
	StartedDateTime string   `json:"startedDateTime"`
	Time            float64  `json:"time"`
	Request         Request  `json:"request"`
	Response        Response `json:"response"`
	Cache           Cache    `json:"cache"`
	Timings         Timings  `json:"timings"`
	ServerIPAddress string   `json:"serverIPAddress,omitempty"`
	Connection      string   `json:"connection,omitempty"`
	Comment         string   `json:"comment,omitempty"`
	Lebedev         *Lebedev `json:"_lebedev,omitempty"`
}

// Request is the performed request. HeadersSize/BodySize default to -1 (unknown).
type Request struct {
	Method             string    `json:"method"`
	URL                string    `json:"url"`
	HTTPVersion        string    `json:"httpVersion"`
	Cookies            []Cookie  `json:"cookies"`
	Headers            []NVP     `json:"headers"`
	QueryString        []NVP     `json:"queryString"`
	PostData           *PostData `json:"postData,omitempty"`
	HeadersSize        int       `json:"headersSize"`
	HeadersCompression *int      `json:"headersCompression,omitempty"`
	BodySize           int       `json:"bodySize"`
	Comment            string    `json:"comment,omitempty"`
}

// Response is the received response, including the decoded content body.
type Response struct {
	Status             int      `json:"status"`
	StatusText         string   `json:"statusText"`
	HTTPVersion        string   `json:"httpVersion"`
	Cookies            []Cookie `json:"cookies"`
	Headers            []NVP    `json:"headers"`
	Content            Content  `json:"content"`
	RedirectURL        string   `json:"redirectURL"`
	HeadersSize        int      `json:"headersSize"`
	HeadersCompression *int     `json:"headersCompression,omitempty"`
	BodySize           int      `json:"bodySize"`
	Comment            string   `json:"comment,omitempty"`
}

// NVP is a name/value pair used for headers and query-string parameters.
type NVP struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Comment string `json:"comment,omitempty"`
}

// Cookie is a parsed request or response cookie. HTTPOnly/Secure are pointers so
// an unknown flag stays absent rather than defaulting to false.
type Cookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Expires  string `json:"expires,omitempty"`
	HTTPOnly *bool  `json:"httpOnly,omitempty"`
	Secure   *bool  `json:"secure,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

// PostData describes the request body. Text and Params are mutually exclusive;
// Encoding (new in 1.3) names a Text transfer encoding such as "base64".
type PostData struct {
	MimeType string  `json:"mimeType"`
	Params   []Param `json:"params,omitempty"`
	Text     string  `json:"text,omitempty"`
	Encoding string  `json:"encoding,omitempty"`
	Comment  string  `json:"comment,omitempty"`
}

// Param is one posted parameter or file part of a request body.
type Param struct {
	Name        string `json:"name"`
	Value       string `json:"value,omitempty"`
	FileName    string `json:"fileName,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	Encoding    string `json:"encoding,omitempty"`
	Comment     string `json:"comment,omitempty"`
}

// Content is the response body. Encoding (e.g. "base64") is set when Text is not
// stored as decoded UTF-8 — Lebedev uses it to carry binary or compressed bytes.
type Content struct {
	Size        int    `json:"size"`
	Compression *int   `json:"compression,omitempty"`
	MimeType    string `json:"mimeType"`
	Text        string `json:"text,omitempty"`
	Encoding    string `json:"encoding,omitempty"`
	Comment     string `json:"comment,omitempty"`
}

// Cache holds the cache-entry state before and after the request. A nil pointer
// means the state was not provided.
type Cache struct {
	BeforeRequest *CacheState `json:"beforeRequest,omitempty"`
	AfterRequest  *CacheState `json:"afterRequest,omitempty"`
	Comment       string      `json:"comment,omitempty"`
}

// CacheState is one cache entry's metadata.
type CacheState struct {
	Expires    string `json:"expires,omitempty"`
	LastAccess string `json:"lastAccess"`
	ETag       string `json:"eTag"`
	HitCount   int    `json:"hitCount"`
	Comment    string `json:"comment,omitempty"`
}

// Timings breaks the round trip into phases (milliseconds). Send/Wait/Receive
// are required and non-negative; the pointer fields are -1 or omitted when N/A.
type Timings struct {
	Blocked *float64 `json:"blocked,omitempty"`
	DNS     *float64 `json:"dns,omitempty"`
	Connect *float64 `json:"connect,omitempty"`
	Send    float64  `json:"send"`
	Wait    float64  `json:"wait"`
	Receive float64  `json:"receive"`
	SSL     *float64 `json:"ssl,omitempty"`
	Comment string   `json:"comment,omitempty"`
}

// Lebedev is the custom _lebedev entry field carrying data outside the HAR model:
// the session id, the raw TLS ClientHello, the upstream protocol actually spoken,
// and the HTTP/2 fingerprint.
type Lebedev struct {
	Session        string `json:"session,omitempty"`
	ClientHelloHex string `json:"clientHelloHex,omitempty"`
	UpstreamProto  string `json:"upstreamProto,omitempty"`
	HTTP2          *HTTP2 `json:"http2,omitempty"`
}

// HTTP2 is the mirrored HTTP/2 fingerprint.
type HTTP2 struct {
	Settings       []Setting `json:"settings,omitempty"`
	ConnectionFlow uint32    `json:"connectionFlow,omitempty"`
	PseudoOrder    []string  `json:"pseudoOrder,omitempty"`
	HeaderOrder    []string  `json:"headerOrder,omitempty"`
}

// Setting is one HTTP/2 SETTINGS id/value pair.
type Setting struct {
	ID    uint16 `json:"id"`
	Value uint32 `json:"value"`
}
