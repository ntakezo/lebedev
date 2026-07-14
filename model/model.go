// Package model is lebedev's database-specific view of a captured session: the
// strict HAR 1.3 object model (package har) extended with the data HAR has no
// home for. Two things intermingle here that package har deliberately keeps out —
// the capture fingerprint (the raw TLS ClientHello and the HTTP/2 fingerprint,
// carried in the custom "_lebedev" field the HAR spec permits) and the store
// identity (row id and owning session) that a persisted entry gains and a plain
// HAR document lacks. Consumers import this package to read entries as lebedev
// stores them without retyping the schema.
package model

import "github.com/ntakezo/lebedev/har"

// Entry is a HAR entry extended with lebedev's capture fingerprint. Its standard
// fields mirror har.Entry and reuse har's request/response sub-objects verbatim;
// the only addition is the custom _lebedev field, emitted last so an Entry
// marshals as a valid HAR entry with one extra underscore-prefixed object. The
// top-level fields are re-declared rather than embedded so the field names are
// not shadowed by the wrapper and construction stays ergonomic.
type Entry struct {
	Pageref         string       `json:"pageref,omitempty"`
	StartedDateTime string       `json:"startedDateTime"`
	Time            float64      `json:"time"`
	Request         har.Request  `json:"request"`
	Response        har.Response `json:"response"`
	Cache           har.Cache    `json:"cache"`
	Timings         har.Timings  `json:"timings"`
	ServerIPAddress string       `json:"serverIPAddress,omitempty"`
	Connection      string       `json:"connection,omitempty"`
	Comment         string       `json:"comment,omitempty"`
	Lebedev         *Lebedev     `json:"_lebedev,omitempty"`
}

// HAR returns the strict HAR 1.3 entry underlying e, dropping the _lebedev
// extension. It lets a consumer hand a stored entry to code that speaks plain HAR.
func (e Entry) HAR() har.Entry {
	return har.Entry{
		Pageref:         e.Pageref,
		StartedDateTime: e.StartedDateTime,
		Time:            e.Time,
		Request:         e.Request,
		Response:        e.Response,
		Cache:           e.Cache,
		Timings:         e.Timings,
		ServerIPAddress: e.ServerIPAddress,
		Connection:      e.Connection,
		Comment:         e.Comment,
	}
}

// HAR is a lebedev HAR document: the standard wrapper whose entries may carry the
// _lebedev extension. It marshals as a valid HAR 1.3 document to any reader that
// ignores custom underscore-prefixed fields.
type HAR struct {
	Log Log `json:"log"`
}

// Log mirrors har.Log but holds extended Entries. The metadata sub-objects are
// pure HAR and are reused from package har.
type Log struct {
	Version string       `json:"version"`
	Creator har.Creator  `json:"creator"`
	Browser *har.Browser `json:"browser,omitempty"`
	Pages   []har.Page   `json:"pages,omitempty"`
	Entries []Entry      `json:"entries"`
	Comment string       `json:"comment,omitempty"`
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

// Stored is one persisted entry together with the store identity that HAR itself
// does not carry: the row id and the owning session.
type Stored struct {
	ID      int64
	Session string
	Entry   Entry
}
