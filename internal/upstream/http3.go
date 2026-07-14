package upstream

import (
	"strings"

	http "github.com/bogdanfinn/fhttp"
)

// browserFamily is the browser lineage a captured client belongs to, inferred
// from traits that survive into the h2 fingerprint. It selects which synthesized
// HTTP/3 profile the mirror uses upstream, since a TCP capture carries no QUIC
// transport parameters or h3 SETTINGS to reproduce directly.
type browserFamily int

const (
	familyChrome browserFamily = iota // Chromium-based: Chrome, Edge, Brave, Opera
	familyFirefox
)

// h3Profile is the synthesized HTTP/3 fingerprint applied to a mirrored client:
// the SETTINGS a browser of its family sends on the QUIC control stream (in
// order), its urgency PRIORITY_UPDATE parameter, its h3 pseudo-header order, and
// whether it emits GREASE frames. Values track the corresponding browser profiles
// in tls-client so a mirrored h3 connection fingerprints as that browser would.
type h3Profile struct {
	settings      map[uint64]uint64
	settingsOrder []uint64
	priorityParam uint32
	pseudoOrder   []string
	sendGrease    bool
}

// chromeH3Profile mirrors current Chrome/Chromium HTTP/3 traits: a two-entry
// SETTINGS frame padded in wire order with MAX_FIELD_SECTION_SIZE and H3_DATAGRAM,
// the Chrome urgency default, and Chrome's :method,:authority,:scheme,:path order.
var chromeH3Profile = h3Profile{
	settings: map[uint64]uint64{
		0x1: 65536, // QPACK_MAX_TABLE_CAPACITY
		0x7: 100,   // QPACK_BLOCKED_STREAMS
	},
	settingsOrder: []uint64{0x1, 0x6, 0x7, 0x33},
	priorityParam: 984832,
	pseudoOrder:   []string{":method", ":authority", ":scheme", ":path"},
	sendGrease:    true,
}

// firefoxH3Profile mirrors current Firefox HTTP/3 traits: a richer SETTINGS set
// including Firefox's reserved/GREASE settings, no urgency parameter, and
// Firefox's :method,:scheme,:authority,:path order.
var firefoxH3Profile = h3Profile{
	settings: map[uint64]uint64{
		0x1:       65536, // QPACK_MAX_TABLE_CAPACITY
		0x7:       20,    // QPACK_BLOCKED_STREAMS
		727725890: 0,     // reserved/GREASE
		16765559:  1,     // reserved/GREASE
		0x33:      1,     // H3_DATAGRAM
		0x8:       1,     // ENABLE_CONNECT_PROTOCOL
	},
	settingsOrder: []uint64{0x1, 0x7, 727725890, 16765559, 0x33, 0x8},
	priorityParam: 0,
	pseudoOrder:   []string{":method", ":scheme", ":authority", ":path"},
	sendGrease:    true,
}

// matchFamily infers a captured client's browser family from its h2 pseudo-header
// order, which is stable per browser: Firefox sends :method,:path,:authority,:scheme,
// while Chromium sends :method,:authority,:scheme,:path. Anything else (including an
// empty order) falls back to Chrome, the most common client and the safest default
// for a synthesized h3 fingerprint.
func matchFamily(pseudoOrder []string) browserFamily {
	if len(pseudoOrder) == 4 &&
		pseudoOrder[0] == ":method" &&
		pseudoOrder[1] == ":path" &&
		pseudoOrder[2] == ":authority" &&
		pseudoOrder[3] == ":scheme" {
		return familyFirefox
	}
	return familyChrome
}

// h3ProfileFor returns the synthesized HTTP/3 profile for a browser family.
func h3ProfileFor(f browserFamily) h3Profile {
	if f == familyFirefox {
		return firefoxH3Profile
	}
	return chromeH3Profile
}

// altSvcOffersH3 reports whether an origin response's Alt-Svc header advertises an
// HTTP/3 alternative ("h3" or a draft "h3-NN"), the in-band signal a real browser
// uses to upgrade a subsequent connection to the origin from h2 to h3. A single
// "clear" value (or the absence of any h3 token) reports false, matching a browser
// dropping a previously advertised h3 route. Only call it when the header is
// present; see altSvcPresent.
func altSvcOffersH3(h http.Header) bool {
	for _, v := range h.Values("Alt-Svc") {
		for alt := range strings.SplitSeq(v, ",") {
			id := strings.TrimSpace(alt)
			if i := strings.IndexByte(id, '='); i >= 0 {
				id = id[:i]
			}
			id = strings.Trim(strings.TrimSpace(id), "\"")
			if id == "h3" || strings.HasPrefix(id, "h3-") {
				return true
			}
		}
	}
	return false
}

// altSvcPresent reports whether the response carried any Alt-Svc header, so the
// mirror only overwrites a cached h3 decision when the origin actually spoke to
// it — a response with no Alt-Svc leaves a prior advertisement in force, exactly
// as a browser retains its Alt-Svc cache across responses that omit the header.
func altSvcPresent(h http.Header) bool {
	return len(h.Values("Alt-Svc")) > 0
}
