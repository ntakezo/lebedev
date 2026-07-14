package upstream

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// This file implements canonical JA3 and JA4 TLS ClientHello fingerprints from
// raw wire bytes, for the validation test in fingerprint_validation_test.go. It
// is test-only: the proxy never computes these itself, so nothing here belongs
// in the package's public API.

// clientHello holds the fields of a parsed ClientHello that feed JA3 and JA4.
// Values are kept in wire order; GREASE is removed at fingerprint time, not here,
// so the raw parse stays faithful.
type clientHello struct {
	legacyVersion uint16
	cipherSuites  []uint16
	extensions    []uint16 // extension types, in wire order
	curves        []uint16 // supported_groups (0x000a)
	pointFormats  []uint8  // ec_point_formats (0x000b)
	supportedVers []uint16 // supported_versions (0x002b)
	sigAlgs       []uint16 // signature_algorithms (0x000d), in wire order
	alpn          []string // application_layer_protocol_negotiation (0x0010)
	hasSNI        bool     // server_name (0x0000) present
}

// isGREASE reports whether v is one of the 16 reserved GREASE values
// (0x0a0a, 0x1a1a, ... 0xfafa): both bytes equal with low nibble 0x0a. GREASE is
// randomized per connection, so it must be stripped before fingerprinting or two
// hellos from the same client would never match.
func isGREASE(v uint16) bool {
	hi, lo := byte(v>>8), byte(v)
	return hi == lo && lo&0x0f == 0x0a
}

// parseClientHello parses a ClientHello from either a full TLS record
// (0x16 handshake record + body) or a bare handshake message. It reads only the
// fields the fingerprints need and tolerates trailing bytes.
func parseClientHello(b []byte) (clientHello, error) {
	var h clientHello
	// Strip the TLS record header if present: content type 0x16, version 0x03xx.
	if len(b) >= 5 && b[0] == 0x16 && b[1] == 0x03 {
		recLen := int(binary.BigEndian.Uint16(b[3:5]))
		if 5+recLen > len(b) {
			return h, fmt.Errorf("fingerprint: record length %d exceeds %d bytes", recLen, len(b)-5)
		}
		b = b[5 : 5+recLen]
	}
	// Handshake header: type 0x01 (ClientHello) + 3-byte length.
	if len(b) < 4 || b[0] != 0x01 {
		return h, fmt.Errorf("fingerprint: not a ClientHello handshake (type=%#x)", firstByte(b))
	}
	msgLen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	b = b[4:]
	if len(b) < msgLen {
		return h, fmt.Errorf("fingerprint: handshake length %d exceeds %d bytes", msgLen, len(b))
	}
	b = b[:msgLen]

	r := reader{b: b}
	if _, ok := r.u16(&h.legacyVersion); !ok {
		return h, errTruncated("legacy_version")
	}
	if !r.skip(32) { // random
		return h, errTruncated("random")
	}
	if !r.skipVec(1) { // session_id
		return h, errTruncated("session_id")
	}

	cs, ok := r.vec(2)
	if !ok {
		return h, errTruncated("cipher_suites")
	}
	for i := 0; i+1 < len(cs); i += 2 {
		h.cipherSuites = append(h.cipherSuites, binary.BigEndian.Uint16(cs[i:]))
	}
	if !r.skipVec(1) { // compression_methods
		return h, errTruncated("compression_methods")
	}

	extAll, ok := r.vec(2)
	if !ok {
		// Extensions are optional on the wire; a hello without them is still valid.
		return h, nil
	}
	if err := h.parseExtensions(extAll); err != nil {
		return h, err
	}
	return h, nil
}

// parseExtensions walks the extension block, recording every extension type and
// decoding the handful whose contents feed JA3/JA4.
func (h *clientHello) parseExtensions(b []byte) error {
	r := reader{b: b}
	for r.remaining() > 0 {
		var extType, extLen uint16
		if _, ok := r.u16(&extType); !ok {
			return errTruncated("extension type")
		}
		if _, ok := r.u16(&extLen); !ok {
			return errTruncated("extension length")
		}
		data, ok := r.take(int(extLen))
		if !ok {
			return errTruncated("extension body")
		}
		h.extensions = append(h.extensions, extType)
		switch extType {
		case 0x0000: // server_name
			h.hasSNI = true
		case 0x000a: // supported_groups
			h.curves = readU16Vec(data, 2)
		case 0x000b: // ec_point_formats
			if len(data) > 0 {
				n := int(data[0])
				if 1+n <= len(data) {
					h.pointFormats = append(h.pointFormats, data[1:1+n]...)
				}
			}
		case 0x000d: // signature_algorithms
			h.sigAlgs = readU16Vec(data, 2)
		case 0x0010: // ALPN
			h.alpn = readALPN(data)
		case 0x002b: // supported_versions
			h.supportedVers = readU16Vec(data, 1)
		}
	}
	return nil
}

// ja3 returns the canonical JA3 string and its md5 hash. The string is
// Version,Ciphers,Extensions,Curves,PointFormats with dash-separated decimal
// values and GREASE removed from ciphers, extensions, and curves.
func ja3(h clientHello) (string, string) {
	s := strings.Join([]string{
		strconv.Itoa(int(h.legacyVersion)),
		joinU16(filterGREASE(h.cipherSuites), "-"),
		joinU16(filterGREASE(h.extensions), "-"),
		joinU16(filterGREASE(h.curves), "-"),
		joinU8(h.pointFormats, "-"),
	}, ",")
	sum := md5.Sum([]byte(s))
	return s, hex.EncodeToString(sum[:])
}

// ja4 returns the canonical JA4 fingerprint a_b_c for TLS-over-TCP. See
// https://github.com/FoxIO-LLC/ja4 for the format.
func ja4(h clientHello) string {
	ciphers := filterGREASE(h.cipherSuites)
	// JA4 counts and hashes every extension except GREASE, but SNI and ALPN are
	// excluded from the JA4_c hash (they are already summarized in JA4_a).
	extsAll := filterGREASE(h.extensions)
	extsForHash := make([]uint16, 0, len(extsAll))
	for _, e := range extsAll {
		if e == 0x0000 || e == 0x0010 {
			continue
		}
		extsForHash = append(extsForHash, e)
	}

	a := "t" + ja4Version(h) + sniFlag(h.hasSNI) +
		count2(len(ciphers)) + count2(len(extsAll)) + alpnChars(h.alpn)

	sortedCiphers := append([]uint16(nil), ciphers...)
	slices.Sort(sortedCiphers)
	b := hash12(hexJoinU16(sortedCiphers))

	sortedExts := append([]uint16(nil), extsForHash...)
	slices.Sort(sortedExts)
	cInput := hexJoinU16(sortedExts)
	if sig := filterGREASE(h.sigAlgs); len(sig) > 0 {
		// Signature algorithms are appended in wire order, not sorted.
		cInput += "_" + hexJoinU16(sig)
	}
	c := hash12(cInput)

	return a + "_" + b + "_" + c
}

func ja4Version(h clientHello) string {
	best := h.legacyVersion
	for _, v := range h.supportedVers {
		if isGREASE(v) {
			continue
		}
		if v > best {
			best = v
		}
	}
	switch best {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	default:
		return "00"
	}
}

func sniFlag(has bool) string {
	if has {
		return "d"
	}
	return "i"
}

func alpnChars(alpn []string) string {
	if len(alpn) == 0 || alpn[0] == "" {
		return "00"
	}
	p := alpn[0]
	return string(p[0]) + string(p[len(p)-1])
}

func count2(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

func hash12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// --- small helpers ---

func filterGREASE(vs []uint16) []uint16 {
	out := make([]uint16, 0, len(vs))
	for _, v := range vs {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func joinU16(vs []uint16, sep string) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, sep)
}

func joinU8(vs []uint8, sep string) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, sep)
}

func hexJoinU16(vs []uint16) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func readU16Vec(b []byte, lenBytes int) []uint16 {
	body, ok := (&reader{b: b}).vec(lenBytes)
	if !ok {
		return nil
	}
	out := make([]uint16, 0, len(body)/2)
	for i := 0; i+1 < len(body); i += 2 {
		out = append(out, binary.BigEndian.Uint16(body[i:]))
	}
	return out
}

func readALPN(b []byte) []string {
	body, ok := (&reader{b: b}).vec(2)
	if !ok {
		return nil
	}
	var out []string
	for i := 0; i < len(body); {
		n := int(body[i])
		i++
		if i+n > len(body) {
			break
		}
		out = append(out, string(body[i:i+n]))
		i += n
	}
	return out
}

func firstByte(b []byte) byte {
	if len(b) == 0 {
		return 0
	}
	return b[0]
}

func errTruncated(field string) error {
	return fmt.Errorf("fingerprint: truncated ClientHello at %s", field)
}

// reader is a minimal big-endian byte-vector reader over a ClientHello.
type reader struct{ b []byte }

func (r *reader) remaining() int { return len(r.b) }

func (r *reader) take(n int) ([]byte, bool) {
	if n < 0 || n > len(r.b) {
		return nil, false
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out, true
}

func (r *reader) skip(n int) bool {
	_, ok := r.take(n)
	return ok
}

func (r *reader) u16(dst *uint16) (uint16, bool) {
	v, ok := r.take(2)
	if !ok {
		return 0, false
	}
	*dst = binary.BigEndian.Uint16(v)
	return *dst, true
}

// vec reads a length-prefixed vector whose length field is lenBytes wide (1 or 2)
// and returns its body.
func (r *reader) vec(lenBytes int) ([]byte, bool) {
	var n int
	switch lenBytes {
	case 1:
		v, ok := r.take(1)
		if !ok {
			return nil, false
		}
		n = int(v[0])
	case 2:
		v, ok := r.take(2)
		if !ok {
			return nil, false
		}
		n = int(binary.BigEndian.Uint16(v))
	default:
		return nil, false
	}
	return r.take(n)
}

func (r *reader) skipVec(lenBytes int) bool {
	_, ok := r.vec(lenBytes)
	return ok
}
