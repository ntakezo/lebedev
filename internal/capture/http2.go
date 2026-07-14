package capture

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const clientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// maxFrameSize bounds outbound DATA frames; the client's advertised max may be
// larger, but 16 KiB is the h2 default and always safe.
const maxFrameSize = 16384

// Setting is one h2 SETTINGS entry, kept in wire order for fingerprinting.
type Setting struct {
	ID    uint16
	Value uint32
}

// Priority is one h2 PRIORITY frame's parameters.
type Priority struct {
	StreamID  uint32
	StreamDep uint32
	Weight    uint8
	Exclusive bool
}

// HTTP2Fingerprint records the connection-level h2 traits needed to rebuild the
// client upstream: SETTINGS in order, the summed connection-level WINDOW_UPDATE,
// any PRIORITY frames, and the pseudo-header/header order of the first request.
type HTTP2Fingerprint struct {
	settings       []Setting
	connectionFlow uint32
	priorities     []Priority
	pseudoOrder    []string
	headerOrder    []string
}

// Settings returns a copy of the SETTINGS entries in wire order.
func (f HTTP2Fingerprint) Settings() []Setting {
	out := make([]Setting, len(f.settings))
	copy(out, f.settings)
	return out
}

func (f HTTP2Fingerprint) ConnectionFlow() uint32 { return f.connectionFlow }

// Priorities returns a copy of the captured PRIORITY frames.
func (f HTTP2Fingerprint) Priorities() []Priority {
	out := make([]Priority, len(f.priorities))
	copy(out, f.priorities)
	return out
}

// PseudoOrder returns a copy of the first request's pseudo-header order.
func (f HTTP2Fingerprint) PseudoOrder() []string { return copyStrings(f.pseudoOrder) }

// HeaderOrder returns a copy of the first request's regular header order.
func (f HTTP2Fingerprint) HeaderOrder() []string { return copyStrings(f.headerOrder) }

func copyStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

// clone returns a deep copy of the fingerprint so a handler goroutine can read
// it while the connection's read loop keeps appending connection-level frames
// (SETTINGS/WINDOW_UPDATE/PRIORITY) to the live fingerprint without a data race.
func (f HTTP2Fingerprint) clone() HTTP2Fingerprint {
	return HTTP2Fingerprint{
		settings:       f.Settings(),
		connectionFlow: f.connectionFlow,
		priorities:     f.Priorities(),
		pseudoOrder:    copyStrings(f.pseudoOrder),
		headerOrder:    copyStrings(f.headerOrder),
	}
}

// H2Handler turns a captured request into the response to send back, and is
// given a snapshot of the connection fingerprint (complete by the first
// request, since SETTINGS/WINDOW_UPDATE/PRIORITY precede the first HEADERS).
type H2Handler func(Request, HTTP2Fingerprint) (Response, error)

type h2stream struct {
	id          uint32
	method      string
	path        string
	scheme      string
	authority   string
	headers     []Header
	pseudoOrder []string
	body        []byte
}

func (s h2stream) request() Request {
	return Request{
		method:      s.method,
		target:      s.path,
		proto:       "HTTP/2.0",
		scheme:      s.scheme,
		authority:   s.authority,
		headers:     s.headers,
		pseudoOrder: s.pseudoOrder,
		body:        s.body,
	}
}

// h2conn owns the write side of one HTTP/2 connection. Because completed
// streams are handled concurrently (so the origin sees the client's real stream
// concurrency rather than a serialized one-at-a-time rewrite), every frame write
// — control frames from the read loop and response frames from handler
// goroutines — must be serialized through wmu; the shared HPACK encoder is
// connection-global state and is only touched under that same lock.
type h2conn struct {
	wmu    sync.Mutex
	fr     *http2.Framer
	enc    *hpack.Encoder
	encBuf *bytes.Buffer
}

func (c *h2conn) settingsAck() {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.fr.WriteSettingsAck()
}

func (c *h2conn) windowUpdate(streamID, n uint32) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.fr.WriteWindowUpdate(streamID, n)
}

func (c *h2conn) pingAck(data [8]byte) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.fr.WritePing(true, data)
}

func (c *h2conn) rstStream(streamID uint32, code http2.ErrCode) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.fr.WriteRSTStream(streamID, code)
}

// ServeHTTP2 reads an HTTP/2 client connection at the frame level, capturing
// each request with header order preserved and recording the connection
// fingerprint, invoking handle for every completed stream. Streams are handled
// concurrently, each in its own goroutine, so requests reach handle in parallel
// exactly as the client multiplexed them — a serialized rewrite would make the
// origin see one stream at a time, which no real browser does. Only the request
// (read) path is fidelity-preserving; responses are written plainly.
func ServeHTTP2(conn net.Conn, handle H2Handler) error {
	if err := readPreface(conn); err != nil {
		return err
	}

	c := &h2conn{fr: http2.NewFramer(conn, conn)}
	c.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	c.encBuf = &bytes.Buffer{}
	c.enc = hpack.NewEncoder(c.encBuf)
	if err := c.fr.WriteSettings(); err != nil {
		return err
	}

	var fp HTTP2Fingerprint
	streams := map[uint32]*h2stream{}
	var wg sync.WaitGroup

	// stop drains in-flight handler goroutines before returning so no goroutine
	// writes to the framer (or the connection) after ServeHTTP2's caller closes it.
	stop := func(err error) error {
		wg.Wait()
		return err
	}

	for {
		frame, err := c.fr.ReadFrame()
		if err != nil {
			if err == io.EOF {
				return stop(nil)
			}
			return stop(err)
		}

		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if f.IsAck() {
				continue
			}
			f.ForeachSetting(func(s http2.Setting) error {
				fp.settings = append(fp.settings, Setting{ID: uint16(s.ID), Value: s.Val})
				return nil
			})
			c.settingsAck()

		case *http2.WindowUpdateFrame:
			if f.StreamID == 0 {
				fp.connectionFlow += f.Increment
			}

		case *http2.PriorityFrame:
			fp.priorities = append(fp.priorities, Priority{
				StreamID:  f.StreamID,
				StreamDep: f.PriorityParam.StreamDep,
				Weight:    f.PriorityParam.Weight,
				Exclusive: f.PriorityParam.Exclusive,
			})

		case *http2.MetaHeadersFrame:
			st := &h2stream{id: f.StreamID}
			captureHeaders(st, f, &fp)
			streams[f.StreamID] = st
			if f.StreamEnded() {
				dispatch(c, streams, st, fp, handle, &wg)
			}

		case *http2.DataFrame:
			st := streams[f.StreamID]
			if st == nil {
				continue
			}
			st.body = append(st.body, f.Data()...)
			if n := uint32(len(f.Data())); n > 0 {
				c.windowUpdate(0, n)
				c.windowUpdate(f.StreamID, n)
			}
			if f.StreamEnded() {
				dispatch(c, streams, st, fp, handle, &wg)
			}

		case *http2.PingFrame:
			if !f.IsAck() {
				c.pingAck(f.Data)
			}

		case *http2.RSTStreamFrame:
			delete(streams, f.StreamID)

		case *http2.GoAwayFrame:
			return stop(nil)
		}
	}
}

// dispatch hands a completed stream off to its own goroutine: it snapshots the
// connection fingerprint (so the read loop may keep mutating the live one),
// removes the stream from the read loop's map (transferring ownership to the
// goroutine), and runs the handler plus response write off the read path so
// slow upstream round trips never block reading the next client frame.
func dispatch(c *h2conn, streams map[uint32]*h2stream, st *h2stream, fp HTTP2Fingerprint, handle H2Handler, wg *sync.WaitGroup) {
	delete(streams, st.id)
	req := st.request()
	snapshot := fp.clone()
	streamID := st.id

	wg.Go(func() {
		resp, err := handle(req, snapshot)
		if err != nil {
			c.rstStream(streamID, http2.ErrCodeInternal)
			return
		}
		c.writeResponse(streamID, resp)
	})
}

func readPreface(conn net.Conn) error {
	buf := make([]byte, len(clientPreface))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if string(buf) != clientPreface {
		return fmt.Errorf("capture: bad http2 preface %q", buf)
	}
	return nil
}

// captureHeaders splits an ordered header block into pseudo-headers (feeding the
// request line) and regular headers, preserving order in both, and records the
// first request's order into the connection fingerprint.
func captureHeaders(st *h2stream, f *http2.MetaHeadersFrame, fp *HTTP2Fingerprint) {
	for _, hf := range f.Fields {
		if strings.HasPrefix(hf.Name, ":") {
			st.pseudoOrder = append(st.pseudoOrder, hf.Name)
			switch hf.Name {
			case ":method":
				st.method = hf.Value
			case ":path":
				st.path = hf.Value
			case ":scheme":
				st.scheme = hf.Value
			case ":authority":
				st.authority = hf.Value
			}
			continue
		}
		st.headers = append(st.headers, Header{Name: hf.Name, Value: hf.Value})
	}
	if fp.pseudoOrder == nil {
		fp.pseudoOrder = append([]string(nil), st.pseudoOrder...)
	}
	if fp.headerOrder == nil {
		for _, h := range st.headers {
			fp.headerOrder = append(fp.headerOrder, h.Name)
		}
	}
}

// writeResponse encodes and writes one stream's response. It holds the write
// lock for the whole message so the shared HPACK encoder stays consistent and a
// response's HEADERS and DATA frames are never interleaved with another stream's.
func (c *h2conn) writeResponse(streamID uint32, resp Response) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	c.encBuf.Reset()
	c.enc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(resp.Status)})
	for _, h := range resp.Headers {
		c.enc.WriteField(hpack.HeaderField{Name: strings.ToLower(h.Name), Value: h.Value})
	}

	endStream := len(resp.Body) == 0
	if err := c.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: c.encBuf.Bytes(),
		EndStream:     endStream,
		EndHeaders:    true,
	}); err != nil {
		return err
	}
	if endStream {
		return nil
	}
	return writeData(c.fr, streamID, resp.Body)
}

// writeData sends the body in max-frame-sized chunks, ending the stream on the
// final frame. It does not yet account for the client's flow-control window.
func writeData(fr *http2.Framer, streamID uint32, body []byte) error {
	for len(body) > maxFrameSize {
		if err := fr.WriteData(streamID, false, body[:maxFrameSize]); err != nil {
			return err
		}
		body = body[maxFrameSize:]
	}
	return fr.WriteData(streamID, true, body)
}
