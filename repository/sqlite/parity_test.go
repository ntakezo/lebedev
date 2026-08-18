package sqlite

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/ntakezo/lebedev/model"
)

// TestParityWithCapturedHAR replays a real capture through the repository and
// checks that every entry comes back byte-identical to the one that went in —
// the guarantee the whole layout exists to keep. It is skipped unless
// LEBEDEV_PARITY_HAR names a HAR 1.3 document to replay:
//
//	LEBEDEV_PARITY_HAR=capture.har go test ./repository/sqlite/
//
// The document is streamed rather than loaded whole, so a multi-gigabyte capture
// costs one entry of memory at a time.
func TestParityWithCapturedHAR(t *testing.T) {
	path := os.Getenv("LEBEDEV_PARITY_HAR")
	if path == "" {
		t.Skip("set LEBEDEV_PARITY_HAR to a HAR file to run the parity check")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ctx := context.Background()
	r := open(t)

	// connections dedupes by fingerprint: a HAR repeats the _lebedev block on every
	// entry, while the store keeps one row per distinct connection.
	connections := map[string]int64{}
	dec := json.NewDecoder(f)
	entries := seekEntries(t, dec)

	session := ""
	checked := 0
	for dec.More() {
		var want model.Entry
		if err := dec.Decode(&want); err != nil {
			t.Fatalf("entry %d: %v", checked, err)
		}
		if checked == 0 {
			// Replay under the capture's own name, so the session the _lebedev field
			// reports is the one the entries were recorded under and the comparison
			// stays byte-for-byte with nothing normalized away.
			session = sessionName(want.Lebedev)
			seed(t, r, session)
		}
		conn, err := connectionFor(ctx, r, session, connections, want.Lebedev)
		if err != nil {
			t.Fatalf("entry %d: %v", checked, err)
		}
		id, err := r.CreateEntry(ctx, session, conn, want)
		if err != nil {
			t.Fatalf("entry %d: %v", checked, err)
		}
		got, err := r.Entry(ctx, id)
		if err != nil {
			t.Fatalf("entry %d: %v", checked, err)
		}
		if got.Session != session {
			t.Fatalf("entry %d: session = %q, want %q", checked, got.Session, session)
		}
		compareJSON(t, checked, want, got.Entry)
		checked++
	}
	if !entries || checked == 0 {
		t.Fatalf("no entries found in %s", path)
	}
	t.Logf("replayed %d captured entries over %d connections into session %q", checked, len(connections), session)
}

// sessionName reports the session a captured entry was recorded under, falling
// back to a fixed name for a HAR that carries no lebedev extension.
func sessionName(lb *model.Lebedev) string {
	if lb == nil || lb.Session == "" {
		return "parity"
	}
	return lb.Session
}

// seekEntries advances dec to the first element of log.entries, reporting
// whether it found the array.
func seekEntries(t *testing.T, dec *json.Decoder) bool {
	t.Helper()
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		case string:
			if v == "entries" && depth == 2 {
				// Consume the opening '[' so the caller decodes elements directly.
				if _, err := dec.Token(); err != nil {
					return false
				}
				return true
			}
		}
	}
}

// connectionFor stores an entry's _lebedev block as a connection the first time
// that exact fingerprint is seen and reuses the row afterwards, which is how a
// capture's repeated fingerprint collapses to one row per connection.
func connectionFor(ctx context.Context, r *Repository, session string, seen map[string]int64, lb *model.Lebedev) (int64, error) {
	if lb == nil {
		return 0, nil
	}
	key, err := json.Marshal(lb)
	if err != nil {
		return 0, err
	}
	if id, ok := seen[string(key)]; ok {
		return id, nil
	}
	id, err := r.CreateConnection(ctx, session, model.Connection{
		ClientHelloHex: lb.ClientHelloHex,
		UpstreamProto:  lb.UpstreamProto,
		HTTP2:          lb.HTTP2,
	})
	if err != nil {
		return 0, err
	}
	seen[string(key)] = id
	return id, nil
}

// compareJSON compares the entry as it would be exported, which is the level the
// faithfulness contract is stated at: identical JSON means identical headers,
// order, whitespace, and bodies.
func compareJSON(t *testing.T, i int, want, got model.Entry) {
	t.Helper()
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(wantJSON) == string(gotJSON) {
		return
	}
	at, stored, read := firstDifference(wantJSON, gotJSON)
	t.Errorf("entry %d (%s %s) diverged at byte %d:\n stored %s\n   read %s",
		i, want.Request.Method, want.Request.URL, at, stored, read)
}

// firstDifference locates where two encodings diverge and returns a window of
// each around that point, so a mismatch deep inside a large entry is readable.
func firstDifference(a, b []byte) (int, string, string) {
	n := min(len(a), len(b))
	at := n
	for i := range n {
		if a[i] != b[i] {
			at = i
			break
		}
	}
	return at, window(a, at), window(b, at)
}

func window(b []byte, at int) string {
	const before, after = 80, 120
	lo := max(at-before, 0)
	hi := min(at+after, len(b))
	return string(b[lo:hi])
}
