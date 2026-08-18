package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/ntakezo/lebedev/har"
	"github.com/ntakezo/lebedev/model"
	"github.com/ntakezo/lebedev/repository"
	"github.com/ntakezo/lebedev/repository/sqlite"
)

// defaultCreator names lebedev in the log header of a session that carries none.
func defaultCreator() har.Creator { return har.Creator{Name: "lebedev", Version: "1.3"} }

// exportHAR writes a session as a HAR 1.3 document. Entries are fetched and
// encoded one at a time rather than collected first, so exporting a capture with
// large bodies costs one entry of memory instead of the whole session.
func exportHAR(ctx context.Context, repo *sqlite.Repository, id string, w io.Writer) error {
	d, err := repo.Session(ctx, id)
	if err != nil {
		return err
	}
	log := d.Log
	if log.Creator.Name == "" {
		log.Creator = defaultCreator()
	}
	if log.Version == "" {
		log.Version = "1.3"
	}

	// The log header is encoded whole and reopened, so the entries array can be
	// streamed into it instead of being built in memory first.
	header, err := json.MarshalIndent(logHeader{
		Version: log.Version,
		Creator: log.Creator,
		Browser: log.Browser,
		Pages:   log.Pages,
		Comment: log.Comment,
	}, "  ", "  ")
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "{\n  \"log\": %s,\n    \"entries\": [", header[:len(header)-1]); err != nil {
		return err
	}

	for i, summary := range d.Entries {
		st, err := repo.Entry(ctx, summary.ID)
		if err != nil {
			return err
		}
		b, err := json.MarshalIndent(st.Entry, "      ", "  ")
		if err != nil {
			return err
		}
		sep := "\n      "
		if i > 0 {
			sep = ",\n      "
		}
		if _, err := io.WriteString(w, sep+string(b)); err != nil {
			return err
		}
	}
	_, err = io.WriteString(w, "\n    ]\n  }\n}\n")
	return err
}

// logHeader is the HAR log without its entries, so the array can be streamed in
// separately.
type logHeader struct {
	Version string       `json:"version"`
	Creator har.Creator  `json:"creator"`
	Browser *har.Browser `json:"browser,omitempty"`
	Pages   []har.Page   `json:"pages,omitempty"`
	Comment string       `json:"comment,omitempty"`
}

// importHAR reads a HAR 1.3 document into a new session and returns how many
// entries it stored. Entries are streamed, and the _lebedev block each one
// repeats is collapsed back into one connection record per distinct fingerprint —
// the shape the document was flattened from.
func importHAR(ctx context.Context, repo *sqlite.Repository, id string, r io.Reader) (int, error) {
	dec := json.NewDecoder(r)
	log, err := seekEntries(dec)
	if err != nil {
		return 0, err
	}
	if _, err := repo.CreateSession(ctx, repository.Session{Name: id, Log: log}); err != nil {
		return 0, err
	}

	connections := map[string]int64{}
	stored := 0
	for dec.More() {
		var e model.Entry
		if err := dec.Decode(&e); err != nil {
			return stored, err
		}
		conn, err := connectionFor(ctx, repo, id, connections, e.Lebedev)
		if err != nil {
			return stored, err
		}
		if _, err := repo.CreateEntry(ctx, id, conn, e); err != nil {
			return stored, err
		}
		stored++
	}
	return stored, nil
}

// seekEntries decodes the log header and leaves dec positioned at the first
// element of log.entries.
func seekEntries(dec *json.Decoder) (model.Log, error) {
	var log model.Log
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return log, fmt.Errorf("import: no log.entries array found: %w", err)
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
			if depth != 2 {
				continue
			}
			// Header members are decoded as they are met; entries opens the array.
			switch v {
			case "entries":
				if _, err := dec.Token(); err != nil {
					return log, err
				}
				return log, nil
			case "version":
				err = dec.Decode(&log.Version)
			case "creator":
				err = dec.Decode(&log.Creator)
			case "browser":
				err = dec.Decode(&log.Browser)
			case "pages":
				err = dec.Decode(&log.Pages)
			case "comment":
				err = dec.Decode(&log.Comment)
			}
			if err != nil {
				return log, err
			}
		}
	}
}

// connectionFor stores an entry's _lebedev block as a connection the first time
// that fingerprint is seen and reuses the row afterwards.
func connectionFor(ctx context.Context, repo *sqlite.Repository, session string, seen map[string]int64, lb *model.Lebedev) (int64, error) {
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
	id, err := repo.CreateConnection(ctx, session, model.Connection{
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

// copySession copies a whole session from src into dst, preserving which entries
// shared a connection: each source connection becomes one destination connection,
// and the entries that referenced it reference the copy.
func copySession(ctx context.Context, dst, src *sqlite.Repository, id string) (int, error) {
	d, err := src.Session(ctx, id)
	if err != nil {
		return 0, err
	}
	if _, err := dst.CreateSession(ctx, repository.Session{Name: id, Log: d.Log}); err != nil {
		return 0, err
	}

	conns := make(map[int64]int64, len(d.Connections))
	for _, c := range d.Connections {
		copied, err := dst.CreateConnection(ctx, id, c)
		if err != nil {
			return 0, err
		}
		conns[c.ID] = copied
	}

	copied := 0
	for _, summary := range d.Entries {
		st, err := src.Entry(ctx, summary.ID)
		if err != nil {
			return copied, err
		}
		if _, err := dst.CreateEntry(ctx, id, conns[st.Connection], st.Entry); err != nil {
			return copied, err
		}
		copied++
	}
	return copied, nil
}
