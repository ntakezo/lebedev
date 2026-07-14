package store

import (
	"context"
	"encoding/json"
	"io"
)

// Export writes the entries matching q as a single HAR 1.3 document to w. The log
// metadata comes from the queried session (when q.Session is set) or a default
// Lebedev creator otherwise; entries are emitted in insertion order.
func (s *Store) Export(ctx context.Context, q Query, w io.Writer) error {
	q.Ascending = true
	stored, err := s.List(ctx, q)
	if err != nil {
		return err
	}
	log, err := s.exportLog(ctx, q.Session)
	if err != nil {
		return err
	}
	log.Entries = make([]Entry, len(stored))
	for i, st := range stored {
		log.Entries[i] = st.Entry
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(HAR{Log: log})
}

func (s *Store) exportLog(ctx context.Context, session string) (Log, error) {
	if session != "" {
		log, err := s.GetLog(ctx, session)
		if err != nil {
			return Log{}, err
		}
		if log.Creator.Name != "" {
			return log, nil
		}
		log.Creator = defaultCreator()
		return log, nil
	}
	return Log{Version: "1.3", Creator: defaultCreator()}, nil
}

func defaultCreator() Creator { return Creator{Name: "lebedev", Version: "1.3"} }

// Import reads a HAR 1.3 document from r and stores every entry under session,
// upserting the log-level metadata. It returns the number of entries stored; on
// the first insert error it returns the count stored so far and that error.
func (s *Store) Import(ctx context.Context, session string, r io.Reader) (int, error) {
	var h HAR
	if err := json.NewDecoder(r).Decode(&h); err != nil {
		return 0, err
	}
	if err := s.PutLog(ctx, session, h.Log); err != nil {
		return 0, err
	}
	for i, e := range h.Log.Entries {
		if _, err := s.Insert(ctx, session, e, int64(i)); err != nil {
			return i, err
		}
	}
	return len(h.Log.Entries), nil
}
