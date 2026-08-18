// Package repository is lebedev's persistence contract: the small set of
// operations a capture store must support, and the read shapes they return. It
// names behavior, not storage — the SQLite implementation lives in the sibling
// package repository/sqlite — so a consumer can depend on the contract and swap
// the backing database.
//
// The data it moves is typed by packages har (the strict HAR 1.3 object model)
// and model (lebedev's extension of it: the capture fingerprint and the store
// identity). Nothing here reshapes an observation: what the wire produced is what
// a repository stores and what it hands back.
package repository

import (
	"context"
	"errors"
	"time"

	"github.com/ntakezo/lebedev/model"
)

var (
	// ErrNotFound is returned when a named session, entry, or connection does not
	// exist.
	ErrNotFound = errors.New("repository: not found")
	// ErrExists is returned when creating or renaming a session would collide with
	// one already stored, so neither call ever merges or clobbers.
	ErrExists = errors.New("repository: already exists")
)

// Repository stores captured sessions and reads them back byte-faithfully:
// header and cookie order, whitespace, URLs, form fields, bodies, and the TLS
// and HTTP/2 fingerprint round-trip exactly as they were handed over. Any
// transformation an observation needs to fit HAR — base64-encoding a binary
// body, deriving a status text — belongs to the caller, before CreateEntry.
//
// A session is addressed by its name, which is unique. Entries and connections
// are addressed by the id their create call returned. Implementations are safe
// for concurrent use.
type Repository interface {
	// CreateSession records a new session and returns its id. It returns ErrExists
	// when the name is already taken.
	CreateSession(ctx context.Context, s Session) (int64, error)
	// Session returns one session with its log metadata, its connections, and a
	// summary of each entry in capture order. Entry bodies are not loaded; fetch a
	// full entry with Entry. It returns ErrNotFound when name is unknown.
	Session(ctx context.Context, name string) (SessionDetails, error)
	// RenameSession moves a session to a new name, keeping its id and every row
	// that hangs off it. It returns ErrNotFound when old is unknown and ErrExists
	// when name is taken.
	RenameSession(ctx context.Context, old, name string) error
	// DeleteSession removes a session together with its connections and entries. It
	// returns ErrNotFound when name is unknown.
	DeleteSession(ctx context.Context, name string) error

	// CreateConnection records the TLS connection a session's entries were captured
	// over and returns its id. It returns ErrNotFound when session is unknown.
	CreateConnection(ctx context.Context, session string, c model.Connection) (int64, error)
	// Connection returns one stored connection. It returns ErrNotFound when id is
	// unknown.
	Connection(ctx context.Context, id int64) (model.Connection, error)

	// CreateEntry records one transaction under session, attributed to the
	// connection it was captured over (0 when none was recorded), and returns its
	// id. It returns ErrNotFound when session or connection is unknown.
	CreateEntry(ctx context.Context, session string, connection int64, e model.Entry) (int64, error)
	// Entry returns one stored entry in full, with its _lebedev field rebuilt from
	// the connection it was captured over. It returns ErrNotFound when id is
	// unknown.
	Entry(ctx context.Context, id int64) (model.Stored, error)
	// DeleteEntry removes one entry and everything hanging off it. The connection it
	// referenced is left in place, since other entries may share it. It returns
	// ErrNotFound when id is unknown.
	DeleteEntry(ctx context.Context, id int64) error
}

// Session is a capture's log-level metadata: the name it is addressed by and the
// HAR log header it exports under. Log.Entries is ignored — entries are written
// one at a time through CreateEntry.
type Session struct {
	Name string
	Log  model.Log
}

// SessionDetails is one stored session read back: its identity, the log metadata
// it exports under, the TLS connections its traffic was captured over, and a
// summary of every entry in capture order. It is deliberately body-free, so
// listing a large session stays cheap; Repository.Entry loads one in full.
type SessionDetails struct {
	ID          int64
	Name        string
	CreatedAt   time.Time
	Log         model.Log
	Connections []model.Connection
	Entries     []EntrySummary
}

// EntrySummary is the light projection of a stored entry — enough to list,
// filter, and pick one out, without reading its headers or body. Connection is
// the connection the entry was captured over, or 0 when none was recorded.
type EntrySummary struct {
	ID              int64
	Connection      int64
	StartedDateTime string
	Method          string
	URL             string
	Status          int
	MimeType        string
	BodySize        int
}
