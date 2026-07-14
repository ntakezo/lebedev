package store

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/ntakezo/lebedev/har"
	"github.com/ntakezo/lebedev/model"
)

func sampleEntry() model.Entry {
	httpOnly := true
	secure := false
	return model.Entry{
		StartedDateTime: "2026-07-13T00:00:00.000Z",
		Time:            0,
		Request: har.Request{
			Method:      "POST",
			URL:         "https://example.com/api?b=2&a=1",
			HTTPVersion: "HTTP/2.0",
			Cookies:     []har.Cookie{{Name: "sid", Value: "xyz"}},
			Headers:     []har.NVP{{Name: "user-agent", Value: "UA"}, {Name: "accept", Value: "*/*"}},
			QueryString: []har.NVP{{Name: "b", Value: "2"}, {Name: "a", Value: "1"}},
			PostData:    &har.PostData{MimeType: "application/json", Text: `{"k":"v"}`},
			HeadersSize: -1,
			BodySize:    9,
		},
		Response: har.Response{
			Status:      200,
			StatusText:  "OK",
			HTTPVersion: "HTTP/2.0",
			Cookies:     []har.Cookie{{Name: "set", Value: "1", Path: "/", HTTPOnly: &httpOnly, Secure: &secure}},
			Headers:     []har.NVP{{Name: "content-type", Value: "application/json"}},
			Content:     har.Content{Size: 2, MimeType: "application/json", Text: "{}"},
			RedirectURL: "",
			HeadersSize: -1,
			BodySize:    2,
		},
		Cache:   har.Cache{},
		Timings: har.Timings{Send: 0, Wait: 0, Receive: 0},
		Lebedev: &model.Lebedev{
			Session:        "s1",
			ClientHelloHex: "1603010001ff",
			HTTP2:          &model.HTTP2{Settings: []model.Setting{{ID: 1, Value: 65536}}, ConnectionFlow: 15663105, PseudoOrder: []string{":method", ":path"}, HeaderOrder: []string{"user-agent"}},
		},
	}
}

func TestInsertGetRoundTrip(t *testing.T) {
	st, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()

	want := sampleEntry()
	id, err := st.Insert(ctx, "s1", want, 100)
	if err != nil {
		t.Fatal(err)
	}

	got, err := st.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Entry, want) {
		t.Errorf("round trip mismatch:\n got %#v\nwant %#v", got.Entry, want)
	}
	if got.Session != "s1" {
		t.Errorf("session = %q", got.Session)
	}
}

func TestQueryFilters(t *testing.T) {
	st, _ := Open("")
	defer st.Close()
	ctx := context.Background()

	a := sampleEntry()
	b := sampleEntry()
	b.Request.URL = "https://other.com/page.html"
	b.Request.Method = "GET"
	b.Response.Content.MimeType = "text/html"
	b.Response.Status = 404

	st.Insert(ctx, "s1", a, 1)
	st.Insert(ctx, "s1", b, 2)

	cases := []struct {
		name string
		q    Query
		want int
	}{
		{"all", Query{}, 2},
		{"by method", Query{Method: "GET"}, 1},
		{"by status", Query{Status: 404}, 1},
		{"by mime", Query{MimeType: "application/json"}, 1},
		{"by url glob", Query{URLGlob: "*other.com*"}, 1},
		{"url glob no match", Query{URLGlob: "*nope*"}, 0},
	}
	for _, c := range cases {
		got, err := st.List(ctx, c.q)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != c.want {
			t.Errorf("%s: got %d entries, want %d", c.name, len(got), c.want)
		}
		n, _ := st.Count(ctx, c.q)
		if n != c.want {
			t.Errorf("%s: count = %d, want %d", c.name, n, c.want)
		}
	}
}

func TestSessionCRUD(t *testing.T) {
	st, _ := Open("")
	defer st.Close()
	ctx := context.Background()

	st.Insert(ctx, "a", sampleEntry(), 1)
	st.Insert(ctx, "a", sampleEntry(), 2)
	st.Insert(ctx, "b", sampleEntry(), 3)

	infos, err := st.SessionInfos(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 2 || infos[0].Session != "a" || infos[0].Entries != 2 || infos[1].Entries != 1 {
		t.Fatalf("session infos = %+v", infos)
	}

	if err := st.RenameSession(ctx, "a", "c"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := st.HasSession(ctx, "a"); ok {
		t.Error("session 'a' should be gone after rename")
	}
	if n, _ := st.Count(ctx, Query{Session: "c"}); n != 2 {
		t.Errorf("renamed session 'c' has %d entries, want 2", n)
	}
	if err := st.RenameSession(ctx, "c", "b"); err == nil {
		t.Error("rename onto an existing session should fail")
	}

	if err := st.DeleteSession(ctx, "c"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := st.HasSession(ctx, "c"); ok {
		t.Error("session 'c' should be gone after delete")
	}
	// Deleting one session must leave the other intact (child rows too).
	if n, _ := st.Count(ctx, Query{Session: "b"}); n != 1 {
		t.Errorf("session 'b' has %d entries after deleting 'c', want 1", n)
	}
	got, err := st.List(ctx, Query{Session: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Entry.Request.Headers) == 0 {
		t.Errorf("session 'b' entry lost its child rows after unrelated delete: %+v", got)
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	ctx := context.Background()
	src, _ := Open("")
	defer src.Close()

	want := sampleEntry()
	src.Insert(ctx, "s1", want, 1)

	var buf bytes.Buffer
	if err := src.Export(ctx, Query{Session: "s1"}, &buf); err != nil {
		t.Fatal(err)
	}

	dst, _ := Open("")
	defer dst.Close()
	n, err := dst.Import(ctx, "s2", &buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("imported %d entries, want 1", n)
	}

	got, err := dst.List(ctx, Query{Session: "s2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries after import, want 1", len(got))
	}
	// The session id is a store dimension, so it becomes s2 on re-import; compare
	// everything else, which must survive the HAR round trip verbatim.
	want.Lebedev.Session = "s2"
	if !reflect.DeepEqual(got[0].Entry, want) {
		t.Errorf("export/import mismatch:\n got %#v\nwant %#v", got[0].Entry, want)
	}
}
