package repl

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ntakezo/lebedev/internal/store"
)

// TestReplSessionCRUD drives the pure store-management commands (no proxy) and
// checks that list, rename, and delete take effect and are reported.
func TestReplSessionCRUD(t *testing.T) {
	durable, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer durable.Close()
	ctx := context.Background()
	durable.Insert(ctx, "alpha", testEntry("https://a/1"), 1)
	durable.Insert(ctx, "alpha", testEntry("https://a/2"), 2)

	var out bytes.Buffer
	r := New(durable, nil, "/tmp/ca.crt", &out)
	input := strings.Join([]string{
		"sessions",
		"rename alpha beta",
		"show beta",
		"rm beta",
		"sessions",
		"quit",
	}, "\n")
	if err := r.Run(strings.NewReader(input)); err != nil {
		t.Fatal(err)
	}

	got := out.String()
	if !strings.Contains(got, "alpha") {
		t.Errorf("expected initial listing to show 'alpha':\n%s", got)
	}
	if !strings.Contains(got, `renamed "alpha" to "beta"`) {
		t.Errorf("expected rename confirmation:\n%s", got)
	}
	if !strings.Contains(got, "https://a/1") {
		t.Errorf("expected 'show beta' to list entries:\n%s", got)
	}
	if !strings.Contains(got, `deleted stored session "beta"`) {
		t.Errorf("expected delete confirmation:\n%s", got)
	}
	// After deletion the final 'sessions' should report none.
	if n := strings.Count(got, "no sessions"); n < 1 {
		t.Errorf("expected 'no sessions' after delete:\n%s", got)
	}
}
