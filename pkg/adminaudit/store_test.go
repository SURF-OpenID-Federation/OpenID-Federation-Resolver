package adminaudit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStorePersistAndNewestFirst(t *testing.T) {
	dir := t.TempDir()
	s, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { SetForTest(nil) })
	if err := s.Append(Entry{Action: "keys.create", Method: "POST", Path: "/admin/v1/keys", Status: 201, Actor: "alice"}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	if err := s.Append(Entry{Action: "keys.rotate", Method: "POST", Path: "/admin/v1/keys/k1/rotate", Status: 201, Actor: "alice"}); err != nil {
		t.Fatal(err)
	}
	got := s.List()
	if len(got) != 2 || got[0].Action != "keys.rotate" || got[1].Action != "keys.create" {
		t.Fatalf("list=%+v", got)
	}

	s2, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	got = s2.List()
	if len(got) != 2 || got[0].Action != "keys.rotate" {
		t.Fatalf("reload=%+v", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "audit", "admin.jsonl")); err != nil {
		t.Fatalf("expected jsonl: %v", err)
	}
}

func TestStoreCapsEntries(t *testing.T) {
	s := &Store{max: 3}
	for i := 0; i < 5; i++ {
		if err := s.Append(Entry{Action: "keys.create", Status: 201}); err != nil {
			t.Fatal(err)
		}
	}
	got := s.List()
	if len(got) != 3 {
		t.Fatalf("len=%d", len(got))
	}
}

func TestAction(t *testing.T) {
	if got := Action("POST", "/admin/v1/keys"); got != "keys.create" {
		t.Fatalf("got %q", got)
	}
	if got := Action("DELETE", "/admin/v1/keys/abc"); got != "keys.delete" {
		t.Fatalf("got %q", got)
	}
	if got := Action("POST", "/admin/v1/keys/:kid/rotate"); got != "keys.rotate" {
		t.Fatalf("got %q", got)
	}
	if got := Action("PATCH", "/admin/v1/configuration"); got != "configuration.patch" {
		t.Fatalf("got %q", got)
	}
	if got := Action("POST", "/admin/v1/tokens"); got != "tokens.create" {
		t.Fatalf("got %q", got)
	}
	if got := Action("DELETE", "/admin/v1/tokens/tok_1"); got != "tokens.revoke" {
		t.Fatalf("got %q", got)
	}
	if got := Action("POST", "/admin/v1/cache/clear-all"); got != "cache.clear_all" {
		t.Fatalf("got %q", got)
	}
}
