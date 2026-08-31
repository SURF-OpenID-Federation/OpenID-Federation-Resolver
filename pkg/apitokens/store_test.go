package apitokens

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateAuthenticateRevokePAT(t *testing.T) {
	t.Setenv("API_PAT_PEPPER", "test-pepper")
	SetForTest(nil)
	t.Cleanup(func() { SetForTest(nil) })

	store, err := Init(t.TempDir())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	now := time.Now().UTC()
	plain, pub, err := store.CreatePAT("ci", 24*time.Hour, now)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if plain == "" || pub.ID == "" || pub.Status != "active" {
		t.Fatalf("unexpected create result: %+v secret empty=%v", pub, plain == "")
	}
	if err := store.Authenticate(plain, now.Add(time.Minute)); err != nil {
		t.Fatalf("auth: %v", err)
	}
	if _, err := store.RevokePAT(pub.ID, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := store.Authenticate(plain, now.Add(3*time.Minute)); err != ErrTokenRevoked {
		t.Fatalf("revoked auth err=%v", err)
	}
}

func TestExpiredPATRejected(t *testing.T) {
	t.Setenv("API_PAT_PEPPER", "test-pepper")
	SetForTest(nil)
	t.Cleanup(func() { SetForTest(nil) })

	store, err := Init(t.TempDir())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	now := time.Now().UTC()
	plain, _, err := store.CreatePAT("short", time.Minute, now)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.Authenticate(plain, now.Add(2*time.Minute)); err != ErrTokenExpired {
		t.Fatalf("expired auth err=%v", err)
	}
}

func TestInitPersistsPepperAndTokens(t *testing.T) {
	t.Setenv("API_PAT_PEPPER", "")
	_ = os.Unsetenv("API_PAT_PEPPER")
	SetForTest(nil)
	t.Cleanup(func() { SetForTest(nil) })

	dir := t.TempDir()
	store, err := Init(dir)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	now := time.Now().UTC()
	plain, pub, err := store.CreatePAT("persist", 24*time.Hour, now)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".api_pat_pepper")); err != nil {
		t.Fatalf("pepper file: %v", err)
	}
	SetForTest(nil)
	again, err := Init(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := again.Authenticate(plain, now.Add(time.Minute)); err != nil {
		t.Fatalf("reopen auth: %v", err)
	}
	got, err := again.GetPAT(pub.ID, now)
	if err != nil || got.Name != "persist" {
		t.Fatalf("get: %+v %v", got, err)
	}
}
