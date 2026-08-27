package resolver

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRegistryPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registered-trust-anchors.json")
	cfg := &Config{
		RequestTimeout: 2 * time.Second,
		RegistryPath:   path,
	}
	r1, err := NewFederationResolver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := r1.RegisterTrustAnchor(&TrustAnchorRegistration{
		EntityID:  "https://ta.example",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("registry not written: %v", err)
	}

	r2, err := NewFederationResolver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !r2.IsAuthorizedForTrustAnchor("https://ta.example") {
		t.Fatal("expected persisted registration")
	}
}

func TestRegistrySkipsExpiredOnLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reg.json")
	body := []byte(`{"version":1,"anchors":{"https://ta.example":{"entity_id":"https://ta.example","expires_at":"2020-01-01T00:00:00Z"}}}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	r2, err := NewFederationResolver(&Config{RequestTimeout: time.Second, RegistryPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if r2.IsAuthorizedForTrustAnchor("https://ta.example") {
		t.Fatal("expired registration should not load as authorized")
	}
}

func TestStoreCachedChainDedupesListAndUsesMinExp(t *testing.T) {
	r, err := NewFederationResolver(&Config{RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(2 * time.Hour)
	earlier := time.Now().Add(30 * time.Minute)
	chain := &CachedTrustChain{
		EntityID:    "https://leaf.example",
		TrustAnchor: "https://ta.example",
		Status:      "valid",
		CachedAt:    time.Now(),
		Chain: []CachedEntityStatement{
			{EntityID: "https://leaf.example", Subject: "https://leaf.example", ExpiresAt: exp},
			{EntityID: "https://ta.example", Subject: "https://ta.example", ExpiresAt: earlier},
		},
	}
	r.StoreCachedChain(chain)
	listed := r.ListCachedChains()
	if len(listed) != 1 {
		t.Fatalf("listed %d, want 1 (alias deduped)", len(listed))
	}
	got, ok := r.GetCachedChain("https://leaf.example")
	if !ok {
		t.Fatal("alias miss")
	}
	if got.ExpiresAt.Sub(earlier).Abs() > time.Second {
		t.Fatalf("expires_at=%s want min JWT exp %s", got.ExpiresAt, earlier)
	}
	gotTA, ok := r.GetCachedChainWithAnchor("https://leaf.example", "https://ta.example")
	if !ok || gotTA.TrustAnchor != "https://ta.example" {
		t.Fatal("per-anchor miss")
	}
	if !r.RemoveCachedChain("https://leaf.example") {
		t.Fatal("remove")
	}
	if _, ok := r.GetCachedChain("https://leaf.example"); ok {
		t.Fatal("alias still present")
	}
	if _, ok := r.GetCachedChainWithAnchor("https://leaf.example", "https://ta.example"); ok {
		t.Fatal("per-anchor still present")
	}
}
