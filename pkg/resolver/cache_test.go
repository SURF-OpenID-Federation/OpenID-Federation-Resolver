package resolver

import (
	"context"
	"testing"
	"time"
)

func TestCacheFunctions(t *testing.T) {
	cfg := &Config{RequestTimeout: 1 * time.Second}
	r, err := NewFederationResolver(cfg)
	if err != nil {
		t.Fatalf("NewFederationResolver: %v", err)
	}

	ctx := context.Background()

	// Prepare a cached entity
	entityID := "https://example.com"
	ta := "https://ta.example"
	cacheKey := entityID + ":" + ta
	stmt := &CachedEntityStatement{
		EntityID:  entityID,
		Statement: "stmt",
		Issuer:    ta,
		Subject:   entityID,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CachedAt:  time.Now(),
	}

	r.entityCache.Set(cacheKey, stmt, time.Until(stmt.ExpiresAt))
	r.cachedEntities[cacheKey] = stmt

	// Ensure GetCachedEntity returns it
	got, ok := r.GetCachedEntity(entityID, ta)
	if !ok || got == nil || got.EntityID != entityID {
		t.Fatalf("GetCachedEntity returned unexpected result: ok=%v, got=%v", ok, got)
	}

	// Remove it and verify it's gone
	if !r.RemoveCachedEntity(entityID, ta) {
		t.Fatalf("RemoveCachedEntity returned false")
	}
	_, ok = r.GetCachedEntity(entityID, ta)
	if ok {
		t.Fatalf("GetCachedEntity should have returned not found after removal")
	}

	// Test GetCachedEntityAny and RemoveCachedEntityAny
	anyKey := entityID + ":any"
	stmt2 := &CachedEntityStatement{EntityID: entityID, ExpiresAt: time.Now().Add(1 * time.Hour)}
	r.entityCache.Set(anyKey, stmt2, time.Until(stmt2.ExpiresAt))
	r.cachedEntities[anyKey] = stmt2

	if s, ok := r.GetCachedEntityAny(entityID); !ok || s.EntityID != entityID {
		t.Fatalf("GetCachedEntityAny failed: ok=%v, s=%v", ok, s)
	}

	if !r.RemoveCachedEntityAny(entityID) {
		t.Fatalf("RemoveCachedEntityAny returned false")
	}
	if _, ok := r.GetCachedEntityAny(entityID); ok {
		t.Fatalf("GetCachedEntityAny should have returned not found after removal")
	}

	// Test expiration handling
	expired := &CachedEntityStatement{EntityID: "expired", ExpiresAt: time.Now().Add(-1 * time.Minute)}
	r.entityCache.Set("expired:any", expired, time.Until(expired.ExpiresAt))
	r.cachedEntities["expired:any"] = expired
	if _, ok := r.GetCachedEntityAny("expired"); ok {
		t.Fatalf("GetCachedEntityAny should not return expired entry")
	}

	// Test chain cache get and remove
	chain := &CachedTrustChain{EntityID: entityID, Chain: []CachedEntityStatement{*stmt}}
	r.chainCache.Set(entityID, chain, time.Until(time.Now().Add(1*time.Hour)))
	if c, ok := r.GetCachedChain(entityID); !ok || c.EntityID != entityID {
		t.Fatalf("GetCachedChain failed: ok=%v, c=%v", ok, c)
	}
	if !r.RemoveCachedChain(entityID) {
		t.Fatalf("RemoveCachedChain returned false")
	}
	if _, ok := r.GetCachedChain(entityID); ok {
		t.Fatalf("GetCachedChain should have returned not found after removal")
	}

	// Clear caches
	// Add entries then clear
	r.entityCache.Set("a:any", stmt, time.Until(stmt.ExpiresAt))
	r.chainCache.Set("b", chain, time.Until(time.Now().Add(1*time.Hour)))
	r.ClearAllCaches()
	if r.entityCache.Size() != 0 || r.chainCache.Size() != 0 {
		t.Fatalf("Caches were not cleared: entity=%d chain=%d", r.entityCache.Size(), r.chainCache.Size())
	}

	// Sanity: GetCacheStats returns a map with numeric entries
	stats := r.GetCacheStats()
	if _, ok := stats["entity_cache_size"]; !ok {
		t.Fatalf("GetCacheStats missing entity_cache_size")
	}
	if _, ok := stats["chain_cache_size"]; !ok {
		t.Fatalf("GetCacheStats missing chain_cache_size")
	}

	// ListCachedEntities should be safe to call
	_ = r.ListCachedEntities()
	_ = r.ListCachedChains()

	// Use resolver in a typical function to ensure no nil-panics
	_, _ = r.ResolveEntity(ctx, entityID, ta, true) // ignore error
}

func TestCachedChainWithExpiredEntity(t *testing.T) {
	cfg := &Config{RequestTimeout: 1 * time.Second}
	// add a trust anchor so ResolveTrustChain will attempt fallback
	cfg.TrustAnchors = []string{"https://ta.example"}
	r, err := NewFederationResolver(cfg)
	if err != nil {
		t.Fatalf("NewFederationResolver: %v", err)
	}

	entityID := "https://example.com"
	// create a chain where one entity is expired
	expiredEntity := CachedEntityStatement{
		EntityID:  "https://expired.example",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	validEntity := CachedEntityStatement{
		EntityID:  entityID,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	chain := &CachedTrustChain{
		EntityID:    entityID,
		TrustAnchor: "https://ta.example",
		Chain:       []CachedEntityStatement{validEntity, expiredEntity},
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}

	// store the cached chain
	r.chainCache.Set(entityID, chain, time.Until(chain.ExpiresAt))

	// ResolveTrustChain should detect expired entity and remove cached chain
	_, err = r.ResolveTrustChain(context.Background(), entityID, false)
	if err == nil {
		// It's okay if ResolveTrustChain returns an error (no anchors able to rebuild)
	}

	// cached chain should be removed or replaced with an error entry
	// allow brief time for removal/replacement
	ok := false
	var cached *CachedTrustChain
	for i := 0; i < 10; i++ {
		if c, found := r.GetCachedChain(entityID); found {
			cached = c
			ok = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if !ok {
		// no cache entry: acceptable
		return
	}

	// if there is a cache entry, it must not contain the expired entity
	for _, ent := range cached.Chain {
		if ent.EntityID == "https://expired.example" {
			t.Fatalf("Cached chain still contains expired entity")
		}
	}
}
