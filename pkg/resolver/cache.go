package resolver

import (
	"fmt"
	"time"

	cache "resolver/pkg/cache"
	"resolver/pkg/metrics"
)

// GetCacheStats returns statistics about the caches
func (r *FederationResolver) GetCacheStats() map[string]interface{} {
	negSize := 0
	if r.negativeCache != nil {
		negSize = r.negativeCache.Size()
	}
	return map[string]interface{}{
		"entity_cache_size":       r.entityCache.Size(),
		"chain_cache_size":        r.chainCache.Size(),
		"unresolvable_cache_size": negSize,
	}
}

func (r *FederationResolver) rememberCachedEntity(key string, stmt *CachedEntityStatement) {
	if stmt == nil {
		return
	}
	r.entitiesMu.Lock()
	r.cachedEntities[key] = stmt
	r.entitiesMu.Unlock()
}

func (r *FederationResolver) forgetCachedEntity(key string) {
	r.entitiesMu.Lock()
	delete(r.cachedEntities, key)
	r.entitiesMu.Unlock()
}

func (r *FederationResolver) resetCachedEntities() {
	r.entitiesMu.Lock()
	r.cachedEntities = make(map[string]*CachedEntityStatement)
	r.entitiesMu.Unlock()
}

func (r *FederationResolver) newEntityCache() *cache.Cache {
	return cache.NewLimitedCache("entity_statements", cacheLimit(r.config))
}

func (r *FederationResolver) newChainCache() *cache.Cache {
	return cache.NewLimitedCache("trust_chains", cacheLimit(r.config))
}

// ListCachedEntities returns live entity-statement cache entries (not expired).
func (r *FederationResolver) ListCachedEntities() []CachedEntityStatement {
	items := r.entityCache.Items()
	entities := make([]CachedEntityStatement, 0, len(items))
	now := time.Now()
	for _, item := range items {
		stmt, ok := item.(*CachedEntityStatement)
		if !ok || stmt == nil {
			continue
		}
		if now.After(stmt.ExpiresAt) {
			continue
		}
		entities = append(entities, *stmt)
	}
	return entities
}

// ListCachedChains returns live trust chains, one row per entity+anchor
// (the `{entity}` alias is not listed separately from `{entity}:{ta}`).
func (r *FederationResolver) ListCachedChains() []CachedTrustChain {
	items := r.chainCache.Items()
	seen := make(map[string]struct{}, len(items))
	chains := make([]CachedTrustChain, 0, len(items))
	for _, item := range items {
		chain, ok := item.(*CachedTrustChain)
		if !ok || chain == nil {
			continue
		}
		id := chain.EntityID + "|" + chain.TrustAnchor
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		chains = append(chains, *chain)
	}
	return chains
}

// InFlightResolveCount is the number of coalesced outbound entity resolves in progress.
func (r *FederationResolver) InFlightResolveCount() int {
	if r == nil {
		return 0
	}
	return r.entityInflight.len()
}

// ClearEntityCache clears all cached entity statements
func (r *FederationResolver) ClearEntityCache() {
	r.entityCache = r.newEntityCache()
	r.resetCachedEntities()
	r.clearNegativeCache()
	metrics.UpdateCacheSize("entity_statements", 0)
}

// ClearChainCache clears all cached trust chains
func (r *FederationResolver) ClearChainCache() {
	r.chainCache = r.newChainCache()
	metrics.UpdateCacheSize("trust_chains", 0)
}

// ClearAllCaches clears both entity and chain caches
func (r *FederationResolver) ClearAllCaches() {
	r.ClearEntityCache()
	r.ClearChainCache()
}

func minChainExpiry(chain *CachedTrustChain) time.Time {
	if chain == nil {
		return time.Time{}
	}
	var min time.Time
	for _, ce := range chain.Chain {
		if ce.ExpiresAt.IsZero() {
			continue
		}
		if min.IsZero() || ce.ExpiresAt.Before(min) {
			min = ce.ExpiresAt
		}
	}
	return min
}

// StoreCachedChain writes the chain under `{entity}:{ta}` and `{entity}` with
// the same TTL. Valid chains expire at the earliest JWT exp in the chain.
func (r *FederationResolver) StoreCachedChain(chain *CachedTrustChain) {
	if chain == nil {
		return
	}
	chain.Chain = DeduplicateCachedChain(chain.Chain)
	if chain.Status == "valid" {
		if exp := minChainExpiry(chain); !exp.IsZero() {
			chain.ExpiresAt = exp
		}
	}
	if chain.ExpiresAt.IsZero() {
		chain.ExpiresAt = time.Now().Add(time.Minute)
	}
	ttl := time.Until(chain.ExpiresAt)
	if ttl <= 0 {
		return
	}
	if chain.TrustAnchor != "" {
		r.chainCache.Set(chain.EntityID+":"+chain.TrustAnchor, chain, ttl)
	}
	r.chainCache.Set(chain.EntityID, chain, ttl)
}

// RemoveCachedEntity removes a specific entity from the cache
func (r *FederationResolver) RemoveCachedEntity(entityID, trustAnchor string) bool {
	cacheKey := fmt.Sprintf("%s:%s", entityID, trustAnchor)
	r.entityCache.Remove(cacheKey)
	r.forgetCachedEntity(cacheKey)
	return true
}

// RemoveCachedEntityAny removes an entity resolved via any trust anchor from the cache
func (r *FederationResolver) RemoveCachedEntityAny(entityID string) bool {
	cacheKey := fmt.Sprintf("%s:any", entityID)
	r.entityCache.Remove(cacheKey)
	r.forgetCachedEntity(cacheKey)
	return true
}

// RemoveCachedChain removes alias and per-anchor slots for an entity.
func (r *FederationResolver) RemoveCachedChain(entityID string) bool {
	return r.chainCache.RemoveExactOrPrefixed(entityID) > 0
}

// GetCachedEntity retrieves a specific cached entity statement
func (r *FederationResolver) GetCachedEntity(entityID, trustAnchor string) (*CachedEntityStatement, bool) {
	cacheKey := fmt.Sprintf("%s:%s", entityID, trustAnchor)
	if item, found := r.entityCache.Get(cacheKey); found {
		stmt := item.(*CachedEntityStatement)
		if time.Now().After(stmt.ExpiresAt) {
			r.entityCache.Remove(cacheKey)
			r.forgetCachedEntity(cacheKey)
			return nil, false
		}
		return stmt, true
	}
	return nil, false
}

// GetCachedEntityAny retrieves a cached entity resolved via any trust anchor
func (r *FederationResolver) GetCachedEntityAny(entityID string) (*CachedEntityStatement, bool) {
	cacheKey := fmt.Sprintf("%s:any", entityID)
	if item, found := r.entityCache.Get(cacheKey); found {
		stmt := item.(*CachedEntityStatement)
		if time.Now().After(stmt.ExpiresAt) {
			r.entityCache.Remove(cacheKey)
			r.forgetCachedEntity(cacheKey)
			return nil, false
		}
		return stmt, true
	}
	return nil, false
}

// GetCachedChain retrieves the alias slot for an entity (nearest/last stored TA).
func (r *FederationResolver) GetCachedChain(entityID string) (*CachedTrustChain, bool) {
	if item, found := r.chainCache.Get(entityID); found {
		return item.(*CachedTrustChain), true
	}
	return nil, false
}

// GetCachedChainWithAnchor prefers the per-anchor slot, then the entity alias.
func (r *FederationResolver) GetCachedChainWithAnchor(entityID, trustAnchor string) (*CachedTrustChain, bool) {
	if trustAnchor != "" {
		key := fmt.Sprintf("%s:%s", entityID, trustAnchor)
		if item, found := r.chainCache.Get(key); found {
			return item.(*CachedTrustChain), true
		}
	}
	return r.GetCachedChain(entityID)
}

// SweepCaches deletes expired entity, chain, and negative-cache entries.
func (r *FederationResolver) SweepCaches() {
	if r == nil {
		return
	}
	if r.entityCache != nil {
		r.entityCache.Sweep()
	}
	if r.chainCache != nil {
		r.chainCache.Sweep()
	}
	if r.negativeCache != nil {
		r.negativeCache.Sweep()
	}
}
