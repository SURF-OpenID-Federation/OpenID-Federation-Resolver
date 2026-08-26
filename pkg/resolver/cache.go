package resolver

import (
	"fmt"
	"time"

	cache "resolver/pkg/cache"
	"resolver/pkg/metrics"
)

// Cache management methods moved here to keep resolver.go smaller

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

// ListCachedEntities returns a list of all cached entity statements
func (r *FederationResolver) ListCachedEntities() []CachedEntityStatement {
	r.entitiesMu.RLock()
	defer r.entitiesMu.RUnlock()
	entities := make([]CachedEntityStatement, 0, len(r.cachedEntities))
	for _, entity := range r.cachedEntities {
		entities = append(entities, *entity)
	}
	return entities
}

// ListCachedChains returns a list of all cached trust chains
func (r *FederationResolver) ListCachedChains() []CachedTrustChain {
	items := r.chainCache.Items()
	chains := make([]CachedTrustChain, 0, len(items))
	for _, item := range items {
		chain, ok := item.(*CachedTrustChain)
		if !ok || chain == nil {
			continue
		}
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
	r.entityCache = cache.NewCache("entity_statements")
	r.resetCachedEntities()
	r.clearNegativeCache()
	// Update metrics
	metrics.UpdateCacheSize("entity_statements", 0)
}

// ClearChainCache clears all cached trust chains
func (r *FederationResolver) ClearChainCache() {
	r.chainCache = cache.NewCache("trust_chains")
	// Update metrics
	metrics.UpdateCacheSize("trust_chains", 0)
}

// ClearAllCaches clears both entity and chain caches
func (r *FederationResolver) ClearAllCaches() {
	r.ClearEntityCache()
	r.ClearChainCache()
}

// StoreCachedChain centralizes dedupe and storage of a CachedTrustChain
func (r *FederationResolver) StoreCachedChain(key string, chain *CachedTrustChain) {
	if chain == nil {
		return
	}
	// Deduplicate issuer+subject pairs before storing
	chain.Chain = DeduplicateCachedChain(chain.Chain)
	r.chainCache.Set(key, chain, time.Until(chain.ExpiresAt))
}

// RemoveCachedEntity removes a specific entity from the cache
func (r *FederationResolver) RemoveCachedEntity(entityID, trustAnchor string) bool {
	cacheKey := fmt.Sprintf("%s:%s", entityID, trustAnchor)
	r.entityCache.Remove(cacheKey)
	r.forgetCachedEntity(cacheKey)
	return true // Delete doesn't return success status
}

// RemoveCachedEntityAny removes an entity resolved via any trust anchor from the cache
func (r *FederationResolver) RemoveCachedEntityAny(entityID string) bool {
	cacheKey := fmt.Sprintf("%s:any", entityID)
	r.entityCache.Remove(cacheKey)
	r.forgetCachedEntity(cacheKey)
	return true // Delete doesn't return success status
}

// RemoveCachedChain removes a specific trust chain from the cache
func (r *FederationResolver) RemoveCachedChain(entityID string) bool {
	r.chainCache.Remove(entityID)
	return true // Delete doesn't return success status
}

// GetCachedEntity retrieves a specific cached entity statement
func (r *FederationResolver) GetCachedEntity(entityID, trustAnchor string) (*CachedEntityStatement, bool) {
	cacheKey := fmt.Sprintf("%s:%s", entityID, trustAnchor)
	if item, found := r.entityCache.Get(cacheKey); found {
		stmt := item.(*CachedEntityStatement)
		if time.Now().After(stmt.ExpiresAt) {
			// expired: remove from cache and report not found
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

// GetCachedChain retrieves a specific cached trust chain
func (r *FederationResolver) GetCachedChain(entityID string) (*CachedTrustChain, bool) {
	if item, found := r.chainCache.Get(entityID); found {
		return item.(*CachedTrustChain), true
	}
	return nil, false
}
