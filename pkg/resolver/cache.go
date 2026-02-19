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
	return map[string]interface{}{
		"entity_cache_size": r.entityCache.Size(),
		"chain_cache_size":  r.chainCache.Size(),
	}
}

// ListCachedEntities returns a list of all cached entity statements
func (r *FederationResolver) ListCachedEntities() []CachedEntityStatement {
	entities := make([]CachedEntityStatement, 0, len(r.cachedEntities))
	for _, entity := range r.cachedEntities {
		entities = append(entities, *entity)
	}
	return entities
}

// ListCachedChains returns a list of all cached trust chains
func (r *FederationResolver) ListCachedChains() []CachedTrustChain {
	// The external cache doesn't expose contents, so return empty list
	// In a real implementation, you'd need to maintain a separate index
	return []CachedTrustChain{}
}

// ClearEntityCache clears all cached entity statements
func (r *FederationResolver) ClearEntityCache() {
	r.entityCache = cache.NewCache("entity_statements")
	r.cachedEntities = make(map[string]*CachedEntityStatement)
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
	delete(r.cachedEntities, cacheKey)
	return true // Delete doesn't return success status
}

// RemoveCachedEntityAny removes an entity resolved via any trust anchor from the cache
func (r *FederationResolver) RemoveCachedEntityAny(entityID string) bool {
	cacheKey := fmt.Sprintf("%s:any", entityID)
	r.entityCache.Remove(cacheKey)
	delete(r.cachedEntities, cacheKey)
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
			delete(r.cachedEntities, cacheKey)
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
			delete(r.cachedEntities, cacheKey)
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
