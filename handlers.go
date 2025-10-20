package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"resolver/pkg/metrics"
	"resolver/pkg/resolver"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type ResolveRequest struct {
	EntityID     string `json:"entity_id" binding:"required"`
	TrustAnchor  string `json:"trust_anchor,omitempty"`
	ForceRefresh bool   `json:"force_refresh,omitempty"`
}

// Health check
func healthHandler(c *gin.Context) {
	start := time.Now()

	health := gin.H{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"service":   config.Service.Name,
		"uptime":    time.Since(startTime).Seconds(), // Add uptime
	}

	if checkTrustAnchors {
		taHealth := make(map[string]string)
		for _, ta := range config.TrustAnchors {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := fedResolver.CheckTrustAnchor(ctx, ta)
			cancel()

			if err != nil {
				taHealth[ta] = "unhealthy: " + err.Error()
				metrics.RecordError("trust_anchor_check_failed", "health_check")
			} else {
				taHealth[ta] = "healthy"
			}
		}
		health["trust_anchors"] = taHealth
	}

	// Record health check metric
	duration := time.Since(start)
	metrics.RecordHTTPRequest("GET", "/health", http.StatusOK, duration)

	c.JSON(http.StatusOK, health)
}

// Metrics handler
func metricsHandler(c *gin.Context) {
	// Update uptime before serving metrics
	metrics.UpdateUptime()

	// Serve Prometheus metrics
	promhttp.Handler().ServeHTTP(c.Writer, c.Request)
}

// DNS-like entity resolution
func resolveEntityHandler(c *gin.Context) {
	start := time.Now()
	entityID := c.Param("entityId")

	// Strip leading slash from wildcard parameter
	entityID = strings.TrimPrefix(entityID, "/")

	// URL decode
	decodedEntityID, err := url.QueryUnescape(entityID)
	if err != nil {
		metrics.RecordError("invalid_entity_id", "resolve_entity")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid entity ID"})
		return
	}

	// Check for trust_anchor query parameter
	trustAnchor := c.Query("trust_anchor")
	forceRefresh := c.Query("force_refresh") == "true"

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	var statement *resolver.CachedEntityStatement
	if trustAnchor != "" {
		// Resolve through specific trust anchor
		decodedTrustAnchor, err := url.QueryUnescape(trustAnchor)
		if err != nil {
			metrics.RecordError("invalid_trust_anchor", "resolve_entity")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid trust anchor"})
			return
		}

		statement, err = fedResolver.ResolveEntity(ctx, decodedEntityID, decodedTrustAnchor, forceRefresh)
		if err != nil {
			metrics.RecordEntityResolution(decodedEntityID, decodedTrustAnchor, "error", time.Since(start))
			metrics.RecordError("entity_resolution_failed", "resolve_entity")

			c.JSON(http.StatusNotFound, gin.H{
				"error":   "Failed to resolve entity",
				"details": err.Error(),
			})
			return
		}

		metrics.RecordEntityResolution(decodedEntityID, decodedTrustAnchor, "success", time.Since(start))

		c.Header("Cache-Control", "public, max-age=3600")
		c.JSON(http.StatusOK, gin.H{
			"entity_id":    decodedEntityID,
			"trust_anchor": decodedTrustAnchor,
			"statement":    statement.Statement,
			"issuer":       statement.Issuer,
			"subject":      statement.Subject,
			"cached_at":    statement.CachedAt,
			"expires_at":   statement.ExpiresAt,
			"fetched_from": statement.FetchedFrom,
			"validated":    statement.Validated,
		})
	} else {
		// Try to resolve through any trust anchor
		statement, err = fedResolver.ResolveEntityAny(ctx, decodedEntityID, forceRefresh)
		if err != nil {
			// Record failed resolution
			metrics.RecordEntityResolution(decodedEntityID, "any", "error", time.Since(start))
			metrics.RecordError("entity_resolution_failed", "resolve_entity")

			c.JSON(http.StatusNotFound, gin.H{
				"error":     "Failed to resolve entity",
				"details":   err.Error(),
				"entity_id": decodedEntityID,
			})
			return
		}

		// Record successful resolution
		metrics.RecordEntityResolution(decodedEntityID, "any", "success", time.Since(start))

		c.Header("Cache-Control", "public, max-age=3600")
		c.JSON(http.StatusOK, gin.H{
			"entity_id":    decodedEntityID,
			"statement":    statement.Statement,
			"issuer":       statement.Issuer,
			"subject":      statement.Subject,
			"cached_at":    statement.CachedAt,
			"expires_at":   statement.ExpiresAt,
			"fetched_from": statement.FetchedFrom,
			"validated":    statement.Validated,
		})
	}
}

// Trust chain resolution (returns signed JWT per OpenID Federation spec when possible)
func resolveTrustChainHandler(c *gin.Context) {
	start := time.Now()
	entityID := c.Param("entityId")

	// Strip leading slash from wildcard parameter
	entityID = strings.TrimPrefix(entityID, "/")

	decodedEntityID, err := url.QueryUnescape(entityID)
	if err != nil {
		metrics.RecordError("invalid_entity_id", "resolve_trust_chain")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid entity ID"})
		return
	}

	forceRefresh := c.Query("force_refresh") == "true"
	trustAnchor := c.Query("trust_anchor")  // Get trust anchor from query
	rawResponse := c.Query("raw") == "true" // Optional: return raw JSON instead of signed JWT

	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()

	var trustChain *resolver.CachedTrustChain
	if trustAnchor != "" {
		// Decode trust anchor
		decodedTrustAnchor, err := url.QueryUnescape(trustAnchor)
		if err != nil {
			metrics.RecordError("invalid_trust_anchor", "resolve_trust_chain")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid trust anchor"})
			return
		}

		// Resolve with specific trust anchor
		trustChain, err = fedResolver.ResolveTrustChainWithAnchor(ctx, decodedEntityID, decodedTrustAnchor, forceRefresh)

		log.Printf("[RESOLVER] Resolved trust chain for %s via trust anchor %s, chain: %v", decodedEntityID, decodedTrustAnchor, trustChain)

		// If resolver is authorized for this trust anchor and no raw response requested,
		// return signed JWT response per OpenID Federation spec
		if err == nil && !rawResponse && fedResolver.IsAuthorizedForTrustAnchor(decodedTrustAnchor) {
			signedResponse, signErr := fedResolver.CreateSignedTrustChainResponse(trustChain, decodedTrustAnchor)
			if signErr == nil {
				duration := time.Since(start)
				metrics.RecordTrustChainDiscovery(decodedEntityID, trustAnchor, "success", duration)

				// Return signed JWT response per OpenID Federation spec Section 8.3.2
				c.Header("Content-Type", "application/resolve-response+jwt")
				c.Header("Cache-Control", "public, max-age=86400") // 24h for trust chains
				c.String(http.StatusOK, signedResponse)
				return
			}
			// If signing fails, fall back to raw response
			log.Printf("[RESOLVER] Failed to create signed response for %s: %v", decodedEntityID, signErr)
		}
	} else {
		// Resolve with any trust anchor (existing behavior)
		trustChain, err = fedResolver.ResolveTrustChain(ctx, decodedEntityID, forceRefresh)
	}
	duration := time.Since(start)

	if err != nil {
		metrics.RecordTrustChainDiscovery(decodedEntityID, trustAnchor, "error", duration)
		metrics.RecordError("trust_chain_resolution_failed", "resolve_trust_chain")

		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Failed to resolve trust chain",
			"details": err.Error(),
		})
		return
	}

	metrics.RecordTrustChainDiscovery(decodedEntityID, trustAnchor, "success", duration)

	// Return raw JSON response (fallback or when raw=true)
	c.Header("Cache-Control", "public, max-age=86400") // 24h for trust chains
	c.JSON(http.StatusOK, trustChain)
}

// Official federation resolve endpoint per OpenID Federation spec Section 8.3
func federationResolveHandler(c *gin.Context) {
	start := time.Now()

	// Get required parameters per spec Section 8.3.1
	entityID := c.Query("sub")
	trustAnchor := c.Query("trust_anchor")
	_ = c.Query("entity_type") // Optional - not used in current implementation

	if entityID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Missing required parameter 'sub' (entity identifier)",
		})
		return
	}

	if trustAnchor == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Missing required parameter 'trust_anchor'",
		})
		return
	}

	// Decode parameters
	decodedEntityID, err := url.QueryUnescape(entityID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid entity ID"})
		return
	}

	decodedTrustAnchor, err := url.QueryUnescape(trustAnchor)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid trust anchor"})
		return
	}

	// Check if resolver is authorized for this trust anchor
	if !fedResolver.IsAuthorizedForTrustAnchor(decodedTrustAnchor) {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Resolver not authorized to resolve for this trust anchor",
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()

	// Resolve the trust chain
	trustChain, err := fedResolver.ResolveTrustChainWithAnchor(ctx, decodedEntityID, decodedTrustAnchor, false)
	if err != nil {
		duration := time.Since(start)
		metrics.RecordTrustChainDiscovery(decodedEntityID, trustAnchor, "error", duration)
		metrics.RecordError("federation_resolve_failed", "federation_resolve")

		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Failed to resolve entity",
			"details": err.Error(),
		})
		return
	}

	// Create signed response (required per spec Section 8.3.2)
	signedResponse, err := fedResolver.CreateSignedTrustChainResponse(trustChain, decodedTrustAnchor)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to create signed response",
			"details": err.Error(),
		})
		return
	}

	duration := time.Since(start)
	metrics.RecordTrustChainDiscovery(decodedEntityID, trustAnchor, "success", duration)

	// Return signed JWT response per OpenID Federation spec Section 8.3.2
	c.Header("Content-Type", "application/resolve-response+jwt")
	c.Header("Cache-Control", "public, max-age=86400")
	c.String(http.StatusOK, signedResponse)
}

func listTrustAnchorsHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"trust_anchors": config.TrustAnchors,
		"count":         len(config.TrustAnchors),
	})
}

// Federation List Endpoint
// Queries the trust anchor's federation_list_endpoint per OpenID Federation spec Section 8.2
func federationListHandler(c *gin.Context) {
	start := time.Now()

	// Get required trust_anchor parameter per spec
	trustAnchor := c.Query("trust_anchor")
	if trustAnchor == "" {
		metrics.RecordError("missing_trust_anchor", "federation_list")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "trust_anchor query parameter is required",
		})
		return
	}

	// Get optional parameters per spec Section 8.2.1
	entityType := c.Query("entity_type")
	trustMarked := c.Query("trust_marked")
	trustMarkType := c.Query("trust_mark_type")
	intermediate := c.Query("intermediate")

	// Validate trust anchor
	decodedTrustAnchor, err := url.QueryUnescape(trustAnchor)
	if err != nil {
		metrics.RecordError("invalid_trust_anchor", "federation_list")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid trust anchor"})
		return
	}

	// Check if trust anchor is configured
	validTA := false
	for _, ta := range config.TrustAnchors {
		if ta == decodedTrustAnchor {
			validTA = true
			break
		}
	}
	if !validTA {
		metrics.RecordError("unauthorized_trust_anchor", "federation_list")
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Unauthorized trust anchor",
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	// Resolve the trust anchor entity to get its metadata
	taEntity, err := fedResolver.ResolveEntity(ctx, decodedTrustAnchor, decodedTrustAnchor, false)
	if err != nil {
		metrics.RecordError("trust_anchor_resolution_failed", "federation_list")

		// Check if this is a network connectivity error
		errMsg := strings.ToLower(err.Error())
		if strings.Contains(errMsg, "connection refused") ||
			strings.Contains(errMsg, "no such host") ||
			strings.Contains(errMsg, "timeout") ||
			strings.Contains(errMsg, "network is unreachable") ||
			strings.Contains(errMsg, "connection reset") ||
			strings.Contains(errMsg, "dial tcp") ||
			strings.Contains(errMsg, "couldn't connect to server") ||
			strings.Contains(errMsg, "connection timed out") ||
			strings.Contains(errMsg, "network unreachable") ||
			strings.Contains(errMsg, "host unreachable") {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Trust anchor is not reachable",
				"details": fmt.Sprintf("The trust anchor %s is not accessible from this resolver. Please ensure the trust anchor endpoint is network-reachable or use a different trust anchor.", decodedTrustAnchor),
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to resolve trust anchor",
			"details": err.Error(),
		})
		return
	}

	// Extract the federation_list_endpoint from the trust anchor's metadata
	listEndpoint, err := fedResolver.ExtractFederationListEndpoint(taEntity)
	if err != nil {
		// If the trust anchor doesn't have a federation_list_endpoint, return empty list
		// This is allowed per the spec - not all federation entities need to expose list endpoints
		log.Printf("[FEDERATION_LIST] Trust anchor %s does not have federation_list_endpoint: %v", decodedTrustAnchor, err)

		federationList := gin.H{
			"iss":             decodedTrustAnchor,
			"sub":             decodedTrustAnchor,
			"iat":             time.Now().Unix(),
			"exp":             time.Now().Add(24 * time.Hour).Unix(),
			"federation_list": []string{},
			"metadata": gin.H{
				"federation_entity": gin.H{
					"federation_list_endpoint": false,
				},
			},
		}

		duration := time.Since(start)
		metrics.RecordHTTPRequest("GET", "/federation_list", http.StatusOK, duration)

		c.Header("Cache-Control", "public, max-age=3600") // Cache for 1 hour
		c.JSON(http.StatusOK, federationList)
		return
	}

	// Query the federation list endpoint
	federationMembers, err := fedResolver.QueryFederationListEndpoint(ctx, listEndpoint, entityType, trustMarked, trustMarkType, intermediate)
	if err != nil {
		metrics.RecordError("federation_list_query_failed", "federation_list")
		log.Printf("[FEDERATION_LIST] Federation list endpoint query failed for %s: %v", decodedTrustAnchor, err)

		// For resilience, return empty list when endpoint is temporarily unavailable
		// This matches the spec's guidance that federation_list_endpoint is optional
		now := time.Now()
		federationList := gin.H{
			"iss":             decodedTrustAnchor,
			"sub":             decodedTrustAnchor,
			"iat":             now.Unix(),
			"exp":             now.Add(24 * time.Hour).Unix(),
			"federation_list": []string{},
			"metadata": gin.H{
				"federation_entity": gin.H{
					"federation_list_endpoint":        true,
					"federation_list_endpoint_status": "unavailable",
					"federation_list_endpoint_error":  err.Error(),
				},
			},
		}

		duration := time.Since(start)
		metrics.RecordHTTPRequest("GET", "/federation_list", http.StatusOK, duration)

		c.Header("Cache-Control", "public, max-age=60") // Cache for 1 minute when unavailable
		c.JSON(http.StatusOK, federationList)
		return
	}

	// Return federation list as JSON per spec Section 8.2.2
	now := time.Now()
	federationList := gin.H{
		"iss":             decodedTrustAnchor,
		"sub":             decodedTrustAnchor,
		"iat":             now.Unix(),
		"exp":             now.Add(24 * time.Hour).Unix(),
		"federation_list": federationMembers,
		"metadata": gin.H{
			"federation_entity": gin.H{
				"federation_list_endpoint": true,
			},
		},
	}

	duration := time.Since(start)
	metrics.RecordHTTPRequest("GET", "/federation_list", http.StatusOK, duration)

	c.Header("Cache-Control", "public, max-age=3600") // Cache for 1 hour
	c.JSON(http.StatusOK, federationList)
}

// collectFederationMembers collects entities that are part of the federation
// In a real implementation, this would query a database maintained by the trust anchor
func collectFederationMembers(ctx context.Context, trustAnchor string) ([]string, error) {
	// For now, we'll collect entities from the cache that were resolved via this trust anchor
	// This is a simplified implementation - in production, trust anchors maintain
	// authoritative lists of federation members

	members := []string{trustAnchor} // Trust anchor is always a member

	// Include all cached entities that were resolved via this trust anchor
	// This is more comprehensive than just looking at trust chains
	cachedEntities := fedResolver.ListCachedEntities()
	for _, entity := range cachedEntities {
		// Check if this entity was resolved via our trust anchor
		// We can determine this by checking if the trust anchor appears in the entity's
		// authority hints or if it was fetched from the trust anchor
		if entity.TrustAnchor == trustAnchor || strings.Contains(entity.FetchedFrom, trustAnchor) {
			// Add the entity if not already present and not the trust anchor itself
			if entity.EntityID != trustAnchor {
				found := false
				for _, member := range members {
					if member == entity.EntityID {
						found = true
						break
					}
				}
				if !found {
					members = append(members, entity.EntityID)
				}
			}
		}
	}

	// Also try to get some entities from trust chains (this is approximate)
	// In a real implementation, this would be a proper database query
	chains := fedResolver.ListCachedChains()
	for _, chain := range chains {
		if chain.TrustAnchor == trustAnchor {
			// Add the leaf entity if not already present
			if chain.EntityID != trustAnchor {
				found := false
				for _, member := range members {
					if member == chain.EntityID {
						found = true
						break
					}
				}
				if !found {
					members = append(members, chain.EntityID)
				}
			}
		}
	}

	log.Printf("[FEDERATION_LIST] Collected %d federation members for trust anchor %s", len(members), trustAnchor)
	return members, nil
}

// Cache management handlers

func cacheStatsHandler(c *gin.Context) {
	stats := fedResolver.GetCacheStats()
	c.JSON(http.StatusOK, gin.H{
		"cache_stats": stats,
		"timestamp":   time.Now(),
	})
}

func listCachedEntitiesHandler(c *gin.Context) {
	entities := fedResolver.ListCachedEntities()
	c.JSON(http.StatusOK, gin.H{
		"cached_entities": entities,
		"count":           len(entities),
		"timestamp":       time.Now(),
	})
}

func listCachedChainsHandler(c *gin.Context) {
	chains := fedResolver.ListCachedChains()
	c.JSON(http.StatusOK, gin.H{
		"cached_chains": chains,
		"count":         len(chains),
		"timestamp":     time.Now(),
	})
}

func clearEntityCacheHandler(c *gin.Context) {
	fedResolver.ClearEntityCache()
	c.JSON(http.StatusOK, gin.H{
		"message":   "Entity cache cleared",
		"timestamp": time.Now(),
	})
}

func clearChainCacheHandler(c *gin.Context) {
	fedResolver.ClearChainCache()
	c.JSON(http.StatusOK, gin.H{
		"message":   "Trust chain cache cleared",
		"timestamp": time.Now(),
	})
}

func clearAllCachesHandler(c *gin.Context) {
	fedResolver.ClearAllCaches()
	c.JSON(http.StatusOK, gin.H{
		"message":   "All caches cleared",
		"timestamp": time.Now(),
	})
}

func removeCachedEntityHandler(c *gin.Context) {
	entityID := c.Param("entityId")
	entityID = strings.TrimPrefix(entityID, "/")

	decodedEntityID, err := url.QueryUnescape(entityID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid entity ID"})
		return
	}

	trustAnchor := c.Query("trust_anchor")

	var removed bool
	if trustAnchor != "" {
		decodedTrustAnchor, err := url.QueryUnescape(trustAnchor)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid trust anchor"})
			return
		}
		removed = fedResolver.RemoveCachedEntity(decodedEntityID, decodedTrustAnchor)
	} else {
		removed = fedResolver.RemoveCachedEntityAny(decodedEntityID)
	}

	if removed {
		c.JSON(http.StatusOK, gin.H{
			"message":   "Entity removed from cache",
			"entity_id": decodedEntityID,
			"timestamp": time.Now(),
		})
	} else {
		c.JSON(http.StatusNotFound, gin.H{
			"error":     "Entity not found in cache",
			"entity_id": decodedEntityID,
		})
	}
}

func removeCachedChainHandler(c *gin.Context) {
	entityID := c.Param("entityId")
	entityID = strings.TrimPrefix(entityID, "/")

	decodedEntityID, err := url.QueryUnescape(entityID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid entity ID"})
		return
	}

	removed := fedResolver.RemoveCachedChain(decodedEntityID)

	if removed {
		c.JSON(http.StatusOK, gin.H{
			"message":   "Trust chain removed from cache",
			"entity_id": decodedEntityID,
			"timestamp": time.Now(),
		})
	} else {
		c.JSON(http.StatusNotFound, gin.H{
			"error":     "Trust chain not found in cache",
			"entity_id": decodedEntityID,
		})
	}
}

// Update testResolveHandler with metrics
func testResolveHandler(c *gin.Context) {
	start := time.Now()
	entityID := c.Param("entityId")

	// Strip leading slash from wildcard parameter
	entityID = strings.TrimPrefix(entityID, "/")

	decodedEntityID, err := url.QueryUnescape(entityID)
	if err != nil {
		metrics.RecordError("invalid_entity_id", "test_resolve")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid entity ID"})
		return
	}

	results := make(map[string]interface{})
	successCount := 0

	for _, ta := range config.TrustAnchors {
		taStart := time.Now()
		ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
		statement, err := fedResolver.ResolveEntity(ctx, decodedEntityID, ta, true)
		cancel()
		taDuration := time.Since(taStart)

		if err != nil {
			metrics.RecordEntityResolution(decodedEntityID, ta, "error", taDuration)
			results[ta] = gin.H{"error": err.Error()}
		} else {
			metrics.RecordEntityResolution(decodedEntityID, ta, "success", taDuration)
			successCount++
			results[ta] = gin.H{
				"success":      true,
				"issuer":       statement.Issuer,
				"subject":      statement.Subject,
				"fetched_from": statement.FetchedFrom,
			}
		}
	}

	// Record overall test metrics
	duration := time.Since(start)
	if successCount > 0 {
		metrics.RecordEntityResolution(decodedEntityID, "test", "success", duration)
	} else {
		metrics.RecordEntityResolution(decodedEntityID, "test", "error", duration)
	}

	c.JSON(http.StatusOK, gin.H{
		"entity_id":     decodedEntityID,
		"results":       results,
		"success_count": successCount,
		"total_tested":  len(config.TrustAnchors),
	})
}

// Cached entity inspection
func getCachedEntityHandler(c *gin.Context) {
	entityID := c.Param("entityId")
	entityID = strings.TrimPrefix(entityID, "/")

	decodedEntityID, err := url.QueryUnescape(entityID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid entity ID"})
		return
	}

	trustAnchor := c.Query("trust_anchor")

	var statement *resolver.CachedEntityStatement
	var found bool

	if trustAnchor != "" {
		decodedTrustAnchor, err := url.QueryUnescape(trustAnchor)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid trust anchor"})
			return
		}
		statement, found = fedResolver.GetCachedEntity(decodedEntityID, decodedTrustAnchor)
	} else {
		statement, found = fedResolver.GetCachedEntityAny(decodedEntityID)
	}

	if !found {
		c.JSON(http.StatusNotFound, gin.H{
			"error":     "Entity not found in cache",
			"entity_id": decodedEntityID,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"entity_id":     decodedEntityID,
		"trust_anchor":  trustAnchor,
		"statement":     statement.Statement,
		"issuer":        statement.Issuer,
		"subject":       statement.Subject,
		"issued_at":     statement.IssuedAt,
		"expires_at":    statement.ExpiresAt,
		"cached_at":     statement.CachedAt,
		"fetched_from":  statement.FetchedFrom,
		"validated":     statement.Validated,
		"parsed_claims": statement.ParsedClaims,
	})
}

// Cached trust chain inspection
func getCachedChainHandler(c *gin.Context) {
	entityID := c.Param("entityId")
	entityID = strings.TrimPrefix(entityID, "/")

	decodedEntityID, err := url.QueryUnescape(entityID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid entity ID"})
		return
	}

	chain, found := fedResolver.GetCachedChain(decodedEntityID)

	if !found {
		c.JSON(http.StatusNotFound, gin.H{
			"error":     "Trust chain not found in cache",
			"entity_id": decodedEntityID,
		})
		return
	}

	c.JSON(http.StatusOK, chain)
}

// Main page handler
func mainPageHandler(c *gin.Context) {
	cacheStats := fedResolver.GetCacheStats()

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Federation Resolver - Cache Management</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .hero-section {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 30px;
            text-align: center;
        }
        
        .hero-section h2 {
            margin: 0 0 10px 0;
            font-size: 28px;
            font-weight: 300;
        }
        
        .hero-section p {
            margin: 0 0 30px 0;
            font-size: 16px;
            opacity: 0.9;
        }
        
        .quick-actions {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .action-card {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .action-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
        }
        
        .action-card h3 {
            margin: 0 0 10px 0;
            font-size: 18px;
            font-weight: 600;
        }
        
        .action-card p {
            margin: 0 0 15px 0;
            font-size: 14px;
            opacity: 0.8;
        }
        
        .action-form {
            display: flex;
            gap: 10px;
            align-items: center;
            justify-content: center;
        }
        
        .action-form input, .action-form select {
            flex: 1;
            padding: 8px 12px;
            border: 1px solid rgba(255, 255, 255, 0.3);
            border-radius: 6px;
            background: rgba(255, 255, 255, 0.9);
            color: #333;
            font-size: 14px;
        }
        
        .primary-btn {
            background: #28a745;
            color: white;
            border: none;
            padding: 10px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: background 0.2s;
        }
        
        .primary-btn:hover {
            background: #218838;
        }
        
        .result-display {
            background: white;
            border: 2px solid #007acc;
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }
        
        .result-display h3 {
            margin: 0 0 15px 0;
            color: #007acc;
            font-size: 18px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .result-content {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 6px;
            padding: 15px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 12px;
            white-space: pre-wrap;
            max-height: 500px;
            overflow-y: auto;
            line-height: 1.4;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            border-left: 4px solid #007acc;
            text-align: center;
        }
        .stat-card h3 {
            margin: 0 0 10px 0;
            color: #333;
            font-size: 14px;
        }
        .stat-value {
            font-size: 36px;
            font-weight: bold;
            color: #007acc;
        }
        .actions {
            margin: 30px 0;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            justify-content: center;
        }
        button {
            background: #007acc;
            color: white;
            border: none;
            padding: 12px 20px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            min-width: 120px;
        }
        button:hover {
            background: #005aa3;
        }
        button.danger {
            background: #dc3545;
        }
        button.danger:hover {
            background: #c82333;
        }
        .inspect-section {
            margin: 30px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
            border: 1px solid #dee2e6;
        }
        .inspect-section h2 {
            margin: 0 0 15px 0;
            color: #333;
            font-size: 18px;
        }
        .inspect-form {
            display: flex;
            gap: 10px;
            align-items: center;
            margin: 15px 0;
        }
        input[type="text"] {
            flex: 1;
            padding: 8px 12px;
            border: 1px solid #ccc;
            border-radius: 4px;
            font-size: 14px;
        }
        .inspect-result {
            margin: 15px 0;
            padding: 15px;
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            font-family: monospace;
            font-size: 12px;
            white-space: pre-wrap;
            max-height: 400px;
            overflow-y: auto;
            display: none;
        }
        .info {
            background: #e7f3ff;
            border: 1px solid #b3d7ff;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
        }
        .info h3 {
            margin: 0 0 10px 0;
            color: #0066cc;
        }
        .api-endpoints {
            font-family: monospace;
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
        }
        .refresh {
            background: #28a745;
        }
        .refresh:hover {
            background: #218838;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>OpenID Federation Resolver</h1>
        
        <div class="hero-section">
            <h2>🔍 Federation Discovery & Resolution</h2>
            <p>Discover federation members, resolve entities, and validate trust chains across OpenID Federation networks.</p>
            
            <div class="quick-actions">
                <div class="action-card">
                    <h3>📋 Federation List</h3>
                    <p>Get the complete list of entities in a federation</p>
                    <div class="action-form">
                        <select id="federationListTA" onchange="updateFederationListURL()">
                            <option value="">Select Trust Anchor...</option>
                        </select>
                        <button onclick="testFederationList()" class="primary-btn">Get Federation List</button>
                    </div>
                </div>
                
                <div class="action-card">
                    <h3>🔗 Entity Resolution</h3>
                    <p>Resolve OpenID Federation entities</p>
                    <div class="action-form">
                        <input type="text" id="quickResolveEntity" placeholder="https://entity.example.com" />
                        <button onclick="quickResolveEntity()" class="primary-btn">Resolve Entity</button>
                    </div>
                </div>
                
                <div class="action-card">
                    <h3>⛓️ Trust Chain</h3>
                    <p>Build and validate trust chains</p>
                    <div class="action-form">
                        <input type="text" id="quickTrustChain" placeholder="https://entity.example.com" />
                        <button onclick="quickTrustChain()" class="primary-btn">Get Trust Chain</button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Federation List Results -->
        <div id="federationListResult" class="result-display" style="display: none;">
            <h3>📋 Federation List Results</h3>
            <div class="result-content"></div>
        </div>

        <!-- Quick Resolution Results -->
        <div id="quickResolveResult" class="result-display" style="display: none;">
            <h3>🔗 Entity Resolution Results</h3>
            <div class="result-content"></div>
        </div>

        <!-- Trust Chain Results -->
        <div id="quickTrustChainResult" class="result-display" style="display: none;">
            <h3>⛓️ Trust Chain Results</h3>
            <div class="result-content"></div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>Entity Cache Size</h3>
                <div class="stat-value">` + fmt.Sprintf("%d", cacheStats["entity_cache_size"]) + `</div>
            </div>
            <div class="stat-card">
                <h3>Trust Chain Cache Size</h3>
                <div class="stat-value">` + fmt.Sprintf("%d", cacheStats["chain_cache_size"]) + `</div>
            </div>
            <div class="stat-card">
                <h3>Total Cached Items</h3>
                <div class="stat-value">` + fmt.Sprintf("%d", cacheStats["entity_cache_size"].(int)+cacheStats["chain_cache_size"].(int)) + `</div>
            </div>
        </div>

        <div class="actions">
            <button onclick="clearAllCaches()">Clear All Caches</button>
            <button onclick="clearEntityCache()">Clear Entity Cache</button>
            <button onclick="clearChainCache()">Clear Trust Chain Cache</button>
            <button class="refresh" onclick="location.reload()">Refresh Stats</button>
        </div>

        <div class="inspect-section">
            <h2>Inspect Cached Entity</h2>
            <div class="inspect-form">
                <input type="text" id="inspectEntityId" placeholder="Enter entity ID (e.g., https://example.com)" />
                <input type="text" id="inspectEntityTA" placeholder="Trust anchor (optional)" />
                <button onclick="inspectEntity()">Inspect Entity</button>
                <button class="danger" onclick="removeEntity()">Remove Entity</button>
            </div>
            <div id="entityResult" class="inspect-result"></div>
        </div>

        <div class="inspect-section">
            <h2>Inspect Cached Trust Chain</h2>
            <div class="inspect-form">
                <input type="text" id="inspectChainId" placeholder="Enter entity ID (e.g., https://example.com)" />
                <button onclick="inspectChain()">Inspect Chain</button>
                <button class="danger" onclick="removeChain()">Remove Chain</button>
            </div>
            <div id="chainResult" class="inspect-result"></div>
        </div>

        <div class="info">
            <div class="api-endpoints">
GET  /api/v1/cache/stats                    - Get cache statistics<br>
GET  /api/v1/cache/entities                 - List cached entities<br>
GET  /api/v1/cache/chains                   - List cached trust chains<br>
GET  /api/v1/cache/entity/{id}?trust_anchor={ta} - Inspect specific cached entity<br>
GET  /api/v1/cache/chain/{id}               - Inspect specific cached trust chain<br>
POST /api/v1/cache/clear-entities           - Clear entity cache<br>
POST /api/v1/cache/clear-chains             - Clear trust chain cache<br>
POST /api/v1/cache/clear-all                - Clear all caches<br>
DELETE /api/v1/cache/entity/{id}            - Remove specific entity<br>
DELETE /api/v1/cache/chain/{id}             - Remove specific trust chain
            </div>
        </div>

        <div class="info">
            <h3>Resolution Endpoints</h3>
            <div class="api-endpoints">
GET /api/v1/entity/{entity_id}?trust_anchor={ta} - Resolve entity<br>
GET /api/v1/trust-chain/{entity_id}               - Resolve trust chain<br>
GET /api/v1/federation_list?trust_anchor={ta}     - Get federation member list<br>
GET /api/v1/test/resolve/{entity_id}              - Test resolution via all trust anchors<br>
GET /health                                       - Health check<br>
GET /metrics                                      - Prometheus metrics
            </div>
        </div>
    </div>

    <script>
        // Load trust anchors on page load
        document.addEventListener('DOMContentLoaded', function() {
            loadTrustAnchors();
        });

        async function loadTrustAnchors() {
            try {
                const response = await fetch('/api/v1/trust-anchors');
                if (response.ok) {
                    const data = await response.json();
                    const selects = ['federationListTA'];
                    
                    selects.forEach(selectId => {
                        const select = document.getElementById(selectId);
                        // Clear existing options except first
                        while (select.options.length > 1) {
                            select.remove(1);
                        }
                        
                        data.trust_anchors.forEach(ta => {
                            const option = document.createElement('option');
                            option.value = ta;
                            option.textContent = ta;
                            select.appendChild(option);
                        });
                    });
                }
            } catch (error) {
                console.error('Failed to load trust anchors:', error);
            }
        }

        function updateFederationListURL() {
            // Could update a URL display if needed
        }

        async function quickResolveEntity() {
            const entityId = document.getElementById('quickResolveEntity').value.trim();
            
            if (!entityId) {
                alert('Please enter an entity ID');
                return;
            }

            try {
                const response = await fetch('/api/v1/entity/' + encodeURIComponent(entityId));
                const resultDiv = document.getElementById('quickResolveResult');
                const contentDiv = resultDiv.querySelector('.result-content');
                
                if (response.ok) {
                    const data = await response.json();
                    contentDiv.textContent = JSON.stringify(data, null, 2);
                    resultDiv.style.display = 'block';
                    resultDiv.scrollIntoView({ behavior: 'smooth' });
                } else {
                    const error = await response.json();
                    contentDiv.textContent = 'Error: ' + JSON.stringify(error, null, 2);
                    resultDiv.style.display = 'block';
                    resultDiv.scrollIntoView({ behavior: 'smooth' });
                }
            } catch (error) {
                const resultDiv = document.getElementById('quickResolveResult');
                const contentDiv = resultDiv.querySelector('.result-content');
                contentDiv.textContent = 'Error: ' + error.message;
                resultDiv.style.display = 'block';
                resultDiv.scrollIntoView({ behavior: 'smooth' });
            }
        }

        async function quickTrustChain() {
            const entityId = document.getElementById('quickTrustChain').value.trim();
            
            if (!entityId) {
                alert('Please enter an entity ID');
                return;
            }

            try {
                const response = await fetch('/api/v1/trust-chain/' + encodeURIComponent(entityId));
                const resultDiv = document.getElementById('quickTrustChainResult');
                const contentDiv = resultDiv.querySelector('.result-content');
                
                if (response.ok) {
                    const data = await response.json();
                    contentDiv.textContent = JSON.stringify(data, null, 2);
                    resultDiv.style.display = 'block';
                    resultDiv.scrollIntoView({ behavior: 'smooth' });
                } else {
                    const error = await response.json();
                    contentDiv.textContent = 'Error: ' + JSON.stringify(error, null, 2);
                    resultDiv.style.display = 'block';
                    resultDiv.scrollIntoView({ behavior: 'smooth' });
                }
            } catch (error) {
                const resultDiv = document.getElementById('quickTrustChainResult');
                const contentDiv = resultDiv.querySelector('.result-content');
                contentDiv.textContent = 'Error: ' + error.message;
                resultDiv.style.display = 'block';
                resultDiv.scrollIntoView({ behavior: 'smooth' });
            }
        }
        async function clearAllCaches() {
            if (confirm('Are you sure you want to clear all caches? This will force fresh resolution of all entities.')) {
                try {
                    const response = await fetch('/api/v1/cache/clear-all', { method: 'POST' });
                    if (response.ok) {
                        alert('All caches cleared successfully');
                        location.reload();
                    } else {
                        alert('Failed to clear caches');
                    }
                } catch (error) {
                    alert('Error: ' + error.message);
                }
            }
        }

        async function clearEntityCache() {
            if (confirm('Are you sure you want to clear the entity cache?')) {
                try {
                    const response = await fetch('/api/v1/cache/clear-entities', { method: 'POST' });
                    if (response.ok) {
                        alert('Entity cache cleared successfully');
                        location.reload();
                    } else {
                        alert('Failed to clear entity cache');
                    }
                } catch (error) {
                    alert('Error: ' + error.message);
                }
            }
        }

        async function clearChainCache() {
            if (confirm('Are you sure you want to clear the trust chain cache?')) {
                try {
                    const response = await fetch('/api/v1/cache/clear-chains', { method: 'POST' });
                    if (response.ok) {
                        alert('Trust chain cache cleared successfully');
                        location.reload();
                    } else {
                        alert('Failed to clear trust chain cache');
                    }
                } catch (error) {
                    alert('Error: ' + error.message);
                }
            }
        }

        async function inspectEntity() {
            const entityId = document.getElementById('inspectEntityId').value.trim();
            const trustAnchor = document.getElementById('inspectEntityTA').value.trim();
            
            if (!entityId) {
                alert('Please enter an entity ID');
                return;
            }

            try {
                let url = '/api/v1/cache/entity/' + encodeURIComponent(entityId);
                if (trustAnchor) {
                    url += '?trust_anchor=' + encodeURIComponent(trustAnchor);
                }
                
                const response = await fetch(url);
                const resultDiv = document.getElementById('entityResult');
                
                if (response.ok) {
                    const data = await response.json();
                    resultDiv.textContent = JSON.stringify(data, null, 2);
                    resultDiv.style.display = 'block';
                } else {
                    const error = await response.json();
                    resultDiv.textContent = 'Error: ' + error.error;
                    resultDiv.style.display = 'block';
                }
            } catch (error) {
                document.getElementById('entityResult').textContent = 'Error: ' + error.message;
                document.getElementById('entityResult').style.display = 'block';
            }
        }

        async function inspectChain() {
            const entityId = document.getElementById('inspectChainId').value.trim();
            
            if (!entityId) {
                alert('Please enter an entity ID');
                return;
            }

            try {
                const response = await fetch('/api/v1/cache/chain/' + encodeURIComponent(entityId));
                const resultDiv = document.getElementById('chainResult');
                
                if (response.ok) {
                    const data = await response.json();
                    resultDiv.textContent = JSON.stringify(data, null, 2);
                    resultDiv.style.display = 'block';
                } else {
                    const error = await response.json();
                    resultDiv.textContent = 'Error: ' + error.error;
                    resultDiv.style.display = 'block';
                }
            } catch (error) {
                document.getElementById('chainResult').textContent = 'Error: ' + error.message;
                document.getElementById('chainResult').style.display = 'block';
            }
        }

        async function removeEntity() {
            const entityId = document.getElementById('inspectEntityId').value.trim();
            const trustAnchor = document.getElementById('inspectEntityTA').value.trim();
            
            if (!entityId) {
                alert('Please enter an entity ID');
                return;
            }

            if (!confirm('Are you sure you want to remove entity "' + entityId + '" from cache?')) {
                return;
            }

            try {
                let url = '/api/v1/cache/entity/' + encodeURIComponent(entityId);
                if (trustAnchor) {
                    url += '?trust_anchor=' + encodeURIComponent(trustAnchor);
                }
                
                const response = await fetch(url, { method: 'DELETE' });
                
                if (response.ok) {
                    alert('Entity removed from cache successfully');
                    document.getElementById('entityResult').style.display = 'none';
                    location.reload();
                } else {
                    const error = await response.json();
                    alert('Failed to remove entity: ' + error.error);
                }
            } catch (error) {
                alert('Error: ' + error.message);
            }
        }

        async function removeChain() {
            const entityId = document.getElementById('inspectChainId').value.trim();
            
            if (!entityId) {
                alert('Please enter an entity ID');
                return;
            }

            if (!confirm('Are you sure you want to remove trust chain for "' + entityId + '" from cache?')) {
                return;
            }

            try {
                const response = await fetch('/api/v1/cache/chain/' + encodeURIComponent(entityId), { method: 'DELETE' });
                
                if (response.ok) {
                    alert('Trust chain removed from cache successfully');
                    document.getElementById('chainResult').style.display = 'none';
                    location.reload();
                } else {
                    const error = await response.json();
                    alert('Failed to remove trust chain: ' + error.error);
                }
            } catch (error) {
                alert('Error: ' + error.message);
            }
        }

        async function testFederationList() {
            const trustAnchor = document.getElementById('federationListTA').value.trim();
            
            if (!trustAnchor) {
                alert('Please select a trust anchor');
                return;
            }

            try {
                const response = await fetch('/api/v1/federation_list?trust_anchor=' + encodeURIComponent(trustAnchor));
                const resultDiv = document.getElementById('federationListResult');
                const contentDiv = resultDiv.querySelector('.result-content');
                
                if (response.ok) {
                    const data = await response.json();
                    contentDiv.textContent = JSON.stringify(data, null, 2);
                    resultDiv.style.display = 'block';
                    resultDiv.scrollIntoView({ behavior: 'smooth' });
                } else {
                    const error = await response.json();
                    contentDiv.textContent = 'Error: ' + JSON.stringify(error, null, 2);
                    resultDiv.style.display = 'block';
                    resultDiv.scrollIntoView({ behavior: 'smooth' });
                }
            } catch (error) {
                const resultDiv = document.getElementById('federationListResult');
                const contentDiv = resultDiv.querySelector('.result-content');
                contentDiv.textContent = 'Error: ' + error.message;
                resultDiv.style.display = 'block';
                resultDiv.scrollIntoView({ behavior: 'smooth' });
            }
        }
    </script>
</body>
</html>`

	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, html)
}

// Trust Anchor Registration Handler
func registerTrustAnchorHandler(c *gin.Context) {
	var registration resolver.TrustAnchorRegistration

	if err := c.ShouldBindJSON(&registration); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid registration request",
			"details": err.Error(),
		})
		return
	}

	// Validate the registration JWT
	if err := validateTrustAnchorRegistrationJWT(&registration); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid registration JWT",
			"details": err.Error(),
		})
		return
	}

	// Register the trust anchor with the resolver
	if err := fedResolver.RegisterTrustAnchor(&registration); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to register trust anchor",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Trust anchor registered successfully",
		"entity_id":  registration.EntityID,
		"expires_at": registration.ExpiresAt,
	})
}

// List registered trust anchors
func listRegisteredTrustAnchorsHandler(c *gin.Context) {
	anchors := fedResolver.ListRegisteredTrustAnchors()

	c.JSON(http.StatusOK, gin.H{
		"registered_trust_anchors": anchors,
		"count":                    len(anchors),
	})
}

// Unregister trust anchor
func unregisterTrustAnchorHandler(c *gin.Context) {
	entityID := c.Param("entityId")
	entityID = strings.TrimPrefix(entityID, "/")

	decodedEntityID, err := url.QueryUnescape(entityID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid entity ID"})
		return
	}

	if err := fedResolver.UnregisterTrustAnchor(decodedEntityID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Trust anchor not found or failed to unregister",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "Trust anchor unregistered successfully",
		"entity_id": decodedEntityID,
	})
}

// Validate trust anchor registration JWT
func validateTrustAnchorRegistrationJWT(registration *resolver.TrustAnchorRegistration) error {
	if registration.RegistrationJWT == "" {
		return fmt.Errorf("registration_jwt is required")
	}

	// Parse the JWT without verification first to extract claims
	token, err := jwt.Parse(registration.RegistrationJWT, func(token *jwt.Token) (interface{}, error) {
		// We'll return the key after extracting it from the token itself
		return nil, nil
	})

	if err != nil {
		// Try to parse without verification to get claims
		parser := jwt.NewParser(jwt.WithoutClaimsValidation())
		token, _, err = parser.ParseUnverified(registration.RegistrationJWT, jwt.MapClaims{})
		if err != nil {
			return fmt.Errorf("failed to parse JWT: %w", err)
		}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid JWT claims")
	}

	// Validate basic JWT structure
	issuer, ok := claims["iss"].(string)
	if !ok {
		return fmt.Errorf("missing or invalid issuer claim")
	}

	subject, ok := claims["sub"].(string)
	if !ok {
		return fmt.Errorf("missing or invalid subject claim")
	}

	// For trust anchor self-signed entity statements, iss should equal sub
	if issuer != subject {
		return fmt.Errorf("for trust anchor entity statements, issuer must equal subject")
	}

	// Validate issuer matches the entity ID
	if issuer != registration.EntityID {
		return fmt.Errorf("issuer %s does not match entity_id %s", issuer, registration.EntityID)
	}

	// Check expiration
	if exp, ok := claims["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		if time.Now().After(expTime) {
			return fmt.Errorf("JWT has expired")
		}
	} else {
		return fmt.Errorf("missing or invalid expiration claim")
	}

	// Check issued at time
	if iat, ok := claims["iat"].(float64); ok {
		issuedAt := time.Unix(int64(iat), 0)
		if time.Now().Before(issuedAt) {
			return fmt.Errorf("JWT issued in the future")
		}
	} else {
		return fmt.Errorf("missing or invalid issued at claim")
	}

	// Extract JWKS from the entity statement
	jwks, err := extractJWKSFromEntityStatement(claims)
	if err != nil {
		return fmt.Errorf("failed to extract JWKS: %w", err)
	}

	// Validate JWT signature using the extracted public keys
	err = validateJWTSignatureWithJWKS(registration.RegistrationJWT, jwks)
	if err != nil {
		return fmt.Errorf("JWT signature validation failed: %w", err)
	}

	// Store the extracted JWKS for later use
	registration.SigningKeys = jwks

	// Extract metadata if present
	if metadata, ok := claims["metadata"].(map[string]interface{}); ok {
		registration.Metadata = metadata
	}

	log.Printf("[RESOLVER] Successfully validated trust anchor registration JWT for %s", registration.EntityID)
	return nil
}

// Extract JWKS from entity statement claims
func extractJWKSFromEntityStatement(claims jwt.MapClaims) (*resolver.JWKSet, error) {
	// Try to find JWKS in metadata.federation_entity.jwks
	if metadata, ok := claims["metadata"].(map[string]interface{}); ok {
		if fedEntity, ok := metadata["federation_entity"].(map[string]interface{}); ok {
			if jwksRaw, ok := fedEntity["jwks"].(map[string]interface{}); ok {
				return parseJWKSFromMap(jwksRaw)
			}
		}
	}

	// Try to find JWKS at top level
	if jwksRaw, ok := claims["jwks"].(map[string]interface{}); ok {
		return parseJWKSFromMap(jwksRaw)
	}

	return nil, fmt.Errorf("no JWKS found in entity statement")
}

// Parse JWKS from a map
func parseJWKSFromMap(jwksMap map[string]interface{}) (*resolver.JWKSet, error) {
	keysRaw, ok := jwksMap["keys"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid JWKS structure: missing keys array")
	}

	jwks := &resolver.JWKSet{
		Keys: make([]resolver.JWK, 0, len(keysRaw)),
	}

	for _, keyRaw := range keysRaw {
		keyMap, ok := keyRaw.(map[string]interface{})
		if !ok {
			continue // Skip invalid keys
		}

		jwk := resolver.JWK{}

		if kty, ok := keyMap["kty"].(string); ok {
			jwk.KeyType = kty
		}
		if use, ok := keyMap["use"].(string); ok {
			jwk.Use = use
		}
		if kid, ok := keyMap["kid"].(string); ok {
			jwk.KeyID = kid
		}
		if alg, ok := keyMap["alg"].(string); ok {
			jwk.Algorithm = alg
		}
		if n, ok := keyMap["n"].(string); ok {
			jwk.Modulus = n
		}
		if e, ok := keyMap["e"].(string); ok {
			jwk.Exponent = e
		}
		if crv, ok := keyMap["crv"].(string); ok {
			jwk.Curve = crv
		}
		if x, ok := keyMap["x"].(string); ok {
			jwk.XCoordinate = x
		}
		if y, ok := keyMap["y"].(string); ok {
			jwk.YCoordinate = y
		}

		jwks.Keys = append(jwks.Keys, jwk)
	}

	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("no valid keys found in JWKS")
	}

	return jwks, nil
}

// Validate JWT signature using JWKS
func validateJWTSignatureWithJWKS(tokenString string, jwks *resolver.JWKSet) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Find the key ID from the JWT header
		var keyID string
		if kid, ok := token.Header["kid"].(string); ok {
			keyID = kid
		}

		// Find matching key in JWKS
		for _, jwk := range jwks.Keys {
			if keyID == "" || jwk.KeyID == keyID {
				// Convert JWK to public key based on key type
				switch jwk.KeyType {
				case "RSA":
					return jwkToRSAPublicKey(&jwk)
				case "EC":
					return jwkToECPublicKey(&jwk)
				default:
					continue // Try next key
				}
			}
		}

		return nil, fmt.Errorf("no suitable key found for signature verification")
	})

	if err != nil {
		return err
	}

	if !token.Valid {
		return fmt.Errorf("invalid JWT signature")
	}

	return nil
}

// Helper functions for JWK to public key conversion

// jwkToRSAPublicKey converts a JWK to RSA public key
func jwkToRSAPublicKey(jwk *resolver.JWK) (*rsa.PublicKey, error) {
	if jwk.KeyType != "RSA" {
		return nil, fmt.Errorf("unsupported key type: %s", jwk.KeyType)
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.Modulus)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.Exponent)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert exponent bytes to int
	var e int
	for _, b := range eBytes {
		e = e*256 + int(b)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}, nil
}

// jwkToECPublicKey converts a JWK to ECDSA public key
func jwkToECPublicKey(jwk *resolver.JWK) (*ecdsa.PublicKey, error) {
	if jwk.KeyType != "EC" {
		return nil, fmt.Errorf("unsupported key type: %s", jwk.KeyType)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.XCoordinate)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x coordinate: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.YCoordinate)
	if err != nil {
		return nil, fmt.Errorf("failed to decode y coordinate: %w", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	var curve elliptic.Curve
	switch jwk.Curve {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", jwk.Curve)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}
