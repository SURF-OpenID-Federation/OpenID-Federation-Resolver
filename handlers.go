package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"resolver/pkg/metrics"
	"resolver/pkg/resolver"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// resolverEntityStatementHandler returns the resolver's own entity statement
// This is required for clients to verify signatures created by the resolver
func resolverEntityStatementHandler(c *gin.Context) {
	// Get the resolver's entity statement
	entityStatement, err := fedResolver.GetResolverEntityStatementWithContext(c.Request.Context())
	if err != nil {
		log.Printf("[RESOLVER] Failed to get entity statement: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to generate resolver entity statement",
		})
		return
	}

	// Return the signed entity statement as a JWT
	c.Header("Content-Type", "application/entity-statement+jwt")
	c.String(http.StatusOK, entityStatement)
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
			writeEntityResolveError(c, decodedEntityID, err)
			return
		}

		metrics.RecordEntityResolution(decodedEntityID, decodedTrustAnchor, "success", time.Since(start))

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
			writeEntityResolveError(c, decodedEntityID, err)
			return
		}

		// Record successful resolution
		metrics.RecordEntityResolution(decodedEntityID, "any", "success", time.Since(start))

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

func writeEntityResolveError(c *gin.Context, entityID string, err error) {
	status := http.StatusNotFound
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		status = http.StatusGatewayTimeout
	}
	c.JSON(status, gin.H{
		"error":     "Failed to resolve entity",
		"details":   err.Error(),
		"entity_id": entityID,
	})
}

// Raw entity statement endpoint - returns the JWT directly with proper Content-Type
// This is useful for federation browsers that expect a raw JWT, not JSON-wrapped
func resolveEntityRawHandler(c *gin.Context) {
	start := time.Now()
	entityID := c.Param("entityId")

	// Strip leading slash from wildcard parameter
	entityID = strings.TrimPrefix(entityID, "/")

	// URL decode
	decodedEntityID, err := url.QueryUnescape(entityID)
	if err != nil {
		metrics.RecordError("invalid_entity_id", "resolve_entity_raw")
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
			metrics.RecordError("invalid_trust_anchor", "resolve_entity_raw")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid trust anchor"})
			return
		}

		statement, err = fedResolver.ResolveEntity(ctx, decodedEntityID, decodedTrustAnchor, forceRefresh)
		if err != nil {
			metrics.RecordEntityResolution(decodedEntityID, decodedTrustAnchor, "error", time.Since(start))
			metrics.RecordError("entity_resolution_failed", "resolve_entity_raw")
			writeEntityResolveError(c, decodedEntityID, err)
			return
		}

		metrics.RecordEntityResolution(decodedEntityID, decodedTrustAnchor, "success", time.Since(start))
	} else {
		// Try to resolve through any trust anchor
		statement, err = fedResolver.ResolveEntityAny(ctx, decodedEntityID, forceRefresh)
		if err != nil {
			metrics.RecordEntityResolution(decodedEntityID, "any", "error", time.Since(start))
			metrics.RecordError("entity_resolution_failed", "resolve_entity_raw")
			writeEntityResolveError(c, decodedEntityID, err)
			return
		}

		metrics.RecordEntityResolution(decodedEntityID, "any", "success", time.Since(start))
	}

	// Return raw JWT with proper Content-Type
	c.Header("Content-Type", "application/entity-statement+jwt")
	c.String(http.StatusOK, statement.Statement)
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
		decodedTrustAnchor, uerr := url.QueryUnescape(trustAnchor)
		if uerr != nil {
			metrics.RecordError("invalid_trust_anchor", "resolve_trust_chain")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid trust anchor"})
			return
		}

		// Resolve with specific trust anchor
		trustChain, err = fedResolver.ResolveTrustChainWithAnchor(ctx, decodedEntityID, decodedTrustAnchor, forceRefresh)

		log.Printf("[RESOLVER] Resolved trust chain for %s via trust anchor %s, chain: %v", decodedEntityID, decodedTrustAnchor, trustChain)

		// If resolver is authorized for this trust anchor and no raw response requested,
		// return signed JWT response per OpenID Federation spec
		if err == nil && !rawResponse {
			if fedResolver.IsAuthorizedForTrustAnchor(decodedTrustAnchor) {
				signedResponse, signErr := fedResolver.CreateSignedTrustChainResponseWithContext(ctx, trustChain, decodedTrustAnchor)
				if signErr == nil {
					duration := time.Since(start)
					metrics.RecordTrustChainDiscovery(decodedEntityID, trustAnchor, "success", duration)

					// Return signed JWT response per OpenID Federation spec Section 8.3.2
					c.Header("Content-Type", "application/resolve-response+jwt")
					c.String(http.StatusOK, signedResponse)
					return
				}
				// If signing fails, fall back to raw response
				log.Printf("[RESOLVER] Failed to create signed response for %s: %v", decodedEntityID, signErr)
			} else {
				// Explicitly log when resolver is not authorized to sign for the requested TA — helps operator triage
				log.Printf("[RESOLVER] Not authorized to sign for trust anchor %s — returning raw JSON response", decodedTrustAnchor)
			}
		} else if rawResponse {
			log.Printf("[RESOLVER] raw=true requested; returning raw JSON response for %s", decodedEntityID)
		}
	} else {
		// Resolve with any trust anchor (existing behavior)
		trustChain, err = fedResolver.ResolveTrustChain(ctx, decodedEntityID, forceRefresh)
	}
	duration := time.Since(start)

	if err != nil || trustChain == nil {
		if err == nil {
			err = fmt.Errorf("empty trust chain")
		}
		metrics.RecordTrustChainDiscovery(decodedEntityID, trustAnchor, "error", duration)
		metrics.RecordError("trust_chain_resolution_failed", "resolve_trust_chain")
		status := http.StatusNotFound
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			status = http.StatusGatewayTimeout
		}
		c.JSON(status, gin.H{
			"error":   "Failed to resolve trust chain",
			"details": err.Error(),
		})
		return
	}

	metrics.RecordTrustChainDiscovery(decodedEntityID, trustAnchor, "success", duration)

	// Sanitize: collapse duplicate chain entries by normalized subject/entity
	if trustChain != nil {
		trustChain.Chain = resolver.DeduplicateCachedChain(trustChain.Chain)
	}

	// Return raw JSON response (fallback or when raw=true)
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
			"error":             "invalid_request",
			"error_description": "Missing required parameter 'sub' (entity identifier)",
		})
		return
	}

	if trustAnchor == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing required parameter 'trust_anchor'",
		})
		return
	}

	// Decode parameters
	decodedEntityID, err := url.QueryUnescape(entityID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid entity ID parameter",
		})
		return
	}

	decodedTrustAnchor, err := url.QueryUnescape(trustAnchor)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid trust anchor parameter",
		})
		return
	}

	// Check if resolver is authorized for this trust anchor
	if !fedResolver.IsAuthorizedForTrustAnchor(decodedTrustAnchor) {
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "invalid_trust_anchor",
			"error_description": "The Trust Anchor cannot be found or used",
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
			"error":             "not_found",
			"error_description": "The requested Entity Identifier cannot be found",
		})
		return
	}

	// Create signed response (required per spec Section 8.3.2)
	// Sanitize: collapse duplicate chain entries by normalized subject/entity
	if trustChain != nil {
		trustChain.Chain = resolver.DeduplicateCachedChain(trustChain.Chain)
	}

	signedResponse, err := fedResolver.CreateSignedTrustChainResponseWithContext(ctx, trustChain, decodedTrustAnchor)
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
	c.String(http.StatusOK, signedResponse)
}

func listTrustAnchorsHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"trust_anchors": config.TrustAnchors,
		"count":         len(config.TrustAnchors),
	})
}

// Debug: return cached trust chain details for an entity (if present)
func debugCachedChainHandler(c *gin.Context) {
	entityID := c.Param("entityId")
	entityID = strings.TrimPrefix(entityID, "/")
	decodedEntityID, err := url.QueryUnescape(entityID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_entity_id"})
		return
	}

	trustAnchor := c.Query("trust_anchor")

	chain, ok := fedResolver.GetCachedChainWithAnchor(decodedEntityID, trustAnchor)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "cached_chain_not_found", "entity_id": decodedEntityID})
		return
	}

	items := make([]gin.H, 0, len(chain.Chain))
	pairs := make([]string, 0, len(chain.Chain))
	for i, it := range chain.Chain {
		items = append(items, gin.H{
			"index":        i,
			"issuer":       it.Issuer,
			"subject":      it.Subject,
			"issued_at":    it.IssuedAt,
			"expires_at":   it.ExpiresAt,
			"fetched_from": it.FetchedFrom,
			"validated":    it.Validated,
		})
		pairs = append(pairs, fmt.Sprintf("%s|%s", it.Issuer, it.Subject))
	}

	uniq := make(map[string]struct{})
	for _, p := range pairs {
		uniq[p] = struct{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"entity_id":     decodedEntityID,
		"trust_anchor":  trustAnchor,
		"cached_chain":  true,
		"total_entries": len(chain.Chain),
		"unique_pairs":  len(uniq),
		"items":         items,
		"cached_at":     chain.CachedAt,
		"expires_at":    chain.ExpiresAt,
		"status":        chain.Status,
	})
}

// Federation List Endpoint
// Queries the trust anchor's federation_list_endpoint per OpenID Federation spec Section 8.2
func federationListHandler(c *gin.Context) {
	// Get required trust_anchor parameter per spec
	trustAnchor := c.Query("trust_anchor")
	if trustAnchor == "" {
		metrics.RecordError("missing_trust_anchor", "federation_list")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing required parameter 'trust_anchor'",
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
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid trust anchor parameter",
		})
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
			"error":             "invalid_trust_anchor",
			"error_description": "The Trust Anchor cannot be found or used",
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

	c.JSON(http.StatusOK, federationList)
}

// Federation Collection Endpoint
// Implements draft: https://zachmann.github.io/openid-federation-entity-collection/main.html

// collectEntitiesRecursively recursively collects all entities in the federation hierarchy
func collectEntitiesRecursively(ctx context.Context, fedResolver *resolver.FederationResolver, entityID, trustAnchor string, collected map[string]bool) {
	// Avoid infinite loops
	if collected[entityID] {
		return
	}

	log.Printf("[COLLECTION] Processing entity: %s", entityID)

	// Resolve the entity to check if it has a federation_list_endpoint
	entity, err := fedResolver.ResolveEntity(ctx, entityID, trustAnchor, false)
	if err != nil {
		log.Printf("[COLLECTION] Failed to resolve entity %s: %v", entityID, err)
		return
	}

	// Mark this entity as collected
	collected[entityID] = true

	// Extract the list endpoint
	listEndpoint, err := fedResolver.ExtractFederationListEndpoint(entity)
	if err != nil {
		log.Printf("[COLLECTION] ExtractFederationListEndpoint failed for %s: %v", entityID, err)
		// Fallback to boolean check
		if entity != nil && entity.ParsedClaims != nil {
			if metadata, ok := entity.ParsedClaims["metadata"].(map[string]interface{}); ok {
				if fed, ok := metadata["federation_entity"].(map[string]interface{}); ok {
					if enabled, ok := fed["federation_list_endpoint"].(bool); ok && enabled {
						listEndpoint = strings.TrimRight(entityID, "/") + "/list"
					}
				}
			}
		}
	}

	log.Printf("[COLLECTION] Entity %s has list endpoint: %s", entityID, listEndpoint)

	// If no list endpoint, this entity has no subordinates
	if listEndpoint == "" {
		return
	}

	// Query the list endpoint to get subordinates
	subordinates, err := fedResolver.QueryFederationListEndpoint(ctx, listEndpoint, "", "", "", "")
	if err != nil {
		log.Printf("[COLLECTION] Failed to query list endpoint %s: %v", listEndpoint, err)
		return
	}

	log.Printf("[COLLECTION] Entity %s has %d subordinates: %v", entityID, len(subordinates), subordinates)

	// Recursively collect subordinates
	for _, subID := range subordinates {
		collectEntitiesRecursively(ctx, fedResolver, subID, trustAnchor, collected)
	}
}

func federationCollectionHandler(c *gin.Context) {

	// Unsupported parameters for now (explicit to avoid partial semantics)
	if len(c.QueryArray("trust_mark_type")) > 0 || c.Query("trust_marked") != "" || c.Query("query") != "" || len(c.QueryArray("entity_claims")) > 0 || len(c.QueryArray("ui_claims")) > 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_parameter",
			"error_description": "one or more requested parameters are not supported",
		})
		return
	}

	trustAnchor := c.Query("trust_anchor")
	if trustAnchor == "" {
		if config != nil && len(config.TrustAnchors) == 1 {
			trustAnchor = config.TrustAnchors[0]
		} else {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": "Missing required parameter 'trust_anchor'",
			})
			return
		}
	}

	decodedTrustAnchor, err := url.QueryUnescape(trustAnchor)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid trust anchor parameter",
		})
		return
	}

	// Validate trust anchor is configured
	validTA := false
	for _, ta := range config.TrustAnchors {
		if ta == decodedTrustAnchor {
			validTA = true
			break
		}
	}
	if !validTA {
		c.JSON(http.StatusForbidden, gin.H{
			"error":             "invalid_trust_anchor",
			"error_description": "The Trust Anchor cannot be found or used",
		})
		return
	}

	// Parse filters/pagination
	entityTypes := c.QueryArray("entity_type")
	fromEntityID := c.Query("from_entity_id")
	limit := 0
	if limitStr := c.Query("limit"); limitStr != "" {
		if lim, err := strconv.Atoi(limitStr); err == nil && lim > 0 {
			limit = lim
		} else {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": "Invalid 'limit' parameter",
			})
			return
		}
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()

	// Parse entity type filters
	requestedTypes := make(map[string]bool)
	for _, et := range entityTypes {
		if et != "" {
			requestedTypes[et] = true
		}
	}

	// Recursively collect all entities in the federation hierarchy
	allEntityIDs := make(map[string]bool)
	collectEntitiesRecursively(ctx, fedResolver, decodedTrustAnchor, decodedTrustAnchor, allEntityIDs)

	// Don't include the trust anchor itself
	delete(allEntityIDs, decodedTrustAnchor)

	// Convert map to slice
	entityIDs := make([]string, 0, len(allEntityIDs))
	for id := range allEntityIDs {
		entityIDs = append(entityIDs, id)
	}
	sort.Strings(entityIDs)

	// Build entity info objects
	entities := make([]map[string]interface{}, 0)
	for _, id := range entityIDs {
		stmt, err := fedResolver.ResolveEntity(ctx, id, decodedTrustAnchor, false)
		if err != nil {
			log.Printf("[COLLECTION] Failed to resolve entity %s: %v", id, err)
			continue
		}

		claims := stmt.ParsedClaims
		if claims == nil {
			continue
		}

		metadata, _ := claims["metadata"].(map[string]interface{})
		entityTypeList := make([]string, 0)
		if metadata != nil {
			for k := range metadata {
				entityTypeList = append(entityTypeList, k)
			}
		}
		sort.Strings(entityTypeList)

		if len(requestedTypes) > 0 {
			matched := false
			for _, et := range entityTypeList {
				if requestedTypes[et] {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		entityID := stmt.Subject
		if entityID == "" {
			if sub, ok := claims["sub"].(string); ok {
				entityID = sub
			} else if iss, ok := claims["iss"].(string); ok {
				entityID = iss
			} else {
				entityID = id
			}
		}

		info := map[string]interface{}{
			"entity_id":    entityID,
			"entity_types": entityTypeList,
		}

		if metadata != nil {
			uiInfos := map[string]interface{}{}
			for _, et := range entityTypeList {
				if len(requestedTypes) > 0 && !requestedTypes[et] && et != "federation_entity" {
					continue
				}
				if md, ok := metadata[et].(map[string]interface{}); ok {
					uiInfo := map[string]interface{}{}
					for _, key := range []string{"display_name", "description", "logo_uri", "policy_uri", "information_uri", "keywords"} {
						for mk, mv := range md {
							if mk == key || strings.HasPrefix(mk, key+"#") {
								uiInfo[mk] = mv
							}
						}
					}
					if len(uiInfo) > 0 {
						uiInfos[et] = uiInfo
					}
				}
			}
			if len(uiInfos) > 0 {
				info["ui_infos"] = uiInfos
			}
		}

		if trustMarks, ok := claims["trust_marks"]; ok {
			info["trust_marks"] = trustMarks
		}

		entities = append(entities, info)
	}

	// Sort and paginate
	sort.Slice(entities, func(i, j int) bool {
		return normalizeCollectionEntityID(entities[i]) < normalizeCollectionEntityID(entities[j])
	})

	startIndex := 0
	if fromEntityID != "" {
		normFrom := normalizeCollectionString(fromEntityID)
		found := false
		for i, entity := range entities {
			if normalizeCollectionEntityID(entity) == normFrom {
				startIndex = i + 1 // Start from the next entity after from_entity_id
				found = true
				break
			}
		}
		if !found {
			c.JSON(http.StatusNotFound, gin.H{
				"error":             "entity_id_not_found",
				"error_description": "from_entity_id not found in result set",
			})
			return
		}
	}

	endIndex := len(entities)
	nextEntityID := ""
	if limit > 0 && startIndex+limit < len(entities) {
		endIndex = startIndex + limit
		if nextID, ok := entities[endIndex]["entity_id"].(string); ok {
			nextEntityID = nextID
		}
	}

	response := gin.H{
		"entities":     entities[startIndex:endIndex],
		"last_updated": time.Now().Unix(),
	}
	if nextEntityID != "" {
		response["next_entity_id"] = nextEntityID
	}

	c.JSON(http.StatusOK, response)
}

func normalizeCollectionString(value string) string {
	v := strings.TrimSpace(value)
	for strings.HasSuffix(v, "/") {
		v = strings.TrimSuffix(v, "/")
	}
	return v
}

func normalizeCollectionEntityID(entity map[string]interface{}) string {
	if val, ok := entity["entity_id"].(string); ok {
		return normalizeCollectionString(val)
	}
	return ""
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
	data, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		c.String(http.StatusInternalServerError, "operations console unavailable")
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", data)
}

func swaggerUIHandler(c *gin.Context) {
	data, err := staticFS.ReadFile("static/docs.html")
	if err != nil {
		c.String(http.StatusInternalServerError, "API docs unavailable")
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", data)
}

func openAPISpecHandler(c *gin.Context) {
	data, err := staticFS.ReadFile("static/openapi.json")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "OpenAPI spec unavailable"})
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", data)
}

func opsSnapshotHandler(c *gin.Context) {
	if fedResolver == nil || config == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "resolver not initialized"})
		return
	}
	stats := fedResolver.GetCacheStats()
	c.JSON(http.StatusOK, gin.H{
		"service":                  config.Service.Name,
		"timestamp":                time.Now().UTC(),
		"metrics":                  metrics.GatherSnapshot(),
		"cache":                    stats,
		"inflight_resolves":        fedResolver.InFlightResolveCount(),
		"concurrent_fetch_limit":   config.Resolver.ConcurrentFetches,
		"trust_anchors":            config.TrustAnchors,
		"registered_trust_anchors": signingTrustAnchorIDs(),
	})
}

// signingTrustAnchorIDs returns registered TAs that are currently authorized to
// have resolve-response JWTs signed (unexpired). Entity IDs only — no keys.
func signingTrustAnchorIDs() []string {
	if fedResolver == nil {
		return []string{}
	}
	anchors := fedResolver.ListRegisteredTrustAnchors()
	ids := make([]string, 0, len(anchors))
	for id := range anchors {
		if fedResolver.IsAuthorizedForTrustAnchor(id) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
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
		// Determine kid from header
		var kid interface{}
		if k, ok := token.Header["kid"]; ok {
			kid = k
		}
		// Use centralized selection helper via global fedResolver
		return resolver.SelectKeyFromJWKSet(fedResolver, jwks, kid)
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
// JWK conversion helpers removed in favor of centralized jwk utilities in pkg/resolver
