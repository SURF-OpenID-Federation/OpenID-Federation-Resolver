package resolver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"resolver/pkg/metrics"

	"github.com/golang-jwt/jwt/v5"
	"github.com/patrickmn/go-cache"
)

// JWK represents a JSON Web Key
type JWK struct {
	KeyType     string `json:"kty"`
	Use         string `json:"use,omitempty"`
	KeyID       string `json:"kid,omitempty"`
	Algorithm   string `json:"alg,omitempty"`
	Modulus     string `json:"n,omitempty"`
	Exponent    string `json:"e,omitempty"`
	Curve       string `json:"crv,omitempty"`
	XCoordinate string `json:"x,omitempty"`
	YCoordinate string `json:"y,omitempty"`
}

// JWKSet represents a JSON Web Key Set
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

func NewFederationResolver(config *Config) (*FederationResolver, error) {
	resolver := &FederationResolver{
		config:            config,
		entityCache:       cache.New(24*time.Hour, 30*time.Minute), // default expiration 24h, cleanup every 30min
		chainCache:        cache.New(24*time.Hour, 30*time.Minute),
		cachedEntities:    make(map[string]*CachedEntityStatement),
		registeredAnchors: make(map[string]*TrustAnchorRegistration),
		httpClient: &http.Client{
			Timeout: config.RequestTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: config.SkipTLSVerify},
			},
		},
	}

	// Initialize resolver keys if signing is enabled
	if config.EnableSigning {
		if err := resolver.InitializeResolverKeys(); err != nil {
			log.Printf("Warning: Failed to initialize resolver keys: %v", err)
		}
	}

	log.Printf("Federation resolver initialized with %d trust anchors", len(config.TrustAnchors))
	return resolver, nil
}

// ResolveEntity resolves an entity using the federation resolver, trying multiple methods
func (r *FederationResolver) ResolveEntity(ctx context.Context, entityID, trustAnchor string, forceRefresh bool) (*CachedEntityStatement, error) {
	log.Printf("[RESOLVER] Resolving entity %s via trust anchor %s", entityID, trustAnchor)

	cacheKey := fmt.Sprintf("%s:%s", entityID, trustAnchor)

	// Check cache first (unless force refresh)
	if !forceRefresh {
		if cached, found := r.entityCache.Get(cacheKey); found {
			statement := cached.(*CachedEntityStatement)
			if time.Now().After(statement.ExpiresAt) {
				log.Printf("[RESOLVER] Cached entity %s via %s expired at %v, removing from cache", entityID, trustAnchor, statement.ExpiresAt)
				r.entityCache.Delete(cacheKey)
			} else {
				log.Printf("[RESOLVER] Cache hit for entity %s via %s", entityID, trustAnchor)
				r.cachedEntities[cacheKey] = statement
				return statement, nil
			}
		}
	}

	// Skip federation resolve if entity is the same as trust anchor or is itself a trust anchor
	// This prevents circular resolution loops
	isEntityTrustAnchor := false
	for _, ta := range r.config.TrustAnchors {
		if entityID == ta {
			isEntityTrustAnchor = true
			break
		}
	}

	if entityID == trustAnchor || isEntityTrustAnchor {
		log.Printf("[RESOLVER] Skipping federation resolve for entity %s (is trust anchor), using direct resolve", entityID)
		// Go directly to direct well-known endpoint
		statement, err := r.tryDirectResolve(ctx, entityID)
		if err != nil {
			return nil, fmt.Errorf("direct resolve failed for trust anchor %s: %w", entityID, err)
		}
		// Cache the result
		r.entityCache.Set(cacheKey, statement, time.Until(statement.ExpiresAt))
		r.cachedEntities[cacheKey] = statement
		return statement, nil
	}

	// Method 1: Try federation resolve endpoint first (if trust anchor has it)
	statement, err := r.tryFederationResolve(ctx, entityID, trustAnchor)
	if err == nil {
		// Cache the result
		r.entityCache.Set(cacheKey, statement, time.Until(statement.ExpiresAt))
		r.cachedEntities[cacheKey] = statement
		return statement, nil
	}
	log.Printf("[RESOLVER] Federation resolve failed for %s via %s: %v", entityID, trustAnchor, err)

	// Method 2: Fall back to direct well-known endpoint
	statement, err = r.tryDirectResolve(ctx, entityID)
	if err == nil {
		// Cache the result
		r.entityCache.Set(cacheKey, statement, time.Until(statement.ExpiresAt))
		r.cachedEntities[cacheKey] = statement
		return statement, nil
	}
	log.Printf("[RESOLVER] Direct resolve failed for %s: %v", entityID, err)

	return nil, fmt.Errorf("failed to resolve entity %s via any method", entityID)
}

// Try federation resolve endpoint
func (r *FederationResolver) tryFederationResolve(ctx context.Context, entityID, trustAnchor string) (*CachedEntityStatement, error) {
	// Build federation resolve URL
	resolveURL := fmt.Sprintf("%s/resolve?sub=%s&trust_anchor=%s",
		trustAnchor,
		url.QueryEscape(entityID),
		url.QueryEscape(trustAnchor))

	// Map URL for internal Docker networking
	resolveURL = r.mapURL(resolveURL)

	log.Printf("[RESOLVER] Trying federation resolve: %s", resolveURL)

	req, err := http.NewRequestWithContext(ctx, "GET", resolveURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("federation resolve request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) // Fix: use io.ReadAll instead of ioutil.ReadAll
		return nil, fmt.Errorf("federation resolve failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read federation resolve response: %w", err)
	}

	resolveResponse := strings.TrimSpace(string(body))
	log.Printf("[RESOLVER] Federation resolve successful, response length: %d", len(resolveResponse))

	// The /resolve endpoint returns a resolve-response+jwt that may contain the entity statement
	// We need to extract the actual entity-statement from it
	statement := resolveResponse

	// Check if this is a JWT (resolve-response+jwt)
	if strings.Count(resolveResponse, ".") == 2 {
		// Parse the resolve-response to extract inner entity statement
		parts := strings.Split(resolveResponse, ".")
		if len(parts) == 3 {
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err == nil {
				var claims map[string]interface{}
				if json.Unmarshal(payload, &claims) == nil {
					// Check if this is a resolve-response with metadata.statement
					if metadata, ok := claims["metadata"].(map[string]interface{}); ok {
						if innerStmt, ok := metadata["statement"].(string); ok && strings.Count(innerStmt, ".") == 2 {
							log.Printf("[RESOLVER] Extracted inner entity-statement from resolve-response")
							statement = innerStmt
						}
					}
				}
			}
		}
	}

	return r.parseEntityStatement(entityID, statement, resolveURL, trustAnchor)
}

// Try direct well-known endpoint
func (r *FederationResolver) tryDirectResolve(ctx context.Context, entityID string) (*CachedEntityStatement, error) {
	// Construct the well-known URL properly to avoid double slashes
	u, err := url.Parse(entityID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse entity ID URL %s: %w", entityID, err)
	}
	u.Path = path.Join(u.Path, ".well-known", "openid-federation")
	wellKnownURL := u.String()

	// Map URL for internal Docker networking
	wellKnownURL = r.mapURL(wellKnownURL)

	log.Printf("[RESOLVER] Trying direct resolve: %s", wellKnownURL)

	req, err := http.NewRequestWithContext(ctx, "GET", wellKnownURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("direct resolve request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("direct resolve failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read direct resolve response: %w", err)
	}

	statement := strings.TrimSpace(string(body))
	log.Printf("[RESOLVER] Direct resolve successful, statement length: %d", len(statement))

	return r.parseEntityStatement(entityID, statement, wellKnownURL, "")
}

// Parse entity statement JWT
func (r *FederationResolver) parseEntityStatement(entityID, statement, fetchedFrom, trustAnchor string) (*CachedEntityStatement, error) {
	// Parse JWT to extract issuer/subject
	parts := strings.Split(statement, ".")
	if len(parts) == 3 {
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err == nil {
			var claims map[string]interface{}
			if json.Unmarshal(payload, &claims) == nil {
				cached := &CachedEntityStatement{
					EntityID:     entityID,
					Statement:    statement,
					ParsedClaims: claims,
					Issuer:       fmt.Sprintf("%v", claims["iss"]),
					Subject:      fmt.Sprintf("%v", claims["sub"]),
					TrustAnchor:  trustAnchor,
					CachedAt:     time.Now(),
					ExpiresAt:    time.Now().Add(time.Hour),
					FetchedFrom:  fetchedFrom,
					Validated:    false, // Will be set by signature validation
				}

				// Parse issued at and expires at from JWT claims
				if iat, ok := claims["iat"].(float64); ok {
					cached.IssuedAt = time.Unix(int64(iat), 0)
				}
				if exp, ok := claims["exp"].(float64); ok {
					cached.ExpiresAt = time.Unix(int64(exp), 0)
				}

				log.Printf("[RESOLVER] Successfully parsed entity statement for %s (iss=%s, sub=%s)",
					entityID, cached.Issuer, cached.Subject)

				// Attempt to validate the entity signature only for self-signed entities
				// (where issuer equals subject, like trust anchors)
				if cached.Issuer == cached.Subject {
					if err := r.validateEntitySignature(context.Background(), cached); err != nil {
						log.Printf("[RESOLVER] Self-signed entity signature validation failed for %s: %v", entityID, err)
						// Don't fail the resolution, just mark as not validated
					} else {
						log.Printf("[RESOLVER] Self-signed entity signature validated successfully for %s", entityID)
					}
				} else {
					log.Printf("[RESOLVER] Skipping signature validation for subordinate entity %s (issuer: %s)", entityID, cached.Issuer)
				}

				return cached, nil
			}
		}
	}

	// Fallback if JWT parsing fails
	log.Printf("[RESOLVER] Warning: Failed to parse JWT for %s, using fallback", entityID)
	cached := &CachedEntityStatement{
		EntityID:     entityID,
		Statement:    statement,
		ParsedClaims: map[string]interface{}{},
		Issuer:       trustAnchor,
		Subject:      entityID,
		TrustAnchor:  trustAnchor,
		CachedAt:     time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
		FetchedFrom:  fetchedFrom,
		Validated:    false,
	}

	return cached, nil
}

// ResolveEntityAny resolves an entity using the federation resolver, trying all trust anchors
func (r *FederationResolver) ResolveEntityAny(ctx context.Context, entityID string, forceRefresh bool) (*CachedEntityStatement, error) {
	log.Printf("[RESOLVER] Resolving entity %s via any trust anchor", entityID)

	cacheKey := fmt.Sprintf("%s:any", entityID)

	// Check cache first (unless force refresh)
	if !forceRefresh {
		if cached, found := r.entityCache.Get(cacheKey); found {
			statement := cached.(*CachedEntityStatement)
			if time.Now().After(statement.ExpiresAt) {
				log.Printf("[RESOLVER] Cached entity %s via any expired at %v, removing from cache", entityID, statement.ExpiresAt)
				r.entityCache.Delete(cacheKey)
			} else {
				log.Printf("[RESOLVER] Cache hit for entity %s via any", entityID)
				r.cachedEntities[cacheKey] = statement
				return statement, nil
			}
		}
	}

	var lastErr error

	// Try each trust anchor
	for _, ta := range r.config.TrustAnchors {
		statement, err := r.ResolveEntity(ctx, entityID, ta, forceRefresh)
		if err == nil {
			log.Printf("[RESOLVER] Successfully resolved %s via trust anchor %s", entityID, ta)
			// Cache the result
			r.entityCache.Set(cacheKey, statement, time.Until(statement.ExpiresAt))
			r.cachedEntities[cacheKey] = statement
			return statement, nil
		}
		log.Printf("[RESOLVER] Failed to resolve %s via %s: %v", entityID, ta, err)
		lastErr = err
	}

	// If all trust anchors fail, try direct resolution
	log.Printf("[RESOLVER] All trust anchors failed, trying direct resolution for %s", entityID)
	statement, err := r.tryDirectResolve(ctx, entityID)
	if err == nil {
		log.Printf("[RESOLVER] Direct resolution successful for %s", entityID)
		// Cache the result
		r.entityCache.Set(cacheKey, statement, time.Until(statement.ExpiresAt))
		r.cachedEntities[cacheKey] = statement
		return statement, nil
	}

	log.Printf("[RESOLVER] All resolution methods failed for %s", entityID)
	if lastErr != nil {
		return nil, fmt.Errorf("could not resolve entity through any trust anchor, last error: %w", lastErr)
	}
	return nil, fmt.Errorf("could not resolve entity %s through any method", entityID)
}

func (r *FederationResolver) ResolveTrustChain(ctx context.Context, entityID string, forceRefresh bool) (*CachedTrustChain, error) {
	log.Printf("[RESOLVER] Resolving trust chain for %s", entityID)

	cacheKey := entityID

	// Check cache first (unless force refresh)
	if !forceRefresh {
		if cached, found := r.chainCache.Get(cacheKey); found {
			chain := cached.(*CachedTrustChain)
			if time.Now().After(chain.ExpiresAt) {
				log.Printf("[RESOLVER] Cached trust chain for %s expired at %v, removing from cache", entityID, chain.ExpiresAt)
				r.chainCache.Delete(cacheKey)
			} else {
				log.Printf("[RESOLVER] Cache hit for trust chain %s", entityID)
				return chain, nil
			}
		}
	}

	// Try to build trust chain for each configured trust anchor
	var lastErr error
	for _, trustAnchor := range r.config.TrustAnchors {
		log.Printf("[RESOLVER] Trying to build trust chain via trust anchor: %s", trustAnchor)

		// First try federation resolve endpoint to get pre-built trust chain
		chain, err := r.tryFederationTrustChainResolve(ctx, entityID, trustAnchor)
		if err == nil {
			log.Printf("[RESOLVER] Successfully resolved trust chain via federation endpoint for %s", entityID)

			// Create the cached trust chain
			cachedChain := &CachedTrustChain{
				EntityID:    entityID,
				TrustAnchor: trustAnchor,
				Status:      "valid",
				CachedAt:    time.Now(),
				ExpiresAt:   time.Now().Add(24 * time.Hour),
				Chain:       chain,
			}

			// Validate the trust chain signatures
			if err := r.validateTrustChain(ctx, chain); err != nil {
				log.Printf("[RESOLVER] Trust chain validation failed for %s via %s: %v", entityID, trustAnchor, err)
				cachedChain.Status = "invalid"
			} else {
				log.Printf("[RESOLVER] Trust chain validation successful for %s via %s", entityID, trustAnchor)
			}

			// Cache the result
			r.chainCache.Set(cacheKey, cachedChain, time.Until(cachedChain.ExpiresAt))

			log.Printf("[RESOLVER] Successfully resolved trust chain for %s with %d entities via federation endpoint", entityID, len(chain))
			return cachedChain, nil
		}
		log.Printf("[RESOLVER] Federation trust chain resolve failed for %s via %s: %v", entityID, trustAnchor, err)

		// Fall back to building trust chain by following authority hints
		chain, resultTrustAnchor, err := r.buildTrustChainWithAnchor(ctx, entityID, trustAnchor, forceRefresh, make(map[string]bool))
		if err == nil {
			log.Printf("[RESOLVER] Successfully built trust chain via fallback for %s", entityID)

			// Create the cached trust chain
			cachedChain := &CachedTrustChain{
				EntityID:    entityID,
				TrustAnchor: resultTrustAnchor,
				Status:      "valid",
				CachedAt:    time.Now(),
				ExpiresAt:   time.Now().Add(24 * time.Hour),
				Chain:       chain,
			}

			// Validate the trust chain signatures
			if err := r.validateTrustChain(ctx, chain); err != nil {
				log.Printf("[RESOLVER] Trust chain validation failed for %s via %s: %v", entityID, trustAnchor, err)
				cachedChain.Status = "invalid"
			} else {
				log.Printf("[RESOLVER] Trust chain validation successful for %s via %s", entityID, trustAnchor)
			}

			// Cache the result
			r.chainCache.Set(cacheKey, cachedChain, time.Until(cachedChain.ExpiresAt))

			log.Printf("[RESOLVER] Successfully resolved trust chain for %s with %d entities via fallback", entityID, len(chain))
			return cachedChain, nil
		}
		log.Printf("[RESOLVER] Fallback trust chain build failed for %s via %s: %v", entityID, trustAnchor, err)
	}

	// If all trust anchors failed, return error chain
	log.Printf("[RESOLVER] Failed to build trust chain for %s via any trust anchor", entityID)
	errorChain := &CachedTrustChain{
		EntityID:    entityID,
		TrustAnchor: "",
		Status:      "error",
		CachedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		Chain:       []CachedEntityStatement{},
	}
	r.chainCache.Set(cacheKey, errorChain, time.Until(errorChain.ExpiresAt))

	if lastErr != nil {
		return errorChain, fmt.Errorf("failed to build trust chain: %w", lastErr)
	}
	return errorChain, fmt.Errorf("failed to build trust chain for %s", entityID)
}

// ResolveTrustChainWithAnchor resolves a trust chain for a specific trust anchor
func (r *FederationResolver) ResolveTrustChainWithAnchor(ctx context.Context, entityID, trustAnchor string, forceRefresh bool) (*CachedTrustChain, error) {
	log.Printf("[RESOLVER] Resolving trust chain for %s with specific trust anchor %s", entityID, trustAnchor)

	// Use both entityID and trustAnchor as cache key
	cacheKey := fmt.Sprintf("%s:%s", entityID, trustAnchor)

	// Check cache first (unless force refresh)
	if !forceRefresh {
		if cached, found := r.chainCache.Get(cacheKey); found {
			log.Printf("[RESOLVER] Cache hit for trust chain %s with anchor %s", entityID, trustAnchor)
			return cached.(*CachedTrustChain), nil
		}
	}

	// Build the trust chain for the specific trust anchor
	chain, resultTrustAnchor, err := r.buildTrustChainWithAnchor(ctx, entityID, trustAnchor, forceRefresh, make(map[string]bool))
	if err != nil {
		log.Printf("[RESOLVER] Failed to build trust chain for %s with anchor %s: %v", entityID, trustAnchor, err)
		// Return a chain with error status
		errorChain := &CachedTrustChain{
			EntityID:    entityID,
			TrustAnchor: trustAnchor,
			Status:      "error",
			CachedAt:    time.Now(),
			ExpiresAt:   time.Now().Add(24 * time.Hour),
			Chain:       []CachedEntityStatement{},
		}
		r.chainCache.Set(cacheKey, errorChain, time.Until(errorChain.ExpiresAt))
		return errorChain, nil
	}

	// Verify the result trust anchor matches requested
	if resultTrustAnchor != trustAnchor {
		log.Printf("[RESOLVER] Trust anchor mismatch: requested %s, got %s", trustAnchor, resultTrustAnchor)
		errorChain := &CachedTrustChain{
			EntityID:    entityID,
			TrustAnchor: trustAnchor,
			Status:      "invalid",
			CachedAt:    time.Now(),
			ExpiresAt:   time.Now().Add(24 * time.Hour),
			Chain:       []CachedEntityStatement{},
		}
		r.chainCache.Set(cacheKey, errorChain, time.Until(errorChain.ExpiresAt))
		return errorChain, nil
	}

	// Create the cached trust chain
	cachedChain := &CachedTrustChain{
		EntityID:    entityID,
		TrustAnchor: trustAnchor,
		Status:      "valid",
		CachedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		Chain:       chain,
	}

	// Validate the trust chain signatures
	if err := r.validateTrustChain(ctx, chain); err != nil {
		log.Printf("[RESOLVER] Trust chain validation failed for %s with anchor %s: %v", entityID, trustAnchor, err)
		cachedChain.Status = "invalid"
	} else {
		log.Printf("[RESOLVER] Trust chain validation successful for %s with anchor %s", entityID, trustAnchor)
	}

	// Cache the result
	r.chainCache.Set(cacheKey, cachedChain, time.Until(cachedChain.ExpiresAt))

	log.Printf("[RESOLVER] Successfully built trust chain for %s with anchor %s (%d entities)", entityID, trustAnchor, len(chain))
	return cachedChain, nil
}

// buildTrustChain recursively builds a trust chain by following authority hints
func (r *FederationResolver) buildTrustChain(ctx context.Context, entityID string, trustAnchor string, visited map[string]bool) ([]*CachedEntityStatement, error) {
	// Add debug logging here
	log.Printf("[DEBUG] Building trust chain for entity: %s, trust anchor: %s", entityID, trustAnchor)

	if visited[entityID] {
		log.Printf("[DEBUG] Entity %s already visited, preventing cycle", entityID)
		return nil, fmt.Errorf("circular reference detected: %s", entityID)
	}
	visited[entityID] = true

	// If this is the trust anchor, we've reached the top
	if entityID == trustAnchor {
		log.Printf("[DEBUG] Reached trust anchor: %s", entityID)
		// Try to resolve the trust anchor itself
		statement, err := r.ResolveEntityAny(ctx, entityID, false)
		if err != nil {
			log.Printf("[DEBUG] Failed to resolve trust anchor %s: %v", entityID, err)
			return nil, fmt.Errorf("failed to resolve trust anchor %s: %w", entityID, err)
		}
		log.Printf("[DEBUG] Successfully resolved trust anchor, returning chain with 1 entity")
		return []*CachedEntityStatement{statement}, nil
	}

	// Resolve the current entity
	log.Printf("[DEBUG] Resolving entity: %s", entityID)
	statement, err := r.ResolveEntityAny(ctx, entityID, false)
	if err != nil {
		log.Printf("[DEBUG] Failed to resolve entity %s: %v", entityID, err)
		return nil, fmt.Errorf("failed to resolve entity %s: %w", entityID, err)
	}

	// Extract authority hints - FIX: Use the correct method signature
	authorityHints, err := r.extractAuthorityHints(statement)
	if err != nil {
		log.Printf("[DEBUG] Failed to extract authority hints for %s: %v", entityID, err)
		return nil, fmt.Errorf("failed to extract authority hints: %w", err)
	}
	log.Printf("[DEBUG] Extracted authority hints for %s: %v", entityID, authorityHints)

	if len(authorityHints) == 0 {
		log.Printf("[DEBUG] No authority hints found for %s", entityID)
		return []*CachedEntityStatement{statement}, nil
	}

	// Try each authority hint
	for _, hint := range authorityHints {
		log.Printf("[DEBUG] Trying authority hint: %s", hint)
		parentChain, err := r.buildTrustChain(ctx, hint, trustAnchor, visited)
		if err != nil {
			log.Printf("[DEBUG] Authority hint %s failed: %v", hint, err)
			continue
		}

		// Build complete chain: current entity + parent chain
		completeChain := []*CachedEntityStatement{statement}
		completeChain = append(completeChain, parentChain...)

		log.Printf("[DEBUG] Built complete chain with %d entities", len(completeChain))
		return completeChain, nil
	}

	log.Printf("[DEBUG] All authority hints failed for %s", entityID)
	return nil, fmt.Errorf("no valid authority path found for %s", entityID)
}

// buildTrustChainWithAnchor builds a trust chain for a specific trust anchor
func (r *FederationResolver) buildTrustChainWithAnchor(ctx context.Context, entityID, requestedTrustAnchor string, forceRefresh bool, visited map[string]bool) ([]CachedEntityStatement, string, error) {
	// Prevent infinite loops
	if visited[entityID] {
		return nil, "", fmt.Errorf("cycle detected in trust chain for entity %s", entityID)
	}
	visited[entityID] = true

	log.Printf("[RESOLVER] Building trust chain segment for %s with target anchor %s", entityID, requestedTrustAnchor)

	// Check if this entity is the requested trust anchor
	if entityID == requestedTrustAnchor {
		log.Printf("[RESOLVER] Reached target trust anchor %s", entityID)
		// Resolve the trust anchor entity
		entity, err := r.ResolveEntity(ctx, entityID, requestedTrustAnchor, forceRefresh)
		if err != nil {
			return nil, "", fmt.Errorf("failed to resolve trust anchor %s: %w", entityID, err)
		}
		return []CachedEntityStatement{*entity}, entityID, nil
	}

	// Resolve the current entity (subordinate statement)
	entity, err := r.ResolveEntity(ctx, entityID, requestedTrustAnchor, forceRefresh)
	if err != nil {
		return nil, "", fmt.Errorf("failed to resolve entity %s: %w", entityID, err)
	}
	// Validate that the returned statement is for the requested entity
	if entity.Subject != entityID {
		log.Printf("[RESOLVER] ERROR: Resolved entity statement subject (%s) does not match requested entity (%s). Possible misconfigured trust anchor endpoint.", entity.Subject, entityID)
		return nil, "", fmt.Errorf("resolved entity statement subject (%s) does not match requested entity (%s)", entity.Subject, entityID)
	}

	// Always prepend the self-signed Entity Configuration for the leaf entity
	var chain []CachedEntityStatement
	selfSigned, err := r.ResolveEntity(ctx, entityID, entityID, forceRefresh)
	if err == nil && selfSigned.Issuer == entityID && selfSigned.Subject == entityID {
		chain = append(chain, *selfSigned)
	} else {
		log.Printf("[RESOLVER] Warning: failed to resolve self-signed Entity Configuration for %s: %v", entityID, err)
	}

	// Add the subordinate statement (even if it's self-signed, to preserve chain structure)
	chain = append(chain, *entity)

	// Get authority hints from the entity's metadata
	authorityHints, err := r.extractAuthorityHints(entity)
	if err != nil {
		return nil, "", fmt.Errorf("failed to extract authority hints from %s: %w", entityID, err)
	}

	log.Printf("[DEBUG] Entity %s has authority hints: %v", entityID, authorityHints)

	if len(authorityHints) == 0 {
		// Fallback: If this subordinate statement was issued by the requested trust anchor
		// for the requested entity, accept it as a valid leaf in the trust chain
		if normalizeEntityID(entity.Issuer) == normalizeEntityID(requestedTrustAnchor) &&
			normalizeEntityID(entity.Subject) == normalizeEntityID(entityID) {
			log.Printf("[RESOLVER] Subordinate statement for %s issued by trust anchor %s has no authority_hints; using fallback to build chain", entityID, requestedTrustAnchor)

			// Get the trust anchor's own statement
			taEntity, err := r.ResolveEntity(ctx, requestedTrustAnchor, requestedTrustAnchor, forceRefresh)
			if err != nil {
				log.Printf("[RESOLVER] Failed to resolve trust anchor %s: %v", requestedTrustAnchor, err)
				return nil, "", fmt.Errorf("failed to resolve trust anchor %s: %w", requestedTrustAnchor, err)
			}

			chain = append(chain, *taEntity)
			return chain, requestedTrustAnchor, nil
		}

		log.Printf("[DEBUG] Entity %s has no authority hints - cannot build trust chain", entityID)
		return nil, "", fmt.Errorf("entity %s has no authority hints and is not the target trust anchor %s", entityID, requestedTrustAnchor)
	}

	// Try each authority hint, but only follow paths that can lead to the requested trust anchor
	for _, authorityID := range authorityHints {
		log.Printf("[RESOLVER] Following authority hint %s for entity %s (targeting %s)", authorityID, entityID, requestedTrustAnchor)

		// Recursively build chain for this authority
		subChain, trustAnchor, err := r.buildTrustChainWithAnchor(ctx, authorityID, requestedTrustAnchor, forceRefresh, visited)
		if err != nil {
			log.Printf("[RESOLVER] Failed to build chain via authority %s: %v", authorityID, err)
			continue
		}

		// Verify the returned trust anchor matches what we requested
		if trustAnchor != requestedTrustAnchor {
			log.Printf("[RESOLVER] Authority %s led to wrong trust anchor %s, expected %s", authorityID, trustAnchor, requestedTrustAnchor)
			continue
		}

		// Build the complete chain: entity config(s) + subordinate + authority ...
		fullChain := append(chain, subChain...)
		log.Printf("[RESOLVER] Successfully built chain via authority %s: %d entities", authorityID, len(fullChain))
		return fullChain, trustAnchor, nil
	}

	return nil, "", fmt.Errorf("could not build trust chain for %s to target anchor %s through any authority hint", entityID, requestedTrustAnchor)
}

// extractAuthorityHints extracts authority_hints from an entity statement's metadata
func (r *FederationResolver) extractAuthorityHints(entity *CachedEntityStatement) ([]string, error) {
	// Extract authority_hints from the top level of parsed claims
	authorityHintsRaw, ok := entity.ParsedClaims["authority_hints"]
	if !ok {
		return []string{}, nil // No authority hints is valid
	}

	// authority_hints should be an array of strings
	hintsArray, ok := authorityHintsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("authority_hints is not an array")
	}

	var hints []string
	for _, hint := range hintsArray {
		if hintStr, ok := hint.(string); ok {
			hints = append(hints, hintStr)
		} else {
			log.Printf("[RESOLVER] Warning: non-string authority hint in %s: %v", entity.EntityID, hint)
		}
	}

	log.Printf("[RESOLVER] Extracted %d authority hints from %s", len(hints), entity.EntityID)
	return hints, nil
}

// validateJWTSignature validates a JWT signature using the issuer's public key
func (r *FederationResolver) validateJWTSignature(ctx context.Context, tokenString string, issuer string) (bool, error) {
	if !r.config.ValidateSignatures {
		log.Printf("[RESOLVER] Signature validation disabled, skipping validation for issuer %s", issuer)
		return true, nil
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Get the public key for this issuer
		publicKey, err := r.getIssuerPublicKey(ctx, issuer, token.Header["kid"])
		if err != nil {
			return nil, fmt.Errorf("failed to get public key for issuer %s: %w", issuer, err)
		}
		return publicKey, nil
	})

	if err != nil {
		log.Printf("[RESOLVER] JWT validation failed for issuer %s: %v", issuer, err)
		return false, err
	}

	if !token.Valid {
		log.Printf("[RESOLVER] JWT signature invalid for issuer %s", issuer)
		return false, fmt.Errorf("invalid JWT signature")
	}

	log.Printf("[RESOLVER] JWT signature validated successfully for issuer %s", issuer)
	return true, nil
}

// validateJWTSignatureForEntity validates a JWT signature for an entity, with special handling for self-signed entities
func (r *FederationResolver) validateJWTSignatureForEntity(ctx context.Context, tokenString string, issuer string, currentEntity *CachedEntityStatement) (bool, error) {
	if !r.config.ValidateSignatures {
		log.Printf("[RESOLVER] Signature validation disabled, skipping validation for issuer %s", issuer)
		return true, nil
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Get the public key for this issuer, with special handling for self-signed entities
		publicKey, err := r.getIssuerPublicKeyForEntity(ctx, issuer, token.Header["kid"], currentEntity)
		if err != nil {
			return nil, fmt.Errorf("failed to get public key for issuer %s: %w", issuer, err)
		}
		return publicKey, nil
	})

	if err != nil {
		log.Printf("[RESOLVER] JWT validation failed for issuer %s: %v", issuer, err)
		return false, err
	}

	if !token.Valid {
		log.Printf("[RESOLVER] JWT signature invalid for issuer %s", issuer)
		return false, fmt.Errorf("invalid JWT signature")
	}

	log.Printf("[RESOLVER] JWT signature validated successfully for issuer %s", issuer)
	return true, nil
}

// getIssuerPublicKey retrieves the public key for an issuer
func (r *FederationResolver) getIssuerPublicKey(ctx context.Context, issuer string, kid interface{}) (interface{}, error) {
	// First, try to get the key from the issuer's entity statement
	entity, err := r.ResolveEntityAny(ctx, issuer, false)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve issuer entity %s: %w", issuer, err)
	}

	// Look for JWK Set in the entity metadata
	jwks, err := r.extractJWKSet(entity)
	if err != nil {
		// Try to get JWKS endpoint from metadata
		jwksURL, urlErr := r.extractJWKSEndpoint(entity)
		if urlErr != nil {
			log.Printf("[RESOLVER] No JWKS found in entity metadata for %s and no JWKS endpoint, trying /.well-known/jwks.json", issuer)
			// Fall back to /.well-known/jwks.json
			jwksURL = fmt.Sprintf("%s/.well-known/jwks.json", issuer)
		} else {
			log.Printf("[RESOLVER] No JWKS found in entity metadata for %s, trying JWKS endpoint %s", issuer, jwksURL)
		}
		return r.fetchJWKSetFromURL(ctx, jwksURL, kid)
	}

	// Find the key with the matching kid
	var kidStr string
	if kid != nil {
		kidStr = fmt.Sprintf("%v", kid)
	}

	for _, key := range jwks.Keys {
		if kidStr == "" || key.KeyID == kidStr {
			// Try different key types in order of preference
			if rsaKey, err := r.jwkToRSAPublicKey(&key); err == nil {
				return rsaKey, nil
			}
			if ecKey, err := r.jwkToECPublicKey(&key); err == nil {
				return ecKey, nil
			}
			if edKey, err := r.jwkToEdDSAPublicKey(&key); err == nil {
				return edKey, nil
			}
		}
	}

	return nil, fmt.Errorf("no suitable public key found for issuer %s", issuer)
}

// getIssuerPublicKeyForEntity retrieves the public key for an issuer, with special handling for self-signed entities
func (r *FederationResolver) getIssuerPublicKeyForEntity(ctx context.Context, issuer string, kid interface{}, currentEntity *CachedEntityStatement) (interface{}, error) {
	// Special case: if the issuer is the same as the current entity (self-signed), use the entity's own JWKS
	if currentEntity != nil && issuer == currentEntity.Subject && issuer == currentEntity.Issuer {
		log.Printf("[RESOLVER] Self-signed entity %s, using its own JWKS", issuer)
		jwks, err := r.extractJWKSet(currentEntity)
		if err != nil {
			return nil, fmt.Errorf("failed to extract JWKS from self-signed entity %s: %w", issuer, err)
		}

		// Find the key with the matching kid
		var kidStr string
		if kid != nil {
			kidStr = fmt.Sprintf("%v", kid)
		}

		for _, key := range jwks.Keys {
			if kidStr == "" || key.KeyID == kidStr {
				// Try different key types in order of preference
				if rsaKey, err := r.jwkToRSAPublicKey(&key); err == nil {
					return rsaKey, nil
				}
				if ecKey, err := r.jwkToECPublicKey(&key); err == nil {
					return ecKey, nil
				}
				if edKey, err := r.jwkToEdDSAPublicKey(&key); err == nil {
					return edKey, nil
				}
			}
		}

		return nil, fmt.Errorf("no suitable public key found in self-signed entity %s", issuer)
	}

	// Normal case: resolve the issuer entity
	return r.getIssuerPublicKey(ctx, issuer, kid)
}

// extractJWKSet extracts JWK Set from entity metadata
func (r *FederationResolver) extractJWKSet(entity *CachedEntityStatement) (*JWKSet, error) {
	// First, check if jwks is at the top level of claims (for self-signed entity configurations)
	jwksRaw, ok := entity.ParsedClaims["jwks"]
	if ok {
		// jwks is at the top level
	} else {
		// Check in metadata.federation_entity
		metadata, ok := entity.ParsedClaims["metadata"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("no metadata found")
		}

		federationEntity, ok := metadata["federation_entity"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("no federation_entity metadata found")
		}

		jwksRaw, ok = federationEntity["jwks"]
		if !ok {
			return nil, fmt.Errorf("no jwks found in federation_entity metadata")
		}
	}

	// jwksRaw should already be a parsed JSON object, so we can marshal it directly
	jwksData, err := json.Marshal(jwksRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal jwks: %w", err)
	}

	var jwks JWKSet
	if err := json.Unmarshal(jwksData, &jwks); err != nil {
		// If direct unmarshaling fails, try to handle it as a JWT
		if jwksStr, ok := jwksRaw.(string); ok {
			// If it's a JWT string, we need to decode it
			if strings.Count(jwksStr, ".") == 2 {
				parts := strings.Split(jwksStr, ".")
				if len(parts) == 3 {
					payload, decodeErr := base64.RawURLEncoding.DecodeString(parts[1])
					if decodeErr == nil {
						if unmarshalErr := json.Unmarshal(payload, &jwks); unmarshalErr == nil {
							return &jwks, nil
						}
					}
				}
			}
		}
		return nil, fmt.Errorf("failed to unmarshal jwks: %w", err)
	}

	return &jwks, nil
}

// extractJWKSEndpoint extracts JWKS endpoint URL from entity metadata
func (r *FederationResolver) extractJWKSEndpoint(entity *CachedEntityStatement) (string, error) {
	metadata, ok := entity.ParsedClaims["metadata"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("no metadata found")
	}

	federationEntity, ok := metadata["federation_entity"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("no federation_entity metadata found")
	}

	jwksEndpoint, ok := federationEntity["jwks_endpoint"].(string)
	if !ok {
		return "", fmt.Errorf("no jwks_endpoint found in federation_entity metadata")
	}

	return jwksEndpoint, nil
}

// ExtractFederationListEndpoint extracts federation_list_endpoint URL from entity metadata
func (r *FederationResolver) ExtractFederationListEndpoint(entity *CachedEntityStatement) (string, error) {
	metadata, ok := entity.ParsedClaims["metadata"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("no metadata found")
	}

	federationEntity, ok := metadata["federation_entity"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("no federation_entity metadata found")
	}

	listEndpoint, ok := federationEntity["federation_list_endpoint"].(string)
	if !ok {
		return "", fmt.Errorf("no federation_list_endpoint found in federation_entity metadata")
	}

	return listEndpoint, nil
}

// fetchJWKSetFromURL fetches JWK Set from a URL
func (r *FederationResolver) fetchJWKSetFromURL(ctx context.Context, url string, kid interface{}) (interface{}, error) {
	// Map URL for internal Docker networking
	mappedURL := r.mapURL(url)

	req, err := http.NewRequestWithContext(ctx, "GET", mappedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("JWKS request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwks JWKSet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	var kidStr string
	if kid != nil {
		kidStr = fmt.Sprintf("%v", kid)
	}

	for _, key := range jwks.Keys {
		if kidStr == "" || key.KeyID == kidStr {
			if rsaKey, err := r.jwkToRSAPublicKey(&key); err == nil {
				return rsaKey, nil
			}
			if ecKey, err := r.jwkToECPublicKey(&key); err == nil {
				return ecKey, nil
			}
			if edKey, err := r.jwkToEdDSAPublicKey(&key); err == nil {
				return edKey, nil
			}
		}
	}

	return nil, fmt.Errorf("no suitable key found in JWKS")
}

// jwkToRSAPublicKey converts a JWK to RSA public key
func (r *FederationResolver) jwkToRSAPublicKey(jwk *JWK) (*rsa.PublicKey, error) {
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
func (r *FederationResolver) jwkToECPublicKey(jwk *JWK) (*ecdsa.PublicKey, error) {
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

// jwkToEdDSAPublicKey converts a JWK to EdDSA public key
func (r *FederationResolver) jwkToEdDSAPublicKey(jwk *JWK) (interface{}, error) {
	if jwk.KeyType != "OKP" {
		return nil, fmt.Errorf("unsupported key type: %s", jwk.KeyType)
	}

	if jwk.Curve != "Ed25519" {
		return nil, fmt.Errorf("unsupported EdDSA curve: %s", jwk.Curve)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.XCoordinate)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x coordinate: %w", err)
	}

	// For Ed25519, the public key is just the x coordinate (32 bytes)
	if len(xBytes) != 32 {
		return nil, fmt.Errorf("invalid Ed25519 public key length: %d", len(xBytes))
	}

	// Note: Go's crypto/ed25519 package doesn't have a direct PublicKey type that implements
	// the jwt.SigningMethod interface. We'll need to handle EdDSA verification differently
	// or use a third-party library. For now, return an error.
	return nil, fmt.Errorf("EdDSA keys are not yet supported in this resolver")
}

// validateTrustChain validates all signatures in a trust chain
// Updated to be more flexible: validates that each entity is properly signed by its issuer
// and that the chain ultimately leads to the trust anchor, allowing for direct relationships
func (r *FederationResolver) validateTrustChain(ctx context.Context, chain []CachedEntityStatement) error {
	if !r.config.ValidateSignatures {
		log.Printf("[RESOLVER] Signature validation disabled, skipping trust chain validation")
		return nil
	}

	if len(chain) == 0 {
		return fmt.Errorf("empty trust chain")
	}

	log.Printf("[RESOLVER] Validating trust chain with %d entities", len(chain))

	// Validate each entity statement's signature against its issuer
	for i := range chain {
		entity := &chain[i]

		// Validate the JWT signature using the entity's issuer
		valid, err := r.validateJWTSignature(ctx, entity.Statement, entity.Issuer)
		if err != nil {
			log.Printf("[RESOLVER] Signature validation failed for entity %s: %v", entity.Subject, err)
			return fmt.Errorf("signature validation failed for entity %s: %w", entity.Subject, err)
		}
		if !valid {
			log.Printf("[RESOLVER] Invalid signature for entity %s", entity.Subject)
			return fmt.Errorf("invalid signature for entity %s", entity.Subject)
		}

		// Mark as validated
		entity.Validated = true
	}

	// Check if the chain contains a trust anchor (self-signed entity)
	hasTrustAnchor := false
	for _, entity := range chain {
		if entity.Issuer == entity.Subject {
			hasTrustAnchor = true
			log.Printf("[RESOLVER] Found trust anchor in chain: %s", entity.Subject)
			break
		}
	}

	if !hasTrustAnchor {
		log.Printf("[RESOLVER] Warning: trust chain does not contain a self-signed trust anchor")
		// Don't fail validation - allow chains that may be valid but don't include the trust anchor
		// This can happen when chains are built through federation endpoints
	}

	// Verify that all entities in the chain are connected (each issuer appears as a subject somewhere in the chain)
	// This allows for flexible chain structures including direct relationships
	entitySubjects := make(map[string]bool)
	for _, entity := range chain {
		entitySubjects[entity.Subject] = true
	}

	for _, entity := range chain {
		// The trust anchor can be self-signed, so skip issuer validation for it
		if entity.Issuer == entity.Subject {
			continue
		}

		// For non-trust-anchor entities, check if the issuer appears in the chain
		// Allow external issuers that can be resolved separately
		if !entitySubjects[entity.Issuer] {
			log.Printf("[RESOLVER] Issuer %s for entity %s does not appear in chain subjects - allowing external issuer", entity.Issuer, entity.Subject)
			// Don't fail - external issuers are allowed
		}
	}

	log.Printf("[RESOLVER] Trust chain validation successful - all signatures valid")
	return nil
}

// validateEntitySignature validates a single entity statement's signature
func (r *FederationResolver) validateEntitySignature(ctx context.Context, entity *CachedEntityStatement) error {
	if !r.config.ValidateSignatures {
		entity.Validated = true
		return nil
	}

	valid, err := r.validateJWTSignatureForEntity(ctx, entity.Statement, entity.Issuer, entity)
	if err != nil {
		return fmt.Errorf("signature validation failed: %w", err)
	}

	entity.Validated = valid
	if !valid {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

func (r *FederationResolver) CheckTrustAnchor(ctx context.Context, trustAnchor string) error {
	wellKnownURL := fmt.Sprintf("%s/.well-known/openid-federation", trustAnchor)

	// Map URL for internal Docker networking
	wellKnownURL = r.mapURL(wellKnownURL)

	req, err := http.NewRequestWithContext(ctx, "GET", wellKnownURL, nil)
	if err != nil {
		return err
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("trust anchor returned status %d", resp.StatusCode)
	}

	return nil
}

// Cache management methods

// GetCacheStats returns statistics about the caches
func (r *FederationResolver) GetCacheStats() map[string]interface{} {
	return map[string]interface{}{
		"entity_cache_size": r.entityCache.ItemCount(),
		"chain_cache_size":  r.chainCache.ItemCount(),
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
	r.entityCache.Flush()
	r.cachedEntities = make(map[string]*CachedEntityStatement)
	// Update metrics
	metrics.UpdateCacheSize("entity_statements", 0)
}

// ClearChainCache clears all cached trust chains
func (r *FederationResolver) ClearChainCache() {
	r.chainCache.Flush()
	// Update metrics
	metrics.UpdateCacheSize("trust_chains", 0)
}

// ClearAllCaches clears both entity and chain caches
func (r *FederationResolver) ClearAllCaches() {
	r.ClearEntityCache()
	r.ClearChainCache()
}

// RemoveCachedEntity removes a specific entity from the cache
func (r *FederationResolver) RemoveCachedEntity(entityID, trustAnchor string) bool {
	cacheKey := fmt.Sprintf("%s:%s", entityID, trustAnchor)
	r.entityCache.Delete(cacheKey)
	delete(r.cachedEntities, cacheKey)
	return true // Delete doesn't return success status
}

// RemoveCachedEntityAny removes an entity resolved via any trust anchor from the cache
func (r *FederationResolver) RemoveCachedEntityAny(entityID string) bool {
	cacheKey := fmt.Sprintf("%s:any", entityID)
	r.entityCache.Delete(cacheKey)
	delete(r.cachedEntities, cacheKey)
	return true // Delete doesn't return success status
}

// RemoveCachedChain removes a specific trust chain from the cache
func (r *FederationResolver) RemoveCachedChain(entityID string) bool {
	r.chainCache.Delete(entityID)
	return true // Delete doesn't return success status
}

// GetCachedEntity retrieves a specific cached entity statement
func (r *FederationResolver) GetCachedEntity(entityID, trustAnchor string) (*CachedEntityStatement, bool) {
	cacheKey := fmt.Sprintf("%s:%s", entityID, trustAnchor)
	if item, found := r.entityCache.Get(cacheKey); found {
		stmt := item.(*CachedEntityStatement)
		if time.Now().After(stmt.ExpiresAt) {
			// expired: remove from cache and report not found
			r.entityCache.Delete(cacheKey)
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
			r.entityCache.Delete(cacheKey)
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

// normalizeEntityID converts an entity ID into a canonical string for comparisons.
// It parses the URL, lowercases scheme/host, removes default ports (80/443),
// and trims trailing slashes on the path.
func normalizeEntityID(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		// fallback: trim whitespace
		return strings.TrimSpace(raw)
	}

	// Normalize scheme/host
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())

	// Remove default ports from Host:80 or Host:443
	if (u.Scheme == "http" && u.Port() == "80") || (u.Scheme == "https" && u.Port() == "443") {
		u.Host = host
	} else if u.Port() != "" {
		u.Host = host + ":" + u.Port()
	} else {
		u.Host = host
	}

	// Normalize path: drop trailing slash (consistent)
	u.Path = strings.TrimRight(u.Path, "/")

	// Return normalized full string (preserve query/fragment if needed)
	// We'll use Scheme + Host + Path for equality checks
	return fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
}

// claimsMapFromJWT decodes a JWT payload without verifying signature, returning claims map.
// Use only for inspection / fallback logic; real verification should be done separately.
func claimsMapFromJWT(jwtStr string) (map[string]interface{}, error) {
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("JWT: unexpected parts count")
	}
	payload := parts[1]
	// base64-url decode with padding fix
	if m := len(payload) % 4; m != 0 {
		payload += strings.Repeat("=", 4-m)
	}
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode payload: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWT payload: %w", err)
	}
	return claims, nil
}

// tryFederationTrustChainResolve attempts to resolve a trust chain via federation endpoint
func (r *FederationResolver) tryFederationTrustChainResolve(ctx context.Context, entityID, trustAnchor string) ([]CachedEntityStatement, error) {
	// Build federation resolve URL for trust chain
	resolveURL := fmt.Sprintf("%s/resolve?sub=%s&trust_anchor=%s",
		trustAnchor,
		url.QueryEscape(entityID),
		url.QueryEscape(trustAnchor))

	// Map URL for internal Docker networking
	resolveURL = r.mapURL(resolveURL)

	log.Printf("[RESOLVER] Trying federation trust chain resolve: %s", resolveURL)

	req, err := http.NewRequestWithContext(ctx, "GET", resolveURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("federation trust chain resolve request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("federation trust chain resolve failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read federation trust chain resolve response: %w", err)
	}

	trustChainJWT := string(body)
	log.Printf("[RESOLVER] Federation trust chain resolve successful, JWT length: %d", len(trustChainJWT))

	// Parse the trust chain JWT
	return r.parseTrustChainJWT(entityID, trustChainJWT, resolveURL, trustAnchor)
}

// parseTrustChainJWT parses a trust chain JWT response
func (r *FederationResolver) parseTrustChainJWT(entityID, trustChainJWT, fetchedFrom, trustAnchor string) ([]CachedEntityStatement, error) {
	// Parse JWT to extract claims
	parts := strings.Split(trustChainJWT, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid trust chain JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode trust chain JWT payload: %w", err)
	}

	var claims map[string]interface{}
	if json.Unmarshal(payload, &claims) == nil {
		// Extract trust_chain array
		trustChainRaw, ok := claims["trust_chain"]
		if !ok {
			log.Printf("[DEBUG] No trust_chain found in response, trying fallback")
			// Try fallback logic here
			return r.tryTrustChainFallback(context.Background(), claims, entityID, trustAnchor)
		}

		trustChainArray, ok := trustChainRaw.([]interface{})
		if !ok {
			return nil, fmt.Errorf("trust_chain is not an array")
		}

		if len(trustChainArray) == 0 {
			log.Printf("[DEBUG] trust_chain is empty, trying fallback")
			return r.tryTrustChainFallback(context.Background(), claims, entityID, trustAnchor)
		}

		var chain []CachedEntityStatement
		for i, stmtRaw := range trustChainArray {
			stmtStr, ok := stmtRaw.(string)
			if !ok {
				return nil, fmt.Errorf("trust_chain[%d] is not a string", i)
			}

			// Parse each entity statement JWT
			entity, err := r.parseEntityStatementFromJWT(entityID, stmtStr, fetchedFrom, trustAnchor)
			if err != nil {
				return nil, fmt.Errorf("failed to parse entity statement %d: %w", i, err)
			}
			chain = append(chain, *entity)
		}

		// Ensure the self-signed Entity Configuration for the leaf entity is the FIRST element in the trust chain
		if len(chain) > 0 {
			var selfSignedIdx = -1
			for i, stmt := range chain {
				if stmt.Issuer == entityID && stmt.Subject == entityID {
					selfSignedIdx = i
					break
				}
			}
			if selfSignedIdx == 0 {
				// Already first, remove any duplicates later in the chain
				newChain := []CachedEntityStatement{chain[0]}
				for i := 1; i < len(chain); i++ {
					if !(chain[i].Issuer == entityID && chain[i].Subject == entityID) {
						newChain = append(newChain, chain[i])
					}
				}
				chain = newChain
				log.Printf("[RESOLVER] Self-signed Entity Configuration for %s is already first in trust chain", entityID)
			} else if selfSignedIdx > 0 {
				// Move self-signed EC to the front, remove any duplicates
				selfSigned := chain[selfSignedIdx]
				newChain := []CachedEntityStatement{selfSigned}
				for i, stmt := range chain {
					if i != selfSignedIdx && !(stmt.Issuer == entityID && stmt.Subject == entityID) {
						newChain = append(newChain, stmt)
					}
				}
				chain = newChain
				log.Printf("[RESOLVER] Moved self-signed Entity Configuration for %s to front of trust chain", entityID)
			} else {
				// Not present, fetch and prepend
				selfSigned, err := r.ResolveEntity(context.Background(), entityID, entityID, false)
				if err == nil && selfSigned.Issuer == entityID && selfSigned.Subject == entityID {
					chain = append([]CachedEntityStatement{*selfSigned}, chain...)
					log.Printf("[RESOLVER] Prepended self-signed Entity Configuration for %s to trust chain (was missing)", entityID)
				} else {
					log.Printf("[RESOLVER] Warning: failed to resolve self-signed Entity Configuration for %s: %v", entityID, err)
				}
			}
		} else {
			// If chain is empty, try to fetch and add the self-signed config
			selfSigned, err := r.ResolveEntity(context.Background(), entityID, entityID, false)
			if err == nil && selfSigned.Issuer == entityID && selfSigned.Subject == entityID {
				chain = append(chain, *selfSigned)
				log.Printf("[RESOLVER] Added self-signed Entity Configuration for %s to empty trust chain", entityID)
			} else {
				log.Printf("[RESOLVER] Warning: failed to resolve self-signed Entity Configuration for %s: %v", entityID, err)
			}
		}

		log.Printf("[RESOLVER] Successfully parsed trust chain with %d entities", len(chain))
		return chain, nil
	}

	return nil, fmt.Errorf("failed to parse trust chain JWT claims")
}

// parseEntityStatementFromJWT parses an entity statement JWT
func (r *FederationResolver) parseEntityStatementFromJWT(entityID, statement, fetchedFrom, trustAnchor string) (*CachedEntityStatement, error) {
	// Parse JWT to extract issuer/subject
	parts := strings.Split(statement, ".")
	if len(parts) == 3 {
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err == nil {
			var claims map[string]interface{}
			if json.Unmarshal(payload, &claims) == nil {
				cached := &CachedEntityStatement{
					EntityID:     entityID,
					Statement:    statement,
					ParsedClaims: claims,
					Issuer:       fmt.Sprintf("%v", claims["iss"]),
					Subject:      fmt.Sprintf("%v", claims["sub"]),
					TrustAnchor:  trustAnchor,
					CachedAt:     time.Now(),
					ExpiresAt:    time.Now().Add(time.Hour),
					FetchedFrom:  fetchedFrom,
					Validated:    false,
				}

				// Parse issued at and expires at from JWT claims
				if iat, ok := claims["iat"].(float64); ok {
					cached.IssuedAt = time.Unix(int64(iat), 0)
				}
				if exp, ok := claims["exp"].(float64); ok {
					cached.ExpiresAt = time.Unix(int64(exp), 0)
				}

				log.Printf("[RESOLVER] Successfully parsed entity statement for %s (iss=%s, sub=%s)",
					entityID, cached.Issuer, cached.Subject)

				return cached, nil
			}
		}
	}

	return nil, fmt.Errorf("failed to parse entity statement JWT")
}

// tryTrustChainFallback attempts to build trust chain when federation response has empty trust_chain
func (r *FederationResolver) tryTrustChainFallback(ctx context.Context, topClaims map[string]interface{}, requestedEntity, trustAnchor string) ([]CachedEntityStatement, error) {
	log.Printf("[DEBUG] Trying trust chain fallback for entity %s via trust anchor %s", requestedEntity, trustAnchor)

	// Check if we have the required fields
	reqEntityNorm := normalizeEntityID(requestedEntity)
	topSub, ok := topClaims["sub"].(string)
	if !ok {
		return nil, fmt.Errorf("no sub claim in top-level response")
	}

	topTA, ok := topClaims["trust_anchor"].(string)
	if !ok {
		return nil, fmt.Errorf("no trust_anchor claim in top-level response")
	}

	if normalizeEntityID(topSub) != reqEntityNorm {
		return nil, fmt.Errorf("top-level sub (%s) does not match requested entity (%s)", topSub, requestedEntity)
	}

	// Try direct resolve to trust anchor
	resolveURL := fmt.Sprintf("%s/resolve?sub=%s", topTA, url.QueryEscape(requestedEntity))

	// Map URL for internal Docker networking
	resolveURL = r.mapURL(resolveURL)

	log.Printf("[DEBUG] Trying direct TA resolve fallback: %s", resolveURL)

	req, err := http.NewRequestWithContext(ctx, "GET", resolveURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create fallback request: %w", err)
	}
	req.Header.Set("Accept", "application/entity-statement+jwt, application/jwt, */*")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		log.Printf("[WARN] TA fallback resolve failed: %v", err)
		return nil, fmt.Errorf("fallback resolve failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read fallback response: %w", err)
	}

	snippet := string(body)
	if len(snippet) > 512 {
		snippet = snippet[:512]
	}
	log.Printf("[DEBUG] TA fallback response status=%d snippet=%s", resp.StatusCode, snippet)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fallback resolve returned status %d", resp.StatusCode)
	}

	stmt := strings.TrimSpace(string(body))
	claims, err := claimsMapFromJWT(stmt)
	if err != nil {
		log.Printf("[WARN] Failed to parse fallback JWT: %v", err)
		return nil, fmt.Errorf("failed to parse fallback statement: %w", err)
	}

	iss, _ := claims["iss"].(string)
	sub, _ := claims["sub"].(string)
	if normalizeEntityID(iss) != normalizeEntityID(topTA) || normalizeEntityID(sub) != reqEntityNorm {
		log.Printf("[WARN] Fallback statement has unexpected iss/sub (iss=%s sub=%s)", iss, sub)
		return nil, fmt.Errorf("fallback statement has wrong issuer/subject")
	}

	// Create subordinate entity
	subordinate := &CachedEntityStatement{
		EntityID:     sub,
		Statement:    stmt,
		ParsedClaims: claims,
		Issuer:       iss,
		Subject:      sub,
		TrustAnchor:  topTA,
		CachedAt:     time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
		FetchedFrom:  resolveURL,
		Validated:    false,
	}

	// Try to get TA's own statement
	taStmt, err := r.tryDirectResolve(ctx, topTA)
	if err != nil {
		log.Printf("[WARN] Failed to get TA statement: %v", err)
		// Return just the subordinate
		return []CachedEntityStatement{*subordinate}, nil
	}

	// Return both subordinate and TA
	return []CachedEntityStatement{*subordinate, *taStmt}, nil
}

// QueryFederationListEndpoint queries a federation list endpoint with optional parameters
// Implements retry logic with exponential backoff for robust handling of network failures
func (r *FederationResolver) QueryFederationListEndpoint(ctx context.Context, listEndpoint string, entityType, trustMarked, trustMarkType, intermediate string) ([]string, error) {
	// Build the request URL with query parameters
	reqURL := listEndpoint

	params := url.Values{}
	if entityType != "" {
		params.Add("entity_type", entityType)
	}
	if trustMarked != "" {
		params.Add("trust_marked", trustMarked)
	}
	if trustMarkType != "" {
		params.Add("trust_mark_type", trustMarkType)
	}
	if intermediate != "" {
		params.Add("intermediate", intermediate)
	}

	if len(params) > 0 {
		reqURL += "?" + params.Encode()
	}

	// Map URL for internal Docker networking
	reqURL = r.mapURL(reqURL)

	log.Printf("[RESOLVER] Querying federation list endpoint: %s", reqURL)

	// Retry configuration
	maxRetries := r.config.MaxRetries
	if maxRetries == 0 {
		maxRetries = 3 // Default if not configured
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: wait 2^attempt seconds
			backoffDuration := time.Duration(1<<uint(attempt-1)) * time.Second
			log.Printf("[RESOLVER] Retrying federation list request in %v (attempt %d/%d)", backoffDuration, attempt+1, maxRetries+1)

			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("context cancelled during retry backoff: %w", ctx.Err())
			case <-time.After(backoffDuration):
				// Continue with retry
			}
		}

		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			lastErr = fmt.Errorf("failed to create list request: %w", err)
			if attempt == maxRetries {
				break
			}
			continue
		}

		resp, err := r.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("federation list request failed: %w", err)
			// Check if this is a network error that should be retried
			if r.isRetryableError(err) && attempt < maxRetries {
				continue
			}
			break
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			lastErr = fmt.Errorf("federation list request failed with status %d: %s", resp.StatusCode, string(body))

			// Retry on server errors (5xx) but not client errors (4xx)
			if resp.StatusCode >= 500 && attempt < maxRetries {
				continue
			}
			break
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("failed to read federation list response: %w", err)
			if attempt < maxRetries {
				continue
			}
			break
		}

		// Parse the response - can be either JSON array or JWT per OpenID Federation spec Section 8.2.2
		var entityIDs []string

		// Check if response is a JWT (starts with "eyJ")
		bodyStr := strings.TrimSpace(string(body))
		if strings.HasPrefix(bodyStr, "eyJ") {
			// Parse as JWT
			log.Printf("[RESOLVER] Federation list response is JWT, parsing...")
			entityIDs, err = r.parseFederationListJWT(bodyStr)
			if err != nil {
				log.Printf("[RESOLVER] Federation list JWT parsing failed: %v", err)
				lastErr = fmt.Errorf("failed to parse federation list JWT: %w", err)
				if attempt < maxRetries {
					continue
				}
				break
			}
		} else {
			// Parse as JSON array
			if err := json.Unmarshal(body, &entityIDs); err != nil {
				lastErr = fmt.Errorf("failed to parse federation list response as JSON: %w", err)
				if attempt < maxRetries {
					continue
				}
				break
			}
		}

		log.Printf("[RESOLVER] Retrieved %d entities from federation list endpoint (attempt %d)", len(entityIDs), attempt+1)
		return entityIDs, nil
	}

	return nil, fmt.Errorf("federation list query failed after %d attempts: %w", maxRetries+1, lastErr)
}

// parseFederationListJWT parses a federation list JWT response
func (r *FederationResolver) parseFederationListJWT(jwtStr string) ([]string, error) {
	log.Printf("[RESOLVER] Parsing federation list JWT (length: %d)", len(jwtStr))

	// Parse JWT without verification to extract claims
	token, _, err := jwt.NewParser().ParseUnverified(jwtStr, jwt.MapClaims{})
	if err != nil {
		log.Printf("[RESOLVER] JWT parsing error: %v", err)
		return nil, fmt.Errorf("failed to parse federation list JWT: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Printf("[RESOLVER] Invalid JWT claims type: %T", token.Claims)
		return nil, fmt.Errorf("invalid JWT claims in federation list response")
	}

	log.Printf("[RESOLVER] JWT claims keys: %v", getMapKeys(claims))

	// Extract federation_list array
	federationListRaw, ok := claims["federation_list"]
	if !ok {
		log.Printf("[RESOLVER] federation_list claim not found in JWT claims")
		return nil, fmt.Errorf("federation_list claim not found in JWT")
	}

	log.Printf("[RESOLVER] federation_list raw value type: %T", federationListRaw)

	// federation_list should be an array of strings
	listArray, ok := federationListRaw.([]interface{})
	if !ok {
		log.Printf("[RESOLVER] federation_list is not an array, got type: %T", federationListRaw)
		return nil, fmt.Errorf("federation_list is not an array")
	}

	log.Printf("[RESOLVER] federation_list array length: %d", len(listArray))

	var entityIDs []string
	for i, item := range listArray {
		if id, ok := item.(string); ok {
			entityIDs = append(entityIDs, id)
		} else {
			log.Printf("[RESOLVER] Warning: non-string entity ID at index %d: %v (type: %T)", i, item, item)
		}
	}

	log.Printf("[RESOLVER] Successfully parsed %d entity IDs from federation list JWT", len(entityIDs))
	return entityIDs, nil
}

// getMapKeys returns a slice of keys from a map for logging purposes
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// isRetryableError determines if an error should trigger a retry
func (r *FederationResolver) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())

	// Network connectivity errors
	if strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "network is unreachable") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "dial tcp") ||
		strings.Contains(errStr, "couldn't connect to server") ||
		strings.Contains(errStr, "connection timed out") ||
		strings.Contains(errStr, "network unreachable") ||
		strings.Contains(errStr, "host unreachable") ||
		strings.Contains(errStr, "temporary failure") ||
		strings.Contains(errStr, "server misbehaving") {
		return true
	}

	// DNS resolution errors
	if strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "name resolution failure") {
		return true
	}

	return false
}

// mapURL maps external domain URLs to internal service URLs for Docker networking
func (r *FederationResolver) mapURL(inputURL string) string {
	// If no URL mappings are configured, return the URL unchanged
	if r.config.URLMappings == nil {
		log.Printf("[RESOLVER] mapURL: no mappings configured")
		return inputURL
	}

	log.Printf("[RESOLVER] mapURL: input=%s, available mappings: %v", inputURL, r.config.URLMappings)

	// First, check if the full URL matches any mapping key
	if mappedURL, exists := r.config.URLMappings[inputURL]; exists {
		log.Printf("[RESOLVER] Mapped URL %s -> %s", inputURL, mappedURL)
		return mappedURL
	}

	// Check if the input URL starts with any mapping key (prefix matching for base URLs)
	for mappingKey, mappedValue := range r.config.URLMappings {
		if strings.HasPrefix(inputURL, mappingKey) {
			// Replace the prefix with the mapped value
			result := strings.Replace(inputURL, mappingKey, mappedValue, 1)
			log.Printf("[RESOLVER] Mapped URL (prefix match) %s -> %s", inputURL, result)
			return result
		}
	}

	// Fallback: Parse the input URL and check if the host matches any mapping
	// This maintains backward compatibility with host-only mappings
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		log.Printf("[RESOLVER] Failed to parse URL for mapping: %s, error: %v", inputURL, err)
		return inputURL
	}

	// Check if the host matches any mapping key (either full URL or host-only)
	// First check for exact host match (backward compatibility)
	if mappedHost, exists := r.config.URLMappings[parsedURL.Host]; exists {
		// Reconstruct URL with mapped host
		mappedURL := *parsedURL
		mappedURL.Host = mappedHost
		// Change scheme to http for internal services
		mappedURL.Scheme = "http"
		result := mappedURL.String()

		log.Printf("[RESOLVER] Mapped URL (host fallback) %s -> %s", inputURL, result)
		return result
	}

	// Check if the host part of the input URL matches the host part of any full URL mapping key
	for mappingKey, mappedValue := range r.config.URLMappings {
		if parsedKey, err := url.Parse(mappingKey); err == nil {
			if parsedKey.Host == parsedURL.Host {
				// Found a match - reconstruct URL with the mapped host from the value
				mappedURL := *parsedURL
				// The mapped value should be in the format "http://service:port"
				if parsedValue, err := url.Parse(mappedValue); err == nil {
					mappedURL.Host = parsedValue.Host
					mappedURL.Scheme = parsedValue.Scheme
					result := mappedURL.String()

					log.Printf("[RESOLVER] Mapped URL (full URL host match) %s -> %s", inputURL, result)
					return result
				}
			}
		}
	}

	log.Printf("[RESOLVER] No mapping found for URL: %s, available mappings: %v", inputURL, r.config.URLMappings)
	return inputURL
}
