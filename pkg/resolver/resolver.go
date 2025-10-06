package resolver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/url"
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
		config:         config,
		entityCache:    cache.New(24*time.Hour, 30*time.Minute), // default expiration 24h, cleanup every 30min
		chainCache:     cache.New(24*time.Hour, 30*time.Minute),
		cachedEntities: make(map[string]*CachedEntityStatement),
		httpClient: &http.Client{
			Timeout: config.RequestTimeout,
		},
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
			log.Printf("[RESOLVER] Cache hit for entity %s via %s", entityID, trustAnchor)
			statement := cached.(*CachedEntityStatement)
			r.cachedEntities[cacheKey] = statement
			return statement, nil
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
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("federation resolve failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read federation resolve response: %w", err)
	}

	statement := string(body)
	log.Printf("[RESOLVER] Federation resolve successful, statement length: %d", len(statement))

	return r.parseEntityStatement(entityID, statement, resolveURL, trustAnchor)
}

// Try direct well-known endpoint
func (r *FederationResolver) tryDirectResolve(ctx context.Context, entityID string) (*CachedEntityStatement, error) {
	wellKnownURL := fmt.Sprintf("%s/.well-known/openid-federation", entityID)

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
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("direct resolve failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read direct resolve response: %w", err)
	}

	statement := string(body)
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
		EntityID:    entityID,
		Statement:   statement,
		Issuer:      entityID,
		Subject:     entityID,
		TrustAnchor: trustAnchor,
		CachedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(time.Hour),
		FetchedFrom: fetchedFrom,
		Validated:   false,
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
			log.Printf("[RESOLVER] Cache hit for entity %s via any", entityID)
			statement := cached.(*CachedEntityStatement)
			r.cachedEntities[cacheKey] = statement
			return statement, nil
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
			log.Printf("[RESOLVER] Cache hit for trust chain %s", entityID)
			return cached.(*CachedTrustChain), nil
		}
	}

	// Build the trust chain by following authority hints
	chain, trustAnchor, err := r.buildTrustChain(ctx, entityID, forceRefresh, make(map[string]bool))
	if err != nil {
		log.Printf("[RESOLVER] Failed to build trust chain for %s: %v", entityID, err)
		// Return a chain with error status
		chain := &CachedTrustChain{
			EntityID:    entityID,
			TrustAnchor: "",
			Status:      "error",
			CachedAt:    time.Now(),
			ExpiresAt:   time.Now().Add(24 * time.Hour),
			Chain:       []CachedEntityStatement{},
		}
		r.chainCache.Set(cacheKey, chain, time.Until(chain.ExpiresAt))
		return chain, nil
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
		log.Printf("[RESOLVER] Trust chain validation failed for %s: %v", entityID, err)
		cachedChain.Status = "invalid"
	} else {
		log.Printf("[RESOLVER] Trust chain validation successful for %s", entityID)
	}

	// Cache the result
	r.chainCache.Set(cacheKey, cachedChain, time.Until(cachedChain.ExpiresAt))

	log.Printf("[RESOLVER] Successfully built trust chain for %s with %d entities", entityID, len(chain))
	return cachedChain, nil
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
func (r *FederationResolver) buildTrustChain(ctx context.Context, entityID string, forceRefresh bool, visited map[string]bool) ([]CachedEntityStatement, string, error) {
	// Prevent infinite loops
	if visited[entityID] {
		return nil, "", fmt.Errorf("cycle detected in trust chain for entity %s", entityID)
	}
	visited[entityID] = true

	log.Printf("[RESOLVER] Building trust chain segment for %s", entityID)

	// Resolve the current entity
	entity, err := r.ResolveEntityAny(ctx, entityID, forceRefresh)
	if err != nil {
		return nil, "", fmt.Errorf("failed to resolve entity %s: %w", entityID, err)
	}

	// Check if this entity is a trust anchor
	for _, ta := range r.config.TrustAnchors {
		if entityID == ta {
			log.Printf("[RESOLVER] Found trust anchor %s", entityID)
			return []CachedEntityStatement{*entity}, entityID, nil
		}
	}

	// Get authority hints from the entity's metadata
	authorityHints, err := r.extractAuthorityHints(entity)
	if err != nil {
		return nil, "", fmt.Errorf("failed to extract authority hints from %s: %w", entityID, err)
	}

	if len(authorityHints) == 0 {
		return nil, "", fmt.Errorf("entity %s has no authority hints and is not a trust anchor", entityID)
	}

	// Try each authority hint
	for _, authorityID := range authorityHints {
		log.Printf("[RESOLVER] Following authority hint %s for entity %s", authorityID, entityID)

		// Recursively build chain for this authority
		subChain, trustAnchor, err := r.buildTrustChain(ctx, authorityID, forceRefresh, visited)
		if err != nil {
			log.Printf("[RESOLVER] Failed to build chain via authority %s: %v", authorityID, err)
			continue
		}

		// Build the complete chain: entity -> authority -> ... -> trust anchor
		completeChain := append([]CachedEntityStatement{*entity}, subChain...)
		log.Printf("[RESOLVER] Successfully built chain via authority %s: %d entities", authorityID, len(completeChain))
		return completeChain, trustAnchor, nil
	}

	return nil, "", fmt.Errorf("could not build trust chain for %s through any authority hint", entityID)
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

	// Resolve the current entity
	entity, err := r.ResolveEntity(ctx, entityID, requestedTrustAnchor, forceRefresh)
	if err != nil {
		return nil, "", fmt.Errorf("failed to resolve entity %s: %w", entityID, err)
	}

	// Get authority hints from the entity's metadata
	authorityHints, err := r.extractAuthorityHints(entity)
	if err != nil {
		return nil, "", fmt.Errorf("failed to extract authority hints from %s: %w", entityID, err)
	}

	if len(authorityHints) == 0 {
		return nil, "", fmt.Errorf("entity %s has no authority hints and is not the target trust anchor %s", entityID, requestedTrustAnchor)
	}

	// Try each authority hint, but only follow paths that can lead to the requested trust anchor
	for _, authorityID := range authorityHints {
		log.Printf("[RESOLVER] Following authority hint %s for entity %s (targeting %s)", authorityID, entityID, requestedTrustAnchor)

		// Skip if authority hint doesn't match our target anchor and isn't configured as a trust anchor
		// This is a simple optimization - in complex federations you might need more sophisticated routing
		validPath := false
		if authorityID == requestedTrustAnchor {
			validPath = true
		} else {
			// Check if this authority is a known trust anchor that could lead to our target
			for _, ta := range r.config.TrustAnchors {
				if authorityID == ta {
					validPath = true
					break
				}
			}
		}

		if !validPath {
			log.Printf("[RESOLVER] Skipping authority %s as it doesn't appear to lead to target anchor %s", authorityID, requestedTrustAnchor)
			continue
		}

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

		// Build the complete chain: entity -> authority -> ... -> trust anchor
		completeChain := append([]CachedEntityStatement{*entity}, subChain...)
		log.Printf("[RESOLVER] Successfully built chain via authority %s: %d entities", authorityID, len(completeChain))
		return completeChain, trustAnchor, nil
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

// fetchJWKSetFromURL fetches JWK Set from a URL
func (r *FederationResolver) fetchJWKSetFromURL(ctx context.Context, url string, kid interface{}) (interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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

	body, err := ioutil.ReadAll(resp.Body)
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
func (r *FederationResolver) validateTrustChain(ctx context.Context, chain []CachedEntityStatement) error {
	if !r.config.ValidateSignatures {
		log.Printf("[RESOLVER] Signature validation disabled, skipping trust chain validation")
		return nil
	}

	log.Printf("[RESOLVER] Validating trust chain with %d entities", len(chain))

	for i := range chain {
		entity := &chain[i] // Get pointer to the struct in the slice
		var expectedIssuer string
		if i == len(chain)-1 {
			// Last entity (trust anchor) should be self-signed
			expectedIssuer = entity.Subject
		} else {
			// Each entity should be signed by the next entity in the chain (towards trust anchor)
			expectedIssuer = chain[i+1].Subject
		}

		if entity.Issuer != expectedIssuer {
			return fmt.Errorf("entity %s has issuer %s, expected %s", entity.Subject, entity.Issuer, expectedIssuer)
		}

		// Validate the JWT signature
		valid, err := r.validateJWTSignature(ctx, entity.Statement, entity.Issuer)
		if err != nil {
			return fmt.Errorf("signature validation failed for entity %s: %w", entity.Subject, err)
		}
		if !valid {
			return fmt.Errorf("invalid signature for entity %s", entity.Subject)
		}

		// Mark as validated
		entity.Validated = true
	}

	log.Printf("[RESOLVER] Trust chain validation successful")
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
		return item.(*CachedEntityStatement), true
	}
	return nil, false
}

// GetCachedEntityAny retrieves a cached entity resolved via any trust anchor
func (r *FederationResolver) GetCachedEntityAny(entityID string) (*CachedEntityStatement, bool) {
	cacheKey := fmt.Sprintf("%s:any", entityID)
	if item, found := r.entityCache.Get(cacheKey); found {
		return item.(*CachedEntityStatement), true
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
