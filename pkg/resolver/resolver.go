package resolver

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	cache "resolver/pkg/cache"
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
		entityCache:       cache.NewCache("entity_statements"),
		chainCache:        cache.NewCache("trust_chains"),
		cachedEntities:    make(map[string]*CachedEntityStatement),
		registeredAnchors: make(map[string]*TrustAnchorRegistration),
		httpClient: &http.Client{
			Timeout: config.RequestTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: config.SkipTLSVerify},
			},
		},
	}

	// Initialize default KeyProvider
	resolver.KeyProvider = &DefaultKeyProvider{r: resolver}

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
				r.entityCache.Remove(cacheKey)
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
	// Request entity statements/JWTs explicitly
	req.Header.Set("Accept", "application/entity-statement+jwt, application/jwt, */*")

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
	// Diagnostic: log first N chars of the response to help debugging resolve responses
	maxDump := 300
	if len(resolveResponse) > maxDump {
		log.Printf("[RESOLVER][DIAG] Federation resolve response snippet: %s", resolveResponse[:maxDump])
	} else {
		log.Printf("[RESOLVER][DIAG] Federation resolve response snippet: %s", resolveResponse)
	}

	// The /resolve endpoint returns a resolve-response+jwt that may contain the entity statement
	// We need to extract the actual entity-statement from it
	statement := resolveResponse

	// Check if this is a JWT (resolve-response+jwt)
	if strings.Count(resolveResponse, ".") == 2 {
		// Parse the resolve-response to extract inner entity statement
		parts := strings.Split(resolveResponse, ".")
		if len(parts) == 3 {
			// Inspect header to determine typ
			headB, herr := base64.RawURLEncoding.DecodeString(parts[0])
			var header map[string]interface{}
			if herr == nil {
				_ = json.Unmarshal(headB, &header)
			}

			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err == nil {
				var claims map[string]interface{}
				if json.Unmarshal(payload, &claims) == nil {
					// If this is a resolve-response+jwt and it contains an inner
					// entity-statement under metadata.statement, extract it. If
					// not present, fall back to direct well-known fetch so we
					// don't treat a resolve-response as an entity-statement.
					if metadata, ok := claims["metadata"].(map[string]interface{}); ok {
						if innerStmt, ok := metadata["statement"].(string); ok && strings.Count(innerStmt, ".") == 2 {
							log.Printf("[RESOLVER] Extracted inner entity-statement from resolve-response")
							statement = innerStmt
						} else {
							// If header indicates this is a resolve-response, fall back
							// to direct fetch for the actual entity-statement.
							if th, ok := header["typ"].(string); ok && th == "resolve-response+jwt" {
								log.Printf("[RESOLVER] resolve-response does not contain inner statement; falling back to direct fetch for %s", entityID)
								return r.tryDirectResolve(ctx, entityID)
							}
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
	log.Printf("[RESOLVER] Trying direct resolve for %s", entityID)
	statement, fetchedFrom, err := r.FetchWellKnownOpenIDFederation(ctx, entityID)
	if err != nil {
		return nil, err
	}
	log.Printf("[RESOLVER] Direct resolve successful, statement length: %d", len(statement))
	return r.parseEntityStatement(entityID, statement, fetchedFrom, "")
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
				r.entityCache.Remove(cacheKey)
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
				r.chainCache.Remove(cacheKey)
			} else {
				log.Printf("[RESOLVER] Cache hit for trust chain %s", entityID)
				// If any entity within the cached chain is expired, treat the cached chain as expired
				for _, ent := range chain.Chain {
					if time.Now().After(ent.ExpiresAt) {
						log.Printf("[RESOLVER] Cached trust chain for %s contains expired entity %s, removing cached chain", entityID, ent.EntityID)
						r.chainCache.Remove(cacheKey)
						// fallthrough to rebuild
						goto rebuild
					}
				}
				return chain, nil
			}
		}
	rebuild:
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

			// Cache the result (StoreCachedChain handles dedupe-on-write)
			r.StoreCachedChain(cacheKey, cachedChain)

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

			// Cache the result (StoreCachedChain handles dedupe-on-write)
			r.StoreCachedChain(cacheKey, cachedChain)

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
	// Cache the error chain (StoreCachedChain handles dedupe)
	r.StoreCachedChain(cacheKey, errorChain)

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
		// Cache the error chain (StoreCachedChain handles dedupe)
		r.StoreCachedChain(cacheKey, errorChain)
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

	// Cache the result (StoreCachedChain handles dedupe)
	r.StoreCachedChain(cacheKey, cachedChain)

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
		// Get the public key for this issuer via KeyProvider
		if r.KeyProvider != nil {
			pub, err := r.KeyProvider.GetPublicKey(ctx, issuer, token.Header["kid"])
			if err != nil {
				return nil, fmt.Errorf("failed to get public key for issuer %s: %w", issuer, err)
			}
			return pub, nil
		}

		// Fallback to existing behavior
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
		if r.KeyProvider != nil {
			pub, err := r.KeyProvider.GetPublicKeyForEntity(ctx, issuer, token.Header["kid"], currentEntity)
			if err != nil {
				return nil, fmt.Errorf("failed to get public key for issuer %s: %w", issuer, err)
			}
			return pub, nil
		}

		// Fallback to existing behavior
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

	// Let KeyProvider select a key from the extracted JWKSet
	if r.KeyProvider != nil {
		return r.KeyProvider.SelectKey(jwks, kid)
	}

	// Use centralized selection helper
	return SelectKeyFromJWKSet(r, jwks, kid)
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

		// Let KeyProvider select a key from the extracted JWKSet
		if r.KeyProvider != nil {
			return r.KeyProvider.SelectKey(jwks, kid)
		}

		// Fallback to local selection
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

		return nil, fmt.Errorf("no suitable public key found in self-signed entity %s", issuer)
	}

	// Normal case: resolve the issuer entity
	return r.getIssuerPublicKey(ctx, issuer, kid)
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

func (r *FederationResolver) CheckTrustAnchor(ctx context.Context, trustAnchor string) error {
	_, _, err := r.FetchWellKnownOpenIDFederation(ctx, trustAnchor)
	if err != nil {
		return fmt.Errorf("trust anchor check failed: %w", err)
	}
	return nil
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
		// Try to prepend self-signed leaf if available
		if selfSigned, err2 := r.ResolveEntity(context.Background(), requestedEntity, requestedEntity, false); err2 == nil && selfSigned != nil {
			return []CachedEntityStatement{*selfSigned, *subordinate}, nil
		}
		// Return just the subordinate
		return []CachedEntityStatement{*subordinate}, nil
	}

	// Try to prepend self-signed leaf if available
	if selfSigned, err2 := r.ResolveEntity(context.Background(), requestedEntity, requestedEntity, false); err2 == nil && selfSigned != nil {
		// Avoid prepending if an equivalent issuer+subject already exists in subordinate or taStmt
		leafKey := normalizeEntityID(selfSigned.Issuer) + " " + normalizeEntityID(selfSigned.Subject)
		subordinateKey := normalizeEntityID(subordinate.Issuer) + " " + normalizeEntityID(subordinate.Subject)
		taKey := normalizeEntityID(taStmt.Issuer) + " " + normalizeEntityID(taStmt.Subject)
		if leafKey != subordinateKey && leafKey != taKey {
			return []CachedEntityStatement{*selfSigned, *subordinate, *taStmt}, nil
		}
		// If duplicate, just return subordinate+taStmt (they already include the leaf)
		return []CachedEntityStatement{*subordinate, *taStmt}, nil
	}

	// Return subordinate and TA
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
