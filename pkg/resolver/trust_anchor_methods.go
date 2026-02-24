package resolver

import (
	"context"

	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"

	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/harrykodden/keymanager"
)

// RegisterTrustAnchor registers a trust anchor with the resolver
func (r *FederationResolver) RegisterTrustAnchor(registration *TrustAnchorRegistration) error {
	if r.registeredAnchors == nil {
		r.registeredAnchors = make(map[string]*TrustAnchorRegistration)
	}

	// Store the registration
	registration.RegisteredAt = time.Now()
	r.registeredAnchors[registration.EntityID] = registration

	log.Printf("[RESOLVER] Registered trust anchor: %s", registration.EntityID)
	return nil
}

// UnregisterTrustAnchor removes a trust anchor registration
func (r *FederationResolver) UnregisterTrustAnchor(entityID string) error {
	if r.registeredAnchors == nil {
		return fmt.Errorf("trust anchor %s not found", entityID)
	}

	if _, exists := r.registeredAnchors[entityID]; !exists {
		return fmt.Errorf("trust anchor %s not found", entityID)
	}

	delete(r.registeredAnchors, entityID)
	log.Printf("[RESOLVER] Unregistered trust anchor: %s", entityID)
	return nil
}

// ListRegisteredTrustAnchors returns all registered trust anchors
func (r *FederationResolver) ListRegisteredTrustAnchors() map[string]*TrustAnchorRegistration {
	if r.registeredAnchors == nil {
		return make(map[string]*TrustAnchorRegistration)
	}
	return r.registeredAnchors
}

// IsAuthorizedForTrustAnchor checks if resolver can sign for a trust anchor
func (r *FederationResolver) IsAuthorizedForTrustAnchor(trustAnchor string) bool {
	if r.registeredAnchors == nil {
		return false
	}

	registration, exists := r.registeredAnchors[trustAnchor]
	if !exists {
		return false
	}

	// Check if registration has expired
	return time.Now().Before(registration.ExpiresAt)
}

// CreateSignedTrustChainResponse creates a signed JWT response for a trust chain
func (r *FederationResolver) CreateSignedTrustChainResponse(trustChain *CachedTrustChain, trustAnchor string) (string, error) {
	return r.CreateSignedTrustChainResponseWithContext(context.Background(), trustChain, trustAnchor)
}

func (r *FederationResolver) CreateSignedTrustChainResponseWithContext(ctx context.Context, trustChain *CachedTrustChain, trustAnchor string) (string, error) {
	if !r.IsAuthorizedForTrustAnchor(trustAnchor) {
		return "", fmt.Errorf("not authorized to sign for trust anchor %s", trustAnchor)
	}

	// Get trust anchor registration
	_ = r.registeredAnchors[trustAnchor] // Used for authorization check above

	// Ensure chain is deduplicated (defensive: in case callers didn't sanitize)
	if trustChain != nil {
		trustChain.Chain = DeduplicateCachedChain(trustChain.Chain)
	}

	// Create response payload
	now := time.Now()
	response := ResolverSignedResponse{
		EntityID:    trustChain.EntityID,
		TrustAnchor: trustAnchor,
		TrustChain:  trustChain.Chain,
		IssuedAt:    now,
		ExpiresAt:   now.Add(24 * time.Hour),   // Valid for 24 hours
		Issuer:      r.config.ResolverEntityID, // You'd need to add this to config
	}

	// Extract metadata from the trust chain
	if len(trustChain.Chain) > 0 {
		response.Metadata = trustChain.Chain[0].ParsedClaims
		// If ParsedClaims already include provider metadata (possibly nested under
		// a "metadata" key), treat the first chain element as authoritative.
		// This covers cases where the CachedEntityStatement.ParsedClaims holds
		// the parsed payload rather than the compact JWT string.
		if response.Metadata != nil {
			// direct provider metadata at top-level
			if _, ok := response.Metadata["openid_provider"]; ok {
				if s := trustChain.Chain[0].Statement; strings.Count(s, ".") == 2 {
					response.Metadata["statement"] = s
				}
			} else if md, ok := response.Metadata["metadata"].(map[string]interface{}); ok {
				// nested metadata (some parsers nest under a metadata key)
				if _, ok2 := md["openid_provider"]; ok2 {
					if s := trustChain.Chain[0].Statement; strings.Count(s, ".") == 2 {
						response.Metadata["statement"] = s
					}
				}
			}
		}

		// Per OpenID Federation: when returning a resolve-response+jwt wrapper, the
		// resolver MUST include the authoritative entity-statement in
		// metadata.statement so clients can revalidate the chain locally.
		// Defensive behavior (robust):
		// 1) Prefer an inner statement found in the first chain element's payload
		//    (payload-first — more tolerant of incorrect header.typ).
		// 2) If not present, prefer the first bona fide entity-statement header.
		// 3) As a last-resort, accept a statement whose payload clearly contains
		//    jwks or openid_provider metadata even if the header is missing/incorrect.
		if len(trustChain.Chain) > 0 {
			firstStmt := trustChain.Chain[0].Statement
			var selected string
			// helper: quick check for compact JWT shape
			isCompact := func(s string) bool { return strings.Count(s, ".") == 2 }

			// 1) Try payload-first: extract metadata.statement regardless of typ
			if isCompact(firstStmt) {
				if inner := extractMetadataStatement(firstStmt); inner != "" {
					selected = inner
				}
			}

			// 2) If still empty, inspect headers and prefer explicit entity-statement
			if selected == "" {
				for i, it := range trustChain.Chain {
					log.Printf("[DEBUG] CreateSignedTrustChainResponse: inspecting chain[%d] entity=%s statement_len=%d", i, it.EntityID, len(it.Statement))
					if !isCompact(it.Statement) {
						log.Printf("[DEBUG] chain[%d] not compact JWT, skipping header check", i)
						// still try to inspect parsed claims below
					} else {
						headB := strings.SplitN(it.Statement, ".", 3)[0]
						if hb, err := base64.RawURLEncoding.DecodeString(padBase64(headB)); err == nil {
							var hdr map[string]interface{}
							_ = json.Unmarshal(hb, &hdr)
							log.Printf("[DEBUG] chain[%d] JWT header: %v", i, hdr)
							if th, _ := hdr["typ"].(string); th == "entity-statement+jwt" {
								selected = it.Statement
								log.Printf("[DEBUG] chain[%d] selected by header typ=entity-statement+jwt", i)
								break
							}
						} else {
							log.Printf("[DEBUG] chain[%d] header decode error: %v", i, err)
						}

						// continue to payload-fingerprint below if header did not match
					}

					// 3) resilience: if header missing/incorrect, accept by payload fingerprint
					plParts := strings.SplitN(it.Statement, ".", 3)
					if len(plParts) == 3 {
						if pb, err := base64.RawURLEncoding.DecodeString(padBase64(plParts[1])); err == nil {
							var c map[string]interface{}
							_ = json.Unmarshal(pb, &c)
							log.Printf("[DEBUG] chain[%d] payload keys: %v", i, getMapKeys(c))
							if _, hasJWKS := c["jwks"]; hasJWKS {
								selected = it.Statement
								log.Printf("[DEBUG] chain[%d] selected by payload jwks", i)
								break
							}
							if md, ok := c["metadata"].(map[string]interface{}); ok {
								if _, hasOP := md["openid_provider"]; hasOP {
									selected = it.Statement
									log.Printf("[DEBUG] chain[%d] selected by payload.metadata.openid_provider", i)
									break
								}
							}
						}
						// if ParsedClaims already exist and include metadata, prefer that
						if it.ParsedClaims != nil {
							log.Printf("[DEBUG] chain[%d] has ParsedClaims keys: %v", i, getMapKeys(it.ParsedClaims))
							// prefer nested metadata.openid_provider (canonical)
							if md, ok := it.ParsedClaims["metadata"].(map[string]interface{}); ok {
								if _, hasOP := md["openid_provider"]; hasOP {
									selected = it.Statement
									log.Printf("[DEBUG] chain[%d] selected by ParsedClaims.metadata.openid_provider", i)
									break
								}
							}
							// resilience: accept top-level jwks in ParsedClaims as authoritative
							if _, hasJWKS := it.ParsedClaims["jwks"]; hasJWKS {
								selected = it.Statement
								log.Printf("[DEBUG] chain[%d] selected by ParsedClaims.jwks", i)
								break
							}
						}
					}
				}
			}

			// set the metadata.statement if we found one
			if selected != "" {
				if response.Metadata == nil {
					response.Metadata = map[string]interface{}{"statement": selected}
				} else {
					response.Metadata["statement"] = selected
				}
			} else {
				// no authoritative statement found — leave metadata as-is and log
				log.Printf("[WARN] CreateSignedTrustChainResponse: no authoritative entity-statement found to embed in metadata.statement for %s", trustChain.EntityID)
			}
		}
	}

	// Create JWT with trust chain always included
	// Per OpenID Federation spec Section 8.3.2:
	// The resolver endpoint MUST return a signed JWT with "iss" set to the resolver's entity ID
	// But for compliance with OIDFED-3, the iss must match the endpoint location
	resolverEntityID := r.config.ResolverEntityID
	if resolverEntityID == "" {
		// Fallback: use the trust anchor if resolver has no entity ID
		resolverEntityID = trustAnchor
	}

	claims := jwt.MapClaims{
		"iss":          resolverEntityID, // Resolver's entity ID (must match resolve endpoint location)
		"sub":          response.EntityID,
		"aud":          trustAnchor,
		"iat":          response.IssuedAt.Unix(),
		"exp":          response.ExpiresAt.Unix(),
		"trust_chain":  convertChainToJWTArray(trustChain.Chain),
		"metadata":     response.Metadata,
		"trust_anchor": trustAnchor,
	}
	// Add validation status
	if trustChain.Status == "valid" {
		claims["validation_status"] = "valid"
	} else {
		claims["validation_status"] = "invalid"
	}

	// Attempt to sign using KeyManager (Vault or file-backed) if available
	if r.KeyManager != nil && r.signingkid != "" {
		// Build header and payload JSON for compact signing
		hdr := map[string]interface{}{"typ": "resolve-response+jwt", "kid": r.getResolverSigningKeyID()}

		// Choose alg header based on configured signing key type if possible
		if r.signingKey != nil {
			switch r.signingKey.(type) {
			case *rsa.PrivateKey:
				hdr["alg"] = "RS256"
			default:
				hdr["alg"] = "ES256"
			}
		} else {
			// Default to ES256 for KeyManager-produced keys
			hdr["alg"] = "ES256"
		}

		hb, _ := json.Marshal(hdr)
		pb, _ := json.Marshal(claims)
		hdrEnc := base64.RawURLEncoding.EncodeToString(hb)
		pldEnc := base64.RawURLEncoding.EncodeToString(pb)
		signingInput := fmt.Sprintf("%s.%s", hdrEnc, pldEnc)

		sig, err := r.KeyManager.Sign(ctx, r.getResolverSigningKeyID(), []byte(signingInput))
		if err == nil {
			sigEnc := base64.RawURLEncoding.EncodeToString(sig)
			return signingInput + "." + sigEnc, nil
		}
		// fallback to local signing below if KeyManager.Sign failed
		log.Printf("[RESOLVER] warning: KeyManager.Sign failed: %v, falling back to local key", err)
	}

	// Fallback: sign using local/private key via jwt library
	signingKey, err := r.getSigningKeyForTrustAnchor(ctx, trustAnchor)
	if err != nil {
		return "", fmt.Errorf("failed to get signing key: %w", err)
	}

	var signingMethod jwt.SigningMethod
	switch signingKey.(type) {
	case *rsa.PrivateKey:
		signingMethod = jwt.SigningMethodRS256
	default:
		signingMethod = jwt.SigningMethodES256
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	token.Header["typ"] = "resolve-response+jwt"
	token.Header["kid"] = r.getResolverSigningKeyID()

	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ResolveAndSign resolves a trust chain and returns a signed response
func (r *FederationResolver) ResolveAndSign(ctx context.Context, entityID, trustAnchor string) (string, error) {
	// First resolve the trust chain
	trustChain, err := r.ResolveTrustChainWithAnchor(ctx, entityID, trustAnchor, false)
	if err != nil {
		return "", fmt.Errorf("failed to resolve trust chain: %w", err)
	}

	// Then create signed response (propagate ctx)
	return r.CreateSignedTrustChainResponseWithContext(ctx, trustChain, trustAnchor)
}

// Helper functions

func (r *FederationResolver) getResolverSigningKeyID() string {
	return r.signingkid
}

// padBase64 and extractMetadataStatement moved to utils.go

func (r *FederationResolver) getSigningKeyForTrustAnchor(ctx context.Context, trustAnchor string) (crypto.PrivateKey, error) {
	_, exists := r.registeredAnchors[trustAnchor]
	if !exists {
		return nil, fmt.Errorf("trust anchor not registered")
	}

	// Prefer KeyManager-provided signing key if available
	if r.KeyManager != nil && r.signingkid != "" {
		if sk, err := r.KeyManager.GetSigningKey(ctx, r.signingkid); err == nil {
			if priv, ok := sk.(crypto.PrivateKey); ok {
				return priv, nil
			}
			// fallback: return whatever was stored in resolver
		}
	}
	if sk, ok := r.signingKey.(crypto.PrivateKey); ok {
		return sk, nil
	}
	return nil, fmt.Errorf("no signing key available")
}

func convertChainToJWTArray(chain []CachedEntityStatement) []string {
	result := make([]string, len(chain))
	for i, stmt := range chain {
		result[i] = stmt.Statement
	}
	return result
}

// InitializeResolverKeys initializes the resolver's own signing keys
func (r *FederationResolver) InitializeResolverKeys() error {
	return r.InitializeResolverKeysWithContext(context.Background())
}

// InitializeResolverKeysWithContext initializes the resolver's signing keys using the provided context
func (r *FederationResolver) InitializeResolverKeysWithContext(ctx context.Context) error {
	// Ensure we have a KeyManager: prefer injected, otherwise create the default one
	if r.KeyManager == nil {
		if km, err := keymanager.NewDefaultKeyManager(); err == nil {
			r.KeyManager = km
			log.Printf("[RESOLVER] using KeyManager backend for resolver keys")
		} else {
			log.Printf("[RESOLVER] warning: failed to create default KeyManager: %v", err)
		}
	}

	// If a KeyManager is available, prefer it for key storage and JWKS
	if r.KeyManager != nil {
		if err := r.KeyManager.LoadKeys(ctx); err != nil {
			log.Printf("[RESOLVER] warning: KeyManager.LoadKeys failed: %v", err)
		}

		// Choose an active key if present, otherwise pick the first or generate
		keys, _ := r.KeyManager.ListKeys(ctx)
		var selected *keymanager.KeyMetadata
		for _, k := range keys {
			if k.Status == keymanager.KeyStatusActive {
				selected = k
				break
			}
		}
		if selected == nil && len(keys) > 0 {
			selected = keys[0]
		}
		if selected == nil {
			md, err := r.KeyManager.GenerateAndActivate(ctx, "resolver", "EC", "ES256")
			if err != nil {
				return fmt.Errorf("failed to generate resolver key via KeyManager: %w", err)
			}
			selected = md
		}

		r.signingkid = selected.Kid
		if sk, err := r.KeyManager.GetSigningKey(ctx, r.signingkid); err == nil {
			r.signingKey = sk
		} else {
			log.Printf("[RESOLVER] warning: signing key not available from KeyManager: %v", err)
		}

		// Populate resolverKeys from KeyManager JWKS
		if jwksMap, err := r.KeyManager.GetJWKS(ctx); err == nil {
			if keysArr, ok := jwksMap["keys"].([]interface{}); ok {
				jwks := []JWK{}
				for _, ki := range keysArr {
					if m, ok := ki.(map[string]interface{}); ok {
						j := JWK{}
						if v, ok := m["kty"].(string); ok {
							j.KeyType = v
						}
						if v, ok := m["kid"].(string); ok {
							j.KeyID = v
						}
						if v, ok := m["alg"].(string); ok {
							j.Algorithm = v
						}
						if v, ok := m["n"].(string); ok {
							j.Modulus = v
						}
						if v, ok := m["e"].(string); ok {
							j.Exponent = v
						}
						if v, ok := m["x"].(string); ok {
							j.XCoordinate = v
						}
						if v, ok := m["y"].(string); ok {
							j.YCoordinate = v
						}
						jwks = append(jwks, j)
					}
				}
				r.resolverKeys = &JWKSet{Keys: jwks}
			}
		}
		return nil
	}

	// Fallback: generate RSA key pair for resolver
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	r.signingKey = signingKey
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	r.signingkid = fmt.Sprintf("resolver-%s", timestamp)

	// Create JWK from public key
	jwk := &JWK{
		KeyType:   "RSA",
		Use:       "sig",
		KeyID:     r.signingkid,
		Algorithm: "RS256",
	}

	r.resolverKeys = &JWKSet{
		Keys: []JWK{*jwk},
	}

	return nil
}

// ValidateSignedResponse validates a signed response from another resolver
func (r *FederationResolver) ValidateSignedResponse(signedResponse string) (*ResolverSignedResponse, error) {
	// Parse the JWT
	token, err := jwt.Parse(signedResponse, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get the issuer (resolver) public key
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, fmt.Errorf("invalid claims")
		}

		issuer, ok := claims["iss"].(string)
		if !ok {
			return nil, fmt.Errorf("missing issuer")
		}

		// Retrieve resolver's public key (implementation dependent)
		return r.getResolverPublicKey(issuer)
	})

	if err != nil {
		return nil, fmt.Errorf("JWT validation failed: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid JWT")
	}

	// Extract claims and construct response
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid JWT claims")
	}

	response := &ResolverSignedResponse{
		EntityID:    getString(claims, "sub"),
		TrustAnchor: getString(claims, "trust_anchor"),
		Issuer:      getString(claims, "iss"),
		IssuedAt:    time.Unix(int64(getFloat64(claims, "iat")), 0),
		ExpiresAt:   time.Unix(int64(getFloat64(claims, "exp")), 0),
	}

	// Extract metadata
	if metadata, ok := claims["metadata"].(map[string]interface{}); ok {
		response.Metadata = metadata
	}

	return response, nil
}

// Helper functions for JWT claim extraction
func getString(claims jwt.MapClaims, key string) string {
	if val, ok := claims[key].(string); ok {
		return val
	}
	return ""
}

func getFloat64(claims jwt.MapClaims, key string) float64 {
	if val, ok := claims[key].(float64); ok {
		return val
	}
	return 0
}

func (r *FederationResolver) getResolverPublicKey(issuer string) (interface{}, error) {
	// Implementation would fetch the resolver's public key
	// This is a placeholder
	return nil, fmt.Errorf("resolver public key retrieval not implemented")
}

// GetResolverEntityStatement creates and returns the resolver's own entity statement
// This is required per OpenID Federation spec so clients can verify resolver signatures
func (r *FederationResolver) GetResolverEntityStatement() (string, error) {
	return r.GetResolverEntityStatementWithContext(context.Background())
}

// Context-aware variant that accepts a context for KeyManager calls.
func (r *FederationResolver) GetResolverEntityStatementWithContext(ctx context.Context) (string, error) {
	if r.config.ResolverEntityID == "" {
		return "", fmt.Errorf("resolver entity ID not configured")
	}

	// Create entity statement claims
	now := time.Now()
	exp := now.Add(24 * time.Hour) // Valid for 24 hours

	claims := jwt.MapClaims{
		"iss": r.config.ResolverEntityID,
		"sub": r.config.ResolverEntityID,
		"iat": now.Unix(),
		"exp": exp.Unix(),
		"jwks": map[string]interface{}{
			"keys": r.getResolverJWKSWithContext(ctx),
		},
		"metadata": map[string]interface{}{
			"federation_entity": map[string]interface{}{
				"organization_name":              "Federation Resolver",
				"contacts":                       []string{},
				"federation_resolve_endpoint":    fmt.Sprintf("%s/api/v1/resolve", r.config.ResolverEntityID),
				"federation_collection_endpoint": fmt.Sprintf("%s/api/v1/collection", r.config.ResolverEntityID),
			},
			"federation_resolver": map[string]interface{}{
				"resolve_endpoint":    fmt.Sprintf("%s/api/v1/resolve", r.config.ResolverEntityID),
				"list_endpoint":       fmt.Sprintf("%s/api/v1/federation_list", r.config.ResolverEntityID),
				"collection_endpoint": fmt.Sprintf("%s/api/v1/collection", r.config.ResolverEntityID),
				"trust_anchors":       r.config.TrustAnchors,
			},
		},
	}

	// Create and sign the JWT (try KeyManager with provided ctx)
	var signingKey interface{}
	if r.KeyManager != nil && r.signingkid != "" {
		if sk, err := r.KeyManager.GetSigningKey(ctx, r.signingkid); err == nil {
			signingKey = sk
		}
	}
	if signingKey == nil {
		signingKey = r.signingKey
	}

	var signingMethod jwt.SigningMethod
	switch signingKey.(type) {
	case *rsa.PrivateKey:
		signingMethod = jwt.SigningMethodRS256
	default:
		signingMethod = jwt.SigningMethodES256
	}

	if r.KeyManager != nil && r.signingkid != "" {
		hdr := map[string]interface{}{"typ": "entity-statement+jwt", "kid": r.signingkid}
		if signingKey != nil {
			switch signingKey.(type) {
			case *rsa.PrivateKey:
				hdr["alg"] = "RS256"
			default:
				hdr["alg"] = "ES256"
			}
		} else {
			hdr["alg"] = "ES256"
		}
		hb, _ := json.Marshal(hdr)
		pb, _ := json.Marshal(claims)
		hdrEnc := base64.RawURLEncoding.EncodeToString(hb)
		pldEnc := base64.RawURLEncoding.EncodeToString(pb)
		signingInput := fmt.Sprintf("%s.%s", hdrEnc, pldEnc)

		sig, err := r.KeyManager.Sign(ctx, r.signingkid, []byte(signingInput))
		if err == nil {
			sigEnc := base64.RawURLEncoding.EncodeToString(sig)
			return signingInput + "." + sigEnc, nil
		}
		log.Printf("[RESOLVER] warning: KeyManager.Sign failed for entity statement: %v", err)
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	token.Header["typ"] = "entity-statement+jwt"
	token.Header["kid"] = r.signingkid

	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign entity statement: %w", err)
	}

	return tokenString, nil
}

// getResolverJWKS returns the resolver's public keys in JWKS format
func (r *FederationResolver) getResolverJWKS() []map[string]interface{} {
	return r.getResolverJWKSWithContext(context.Background())
}

// Context-aware variant of getResolverJWKS
func (r *FederationResolver) getResolverJWKSWithContext(ctx context.Context) []map[string]interface{} {
	if r.KeyManager != nil {
		if jwksMap, err := r.KeyManager.GetJWKS(ctx); err == nil {
			if keysArr, ok := jwksMap["keys"].([]interface{}); ok {
				out := []map[string]interface{}{}
				for _, ki := range keysArr {
					if m, ok := ki.(map[string]interface{}); ok {
						out = append(out, m)
					}
				}
				return out
			}
		}
	}

	if r.signingKey == nil {
		return []map[string]interface{}{}
	}

	// Fallback: extract public key from RSA private key
	rsaPrivateKey, ok := r.signingKey.(*rsa.PrivateKey)
	if !ok {
		log.Printf("[RESOLVER] Signing key is not RSA, JWKS generation may fail")
		return []map[string]interface{}{}
	}

	publicKey := &rsaPrivateKey.PublicKey

	// Encode modulus and exponent in base64url format
	nBytes := publicKey.N.Bytes()
	eBytes := big.NewInt(int64(publicKey.E)).Bytes()

	jwk := map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"kid": r.signingkid,
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(nBytes),
		"e":   base64.RawURLEncoding.EncodeToString(eBytes),
	}

	return []map[string]interface{}{jwk}
}
