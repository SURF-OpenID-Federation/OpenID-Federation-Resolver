package resolver

import (
	"context"

	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"

	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
	if !r.IsAuthorizedForTrustAnchor(trustAnchor) {
		return "", fmt.Errorf("not authorized to sign for trust anchor %s", trustAnchor)
	}

	// Get trust anchor registration
	_ = r.registeredAnchors[trustAnchor] // Used for authorization check above

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

	// Create JWT
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Set header
	token.Header["typ"] = "resolve-response+jwt"
	token.Header["kid"] = r.getResolverSigningKeyID()

	// Sign the token using resolver's key on behalf of trust anchor
	signingKey, err := r.getSigningKeyForTrustAnchor(trustAnchor)
	if err != nil {
		return "", fmt.Errorf("failed to get signing key: %w", err)
	}

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

	// Then create signed response
	return r.CreateSignedTrustChainResponse(trustChain, trustAnchor)
}

// Helper functions

func (r *FederationResolver) getResolverSigningKeyID() string {
	return r.signingkid
}

func (r *FederationResolver) getSigningKeyForTrustAnchor(trustAnchor string) (crypto.PrivateKey, error) {
	_, exists := r.registeredAnchors[trustAnchor]
	if !exists {
		return nil, fmt.Errorf("trust anchor not registered")
	}

	return r.signingKey, nil
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
	// Generate RSA key pair for resolver
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	r.signingKey = signingKey
	r.signingkid = "resolver-key-1" // In practice, use a proper key ID

	// Create JWK from public key
	jwk := &JWK{
		KeyType:   "RSA",
		Use:       "sig",
		KeyID:     r.signingkid,
		Algorithm: "RS256",
		// You would need to populate the actual key parameters
	}

	r.resolverKeys = &JWKSet{
		Keys: []JWK{*jwk},
	}

	// Store private key securely (implementation dependent)
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
			"keys": r.getResolverJWKS(),
		},
		"metadata": map[string]interface{}{
			"federation_entity": map[string]interface{}{
				"organization_name": "Federation Resolver",
				"contacts":          []string{},
				"federation_resolve_endpoint": fmt.Sprintf("%s/api/v1/resolve", r.config.ResolverEntityID),
			},
			"federation_resolver": map[string]interface{}{
				"resolve_endpoint": fmt.Sprintf("%s/api/v1/resolve", r.config.ResolverEntityID),
				"list_endpoint":    fmt.Sprintf("%s/api/v1/federation_list", r.config.ResolverEntityID),
			},
		},
	}

	// Create and sign the JWT
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = "entity-statement+jwt"
	token.Header["kid"] = r.signingkid

	tokenString, err := token.SignedString(r.signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign entity statement: %w", err)
	}

	return tokenString, nil
}

// getResolverJWKS returns the resolver's public keys in JWKS format
func (r *FederationResolver) getResolverJWKS() []map[string]interface{} {
	if r.signingKey == nil {
		return []map[string]interface{}{}
	}

	// Extract public key from private key
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
