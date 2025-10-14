package resolver

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
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
		ExpiresAt:   now.Add(24 * time.Hour), // Valid for 24 hours
		Issuer:      r.config.ResolverEntityID, // You'd need to add this to config
	}

	// Extract metadata from the trust chain
	if len(trustChain.Chain) > 0 {
		response.Metadata = trustChain.Chain[0].ParsedClaims
	}

	// Create JWT
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":          response.Issuer,
		"sub":          response.EntityID,
		"aud":          trustAnchor,
		"iat":          response.IssuedAt.Unix(),
		"exp":          response.ExpiresAt.Unix(),
		"trust_chain":  convertChainToJWTArray(trustChain.Chain),
		"metadata":     response.Metadata,
		"trust_anchor": trustAnchor,
	})

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
	if r.resolverKeys != nil && len(r.resolverKeys.Keys) > 0 {
		return r.resolverKeys.Keys[0].KeyID
	}
	return "resolver-key-1" // Default
}

func (r *FederationResolver) getSigningKeyForTrustAnchor(trustAnchor string) (crypto.PrivateKey, error) {
	_, exists := r.registeredAnchors[trustAnchor]
	if !exists {
		return nil, fmt.Errorf("trust anchor not registered")
	}

	// In a real implementation, you would have the private keys associated with the trust anchor
	// For now, this is a placeholder
	// You would need to securely store and retrieve the private keys
	return nil, fmt.Errorf("signing key retrieval not implemented")
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
	_, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Create JWK from public key
	jwk := &JWK{
		KeyType:   "RSA",
		Use:       "sig",
		KeyID:     "resolver-key-1",
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