package resolver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

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

// SelectKeyFromJWKSet selects a public key from a JWKSet by kid (string or nil).
// It returns a parsed public key (RSA/ECDSA/EdDSA) or an error.
func SelectKeyFromJWKSet(r *FederationResolver, jwks *JWKSet, kid interface{}) (interface{}, error) {
	if jwks == nil {
		return nil, fmt.Errorf("jwks is nil")
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
	return nil, fmt.Errorf("no suitable public key found for kid %s", kidStr)
}

// fetchJWKSetFromURL fetches a JWKS from the given URL (uses http helpers)
func (r *FederationResolver) fetchJWKSetFromURL(ctx context.Context, url string, kid interface{}) (interface{}, error) {
	// Use the shared HTTP GET helper which maps URLs and performs the request
	body, status, err := r.httpGet(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("JWKS request failed: %w", err)
	}
	if status != 200 {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", status)
	}

	var jwks JWKSet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	// Delegate key selection to the configured KeyProvider
	if r.KeyProvider != nil {
		return r.KeyProvider.SelectKey(&jwks, kid)
	}

	// Fallback: centralized selection helper
	return SelectKeyFromJWKSet(r, &jwks, kid)
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
