package resolver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

// parseEntityStatement parses an entity statement (JWT or raw) into a CachedEntityStatement
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

// parseEntityStatementFromJWT parses an entity statement JWT (extracting minimal fields)
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
