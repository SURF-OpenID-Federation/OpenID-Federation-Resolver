package resolver

import (
	"context"
)

// KeyProvider is an abstraction for retrieving public keys used to validate JWTs.
type KeyProvider interface {
	GetPublicKey(ctx context.Context, issuer string, kid interface{}) (interface{}, error)
	GetPublicKeyForEntity(ctx context.Context, issuer string, kid interface{}, currentEntity *CachedEntityStatement) (interface{}, error)
	SelectKey(jwks *JWKSet, kid interface{}) (interface{}, error)
}

// DefaultKeyProvider uses the resolver's existing methods to fetch keys.
type DefaultKeyProvider struct {
	r *FederationResolver
}

func (d *DefaultKeyProvider) GetPublicKey(ctx context.Context, issuer string, kid interface{}) (interface{}, error) {
	return d.r.getIssuerPublicKey(ctx, issuer, kid)
}

func (d *DefaultKeyProvider) GetPublicKeyForEntity(ctx context.Context, issuer string, kid interface{}, currentEntity *CachedEntityStatement) (interface{}, error) {
	return d.r.getIssuerPublicKeyForEntity(ctx, issuer, kid, currentEntity)
}

// SelectKey chooses a usable public key from a JWKSet, preferring RSA then EC then EdDSA.
func (d *DefaultKeyProvider) SelectKey(jwks *JWKSet, kid interface{}) (interface{}, error) {
	return SelectKeyFromJWKSet(d.r, jwks, kid)
}
