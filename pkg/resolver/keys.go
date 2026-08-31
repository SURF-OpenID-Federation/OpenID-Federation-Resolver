package resolver

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/harrykodden/keymanager"
)

// RotateSigningKey generates a new ES256 key, makes it the active signer, and
// keeps previous public keys in the JWKS so already-issued resolve-response
// JWTs remain verifiable via /.well-known/openid-federation.
func (r *FederationResolver) RotateSigningKey(ctx context.Context) (previousKid, newKid string, err error) {
	if r == nil || r.KeyManager == nil {
		return "", "", fmt.Errorf("key manager not configured")
	}
	previousKid = r.getResolverSigningKeyID()
	md, err := r.KeyManager.GenerateAndActivate(ctx, "resolver", "EC", "ES256")
	if err != nil {
		return "", "", fmt.Errorf("generate signing key: %w", err)
	}
	newKid = md.Kid
	if jwksMap, err := r.KeyManager.GetJWKS(ctx); err == nil {
		newKid = resolveVersionedKid(jwksMap, md.Kid)
	}
	r.setActiveSigningKey(ctx, newKid)
	return previousKid, newKid, nil
}

var (
	// ErrLastSigningKey is returned when DELETE would remove the last usable signing key.
	ErrLastSigningKey = errors.New("cannot delete the last signing key")
	// ErrUnknownSigningKey is returned when the kid is not in the published JWKS.
	ErrUnknownSigningKey = errors.New("unknown key")
)

// RevokeSigningKey retires kid and removes it from the published JWKS.
// If it was the signing key and another signing-capable key remains, that key
// is promoted. The last remaining key cannot be deleted.
func (r *FederationResolver) RevokeSigningKey(ctx context.Context, kid string) error {
	if r == nil || r.KeyManager == nil {
		return fmt.Errorf("key manager not configured")
	}
	kid = strings.TrimSpace(kid)
	if kid == "" {
		return ErrUnknownSigningKey
	}
	info := r.SigningKeyPublicInfo(ctx)
	var found bool
	others := make([]string, 0, len(info.JWKS))
	for _, jwk := range info.JWKS {
		k, _ := jwk["kid"].(string)
		if k == "" {
			continue
		}
		if k == kid {
			found = true
			continue
		}
		others = append(others, k)
	}
	if !found {
		return ErrUnknownSigningKey
	}
	if kid == info.ActiveKid && len(others) == 0 {
		return ErrLastSigningKey
	}
	if err := r.KeyManager.RevokeKey(ctx, kid); err != nil {
		return err
	}
	if kid == info.ActiveKid {
		sort.Strings(others)
		replacement := others[len(others)-1]
		if err := r.KeyManager.ActivateKey(ctx, replacement); err != nil {
			return fmt.Errorf("activate replacement signing key: %w", err)
		}
		r.setActiveSigningKey(ctx, replacement)
		return nil
	}
	r.setActiveSigningKey(ctx, info.ActiveKid)
	return nil
}

// SigningKeyPublicInfo is the public view of the resolver's signing material.
type SigningKeyPublicInfo struct {
	ActiveKid string                   `json:"active_kid"`
	JWKS      []map[string]interface{} `json:"jwks"`
}

// SigningKeyPublicInfo returns the active kid and public JWKS (no private keys).
func (r *FederationResolver) SigningKeyPublicInfo(ctx context.Context) SigningKeyPublicInfo {
	if r == nil {
		return SigningKeyPublicInfo{JWKS: []map[string]interface{}{}}
	}
	jwks := r.getResolverJWKSWithContext(ctx)
	if jwks == nil {
		jwks = []map[string]interface{}{}
	}
	return SigningKeyPublicInfo{
		ActiveKid: r.getResolverSigningKeyID(),
		JWKS:      jwks,
	}
}

// SigningKeySummary is active kid and JWKS size from in-memory state.
// It does not call KeyManager (ops poll must not hit disk / log GetJWKS).
func (r *FederationResolver) SigningKeySummary() (activeKid string, keyCount int) {
	if r == nil {
		return "", 0
	}
	activeKid = r.getResolverSigningKeyID()
	r.keysMu.RLock()
	defer r.keysMu.RUnlock()
	if r.resolverKeys != nil {
		keyCount = len(r.resolverKeys.Keys)
	}
	return activeKid, keyCount
}

func (r *FederationResolver) setActiveSigningKey(ctx context.Context, kid string) {
	r.keysMu.Lock()
	defer r.keysMu.Unlock()
	r.signingkid = kid
	if r.KeyManager == nil || kid == "" {
		return
	}
	if sk, err := r.KeyManager.GetSigningKey(ctx, kid); err == nil {
		r.signingKey = sk
	}
	if set := jwkSetFromKeyManager(ctx, r.KeyManager); set != nil {
		r.resolverKeys = set
	}
}

func jwkSetFromKeyManager(ctx context.Context, km keymanager.AdvancedKeyManager) *JWKSet {
	if km == nil {
		return nil
	}
	jwksMap, err := km.GetJWKS(ctx)
	if err != nil || jwksMap == nil {
		return nil
	}
	keysArr, ok := jwksMap["keys"].([]interface{})
	if !ok {
		return nil
	}
	jwks := make([]JWK, 0, len(keysArr))
	for _, ki := range keysArr {
		m, ok := ki.(map[string]interface{})
		if !ok {
			continue
		}
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
		if v, ok := m["crv"].(string); ok {
			j.Curve = v
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
	if len(jwks) == 0 {
		return nil
	}
	return &JWKSet{Keys: jwks}
}

// Vault (and similar) backends may append a version suffix to the generated kid.
func resolveVersionedKid(jwksMap map[string]interface{}, generatedKid string) string {
	if jwksMap == nil || generatedKid == "" {
		return generatedKid
	}
	keysIfc, ok := jwksMap["keys"]
	if !ok {
		return generatedKid
	}
	var maps []map[string]interface{}
	switch keys := keysIfc.(type) {
	case []interface{}:
		for _, ki := range keys {
			if m, ok := ki.(map[string]interface{}); ok {
				maps = append(maps, m)
			}
		}
	case []map[string]interface{}:
		maps = keys
	}
	resolved := generatedKid
	for _, m := range maps {
		kidStr, _ := m["kid"].(string)
		if strings.HasPrefix(kidStr, generatedKid+"-") {
			return kidStr
		}
		if kidStr == generatedKid {
			resolved = kidStr
		}
	}
	return resolved
}
