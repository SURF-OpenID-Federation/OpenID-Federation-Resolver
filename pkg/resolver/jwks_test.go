package resolver

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelectKeyFromJWKSet_EC(t *testing.T) {
	cfg := &Config{RequestTimeout: 1 * time.Second}
	r, err := NewFederationResolver(cfg)
	require.NoError(t, err)

	// Create a fake P-256 public key coordinates (32 bytes each)
	x := make([]byte, 32)
	y := make([]byte, 32)
	for i := 0; i < 32; i++ {
		x[i] = byte(i + 1)
		y[i] = byte(i + 2)
	}

	jwk := JWK{
		KeyType:     "EC",
		Curve:       "P-256",
		KeyID:       "test-ec-1",
		XCoordinate: base64.RawURLEncoding.EncodeToString(x),
		YCoordinate: base64.RawURLEncoding.EncodeToString(y),
	}
	jwks := &JWKSet{Keys: []JWK{jwk}}

	key, err := SelectKeyFromJWKSet(r, jwks, "test-ec-1")
	require.NoError(t, err)
	assert.NotNil(t, key)
}

// Verify that the resolver's in-memory JWKS serializes to the canonical
// JSON shape (keys -> []interface{} of objects). This prevents runtime
// type-assertion failures in callers that unmarshal into map[string]interface{}.
func TestResolverJWKSJSONShape(t *testing.T) {
	cfg := &Config{EnableSigning: true, RequestTimeout: 1 * time.Second}
	r, err := NewFederationResolver(cfg)
	if err != nil {
		t.Fatalf("NewFederationResolver: %v", err)
	}

	if err := r.InitializeResolverKeys(); err != nil {
		t.Fatalf("InitializeResolverKeys: %v", err)
	}

	b, err := json.Marshal(r.resolverKeys)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal jwks into generic map: %v", err)
	}

	keys, ok := m["keys"]
	if !ok {
		t.Fatalf("jwks missing 'keys' field: %v", m)
	}

	ks, ok := keys.([]interface{})
	if !ok {
		t.Fatalf("jwks.keys is not []interface{} (got %T)", keys)
	}

	if len(ks) == 0 {
		t.Fatalf("jwks.keys is empty")
	}

	first, ok := ks[0].(map[string]interface{})
	if !ok {
		t.Fatalf("jwks.keys[0] is not object (got %T)", ks[0])
	}

	if _, ok := first["kid"]; !ok {
		t.Fatalf("jwks.keys[0] missing kid: %v", first)
	}
}
