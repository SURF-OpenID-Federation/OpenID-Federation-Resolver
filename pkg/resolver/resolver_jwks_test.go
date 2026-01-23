package resolver

import (
	"encoding/json"
	"testing"
	"time"
)

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
