package resolver

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Ensure resolver correctly unwraps a resolve-response+jwt chain element and
// embeds the inner entity-statement into the signed resolver response.
func TestCreateSignedTrustChainResponse_UnwrapsResolveResponseStatement(t *testing.T) {
	parentID := "http://parent.example"
	leafID := "http://leaf.example"

	parent, err := newTestEntity(parentID)
	if err != nil {
		t.Fatalf("newTestEntity(parent): %v", err)
	}
	leaf, err := newTestEntity(leafID)
	if err != nil {
		t.Fatalf("newTestEntity(leaf): %v", err)
	}

	// Inner entity-statement (compact JWT)
	leafClaims := map[string]interface{}{"iss": leafID, "sub": leafID, "iat": float64(time.Now().Unix()), "exp": float64(time.Now().Add(time.Hour).Unix()), "jwks": leaf.GetJWKS()}
	leafStmt, err := leaf.SignEntityStatement(leafClaims)
	if err != nil {
		t.Fatalf("leaf SignEntityStatement: %v", err)
	}
	t.Logf("leafStmt: len=%d, parts=%d", len(leafStmt), strings.Count(leafStmt, "."))

	// Create a resolve-response JWT whose payload.metadata.statement == leafStmt
	resolveClaims := map[string]interface{}{"iss": parentID, "sub": leafID, "iat": float64(time.Now().Unix()), "exp": float64(time.Now().Add(time.Hour).Unix()), "metadata": map[string]interface{}{"statement": leafStmt}}
	if md, ok := resolveClaims["metadata"].(map[string]interface{}); ok {
		if s, ok2 := md["statement"].(string); ok2 {
			t.Logf("resolveClaims.metadata.statement present: len=%d, parts=%d", len(s), strings.Count(s, "."))
		}
	}
	resolveJWT, err := parent.SignResolveResponse(resolveClaims)
	if err != nil {
		t.Fatalf("parent SignResolveResponse: %v", err)
	}
	t.Logf("resolveJWT len=%d", len(resolveJWT))

	// Parent: subordinate statement about leaf (embed parent's jwks)
	parentClaims := map[string]interface{}{"iss": parentID, "sub": leafID, "iat": float64(time.Now().Unix()), "exp": float64(time.Now().Add(time.Hour).Unix()), "jwks": parent.GetJWKS()}
	parentStmt, err := parent.SignEntityStatement(parentClaims)
	if err != nil {
		t.Fatalf("parent SignEntityStatement: %v", err)
	}

	chain := []CachedEntityStatement{
		{EntityID: leafID, Statement: resolveJWT, ParsedClaims: map[string]interface{}{"metadata": map[string]interface{}{"statement": leafStmt}, "openid_provider": map[string]interface{}{"issuer": leafID}}, Issuer: parentID, Subject: leafID, CachedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
		{EntityID: parentID, Statement: parentStmt, ParsedClaims: nil, Issuer: parentID, Subject: parentID, CachedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
	}

	cfg := &Config{EnableSigning: true, RequestTimeout: 2 * time.Second}
	r, err := NewFederationResolver(cfg)
	if err != nil {
		t.Fatalf("NewFederationResolver: %v", err)
	}
	if err := r.InitializeResolverKeys(); err != nil {
		t.Fatalf("InitializeResolverKeys: %v", err)
	}
	r.registeredAnchors[parentID] = &TrustAnchorRegistration{EntityID: parentID, ExpiresAt: time.Now().Add(1 * time.Hour)}

	trustChain := &CachedTrustChain{EntityID: leafID, TrustAnchor: parentID, Status: "valid", Chain: chain, CachedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour)}
	token, err := r.CreateSignedTrustChainResponse(trustChain, parentID)
	if err != nil {
		t.Fatalf("CreateSignedTrustChainResponse: %v", err)
	}

	// inspect resolver payload (no signature verification)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected resolver JWT format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode resolver JWT payload: %v", err)
	}
	var top map[string]interface{}
	if err := json.Unmarshal(payload, &top); err != nil {
		t.Fatalf("unmarshal resolver payload: %v", err)
	}
	md, ok := top["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("resolver payload missing metadata: %v", top["metadata"])
	}
	stm, _ := md["statement"].(string)
	if stm == "" {
		t.Fatalf("resolver payload missing metadata.statement (inner entity-statement)")
	}
	if len(strings.Split(stm, ".")) != 3 {
		t.Fatalf("metadata.statement is not a JWT: %s", stm)
	}
}

// If the first chain element is a resolve-response+jwt without metadata.statement,
// the resolver should fall back to the first entity-statement it can find.
func TestCreateSignedTrustChainResponse_FallbacksToNextEntityStatement(t *testing.T) {
	parentID := "http://parent.example"
	leafID := "http://leaf.example"

	parent, err := newTestEntity(parentID)
	if err != nil {
		t.Fatalf("newTestEntity(parent): %v", err)
	}
	leaf, err := newTestEntity(leafID)
	if err != nil {
		t.Fatalf("newTestEntity(leaf): %v", err)
	}

	// First element: resolve-response WITHOUT metadata.statement
	resolveClaims := map[string]interface{}{"iss": parentID, "sub": leafID, "iat": float64(time.Now().Unix()), "exp": float64(time.Now().Add(time.Hour).Unix()), "metadata": map[string]interface{}{"federation_entity": map[string]interface{}{}}}
	resolveJWT, err := parent.SignResolveResponse(resolveClaims)
	if err != nil {
		t.Fatalf("parent SignResolveResponse: %v", err)
	}

	// Second element: actual leaf entity-statement
	leafClaims := map[string]interface{}{"iss": leafID, "sub": leafID, "iat": float64(time.Now().Unix()), "exp": float64(time.Now().Add(time.Hour).Unix()), "jwks": leaf.GetJWKS()}
	leafStmt, err := leaf.SignEntityStatement(leafClaims)
	if err != nil {
		t.Fatalf("leaf SignEntityStatement: %v", err)
	}

	chain := []CachedEntityStatement{
		// first element is a resolve-response JWT without metadata.statement
		{EntityID: leafID, Statement: resolveJWT, ParsedClaims: nil, Issuer: parentID, Subject: leafID, CachedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
		// authoritative leaf entity-statement (parser-friendly)
		{EntityID: leafID, Statement: leafStmt, ParsedClaims: map[string]interface{}{"iss": leafID, "sub": leafID, "jwks": leaf.GetJWKS()}, Issuer: leafID, Subject: leafID, CachedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
	}

	cfg := &Config{EnableSigning: true, RequestTimeout: 2 * time.Second}
	r, err := NewFederationResolver(cfg)
	if err != nil {
		t.Fatalf("NewFederationResolver: %v", err)
	}
	if err := r.InitializeResolverKeys(); err != nil {
		t.Fatalf("InitializeResolverKeys: %v", err)
	}
	r.registeredAnchors[parentID] = &TrustAnchorRegistration{EntityID: parentID, ExpiresAt: time.Now().Add(1 * time.Hour)}

	trustChain := &CachedTrustChain{EntityID: leafID, TrustAnchor: parentID, Status: "valid", Chain: chain, CachedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour)}
	token, err := r.CreateSignedTrustChainResponse(trustChain, parentID)
	if err != nil {
		t.Fatalf("CreateSignedTrustChainResponse: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected resolver JWT format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode resolver JWT payload: %v", err)
	}
	var top map[string]interface{}
	if err := json.Unmarshal(payload, &top); err != nil {
		t.Fatalf("unmarshal resolver payload: %v", err)
	}
	md, ok := top["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("resolver payload missing metadata: %v", top["metadata"])
	}
	stm, _ := md["statement"].(string)
	if stm == "" {
		t.Fatalf("resolver payload missing metadata.statement (fallback not applied)")
	}
	if stm != leafStmt {
		t.Fatalf("expected metadata.statement to equal leafStmt; got: %s", stm)
	}
}
