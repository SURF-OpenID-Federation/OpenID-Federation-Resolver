package resolver

import (
	"context"
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
	leafStmt, err := leaf.SignEntityStatement(context.Background(), leafClaims)
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
	resolveJWT, err := parent.SignResolveResponse(context.Background(), resolveClaims)
	if err != nil {
		t.Fatalf("parent SignResolveResponse: %v", err)
	}
	t.Logf("resolveJWT len=%d", len(resolveJWT))

	// Parent: subordinate statement about leaf (embed parent's jwks)
	parentClaims := map[string]interface{}{"iss": parentID, "sub": leafID, "iat": float64(time.Now().Unix()), "exp": float64(time.Now().Add(time.Hour).Unix()), "jwks": parent.GetJWKS()}
	parentStmt, err := parent.SignEntityStatement(context.Background(), parentClaims)
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

// TestCreateSignedTrustChainResponse_SpecCompliantOutput verifies that
// CreateSignedTrustChainResponse produces a resolve-response+jwt that complies
// with OpenID Federation spec §8.3.2:
//   - Required claims: iss, sub, iat, exp, metadata (resolved), trust_chain
//   - Forbidden non-spec claims: aud, trust_anchor, validation_status, metadata.statement
//   - exp is min(exp across all chain elements) per §10.4
func TestCreateSignedTrustChainResponse_SpecCompliantOutput(t *testing.T) {
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

	// Leaf EC (iss == sub == leaf), must be Chain[0]
	leafExp := time.Now().Add(2 * time.Hour).Unix()
	leafClaims := map[string]interface{}{
		"iss": leafID, "sub": leafID,
		"iat": float64(time.Now().Unix()), "exp": float64(leafExp),
		"jwks":     leaf.GetJWKS(),
		"metadata": map[string]interface{}{"openid_provider": map[string]interface{}{"issuer": leafID}},
	}
	leafStmt, err := leaf.SignEntityStatement(context.Background(), leafClaims)
	if err != nil {
		t.Fatalf("leaf SignEntityStatement: %v", err)
	}

	// SubStmt (iss == parent, sub == leaf), must be Chain[1]
	subExp := time.Now().Add(1 * time.Hour).Unix() // lower exp → determines chain exp
	subClaims := map[string]interface{}{
		"iss": parentID, "sub": leafID,
		"iat": float64(time.Now().Unix()), "exp": float64(subExp),
	}
	subStmt, err := parent.SignEntityStatement(context.Background(), subClaims)
	if err != nil {
		t.Fatalf("parent SignEntityStatement: %v", err)
	}

	chain := []CachedEntityStatement{
		{EntityID: leafID, Statement: leafStmt,
			ParsedClaims: leafClaims, Issuer: leafID, Subject: leafID,
			CachedAt: time.Now(), ExpiresAt: time.Unix(leafExp, 0)},
		{EntityID: leafID, Statement: subStmt,
			ParsedClaims: subClaims, Issuer: parentID, Subject: leafID,
			CachedAt: time.Now(), ExpiresAt: time.Unix(subExp, 0)},
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

	trustChain := &CachedTrustChain{
		EntityID: leafID, TrustAnchor: parentID, Status: "valid",
		Chain: chain, CachedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour),
	}
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

	// §8.3.2 REQUIRED claims
	if top["iss"] == nil {
		t.Fatalf("resolve-response MUST have iss")
	}
	if top["sub"] == nil {
		t.Fatalf("resolve-response MUST have sub")
	}
	if top["iat"] == nil {
		t.Fatalf("resolve-response MUST have iat")
	}
	if top["exp"] == nil {
		t.Fatalf("resolve-response MUST have exp")
	}
	if top["trust_chain"] == nil {
		t.Fatalf("resolve-response MUST have trust_chain")
	}
	md, ok := top["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("resolve-response MUST have metadata map, got: %T", top["metadata"])
	}

	// §6.1.4: resolved metadata must contain the leaf's openid_provider sub-object
	if _, hasOP := md["openid_provider"]; !hasOP {
		t.Fatalf("resolved metadata must contain openid_provider: %v", md)
	}

	// §8.3.2 — metadata.statement is non-spec and MUST NOT be present
	if _, hasStmt := md["statement"]; hasStmt {
		t.Fatalf("metadata.statement is non-spec and MUST NOT appear in resolve-response")
	}

	// §10.4 — exp must equal min(chain exp values) = subExp
	gotExp := int64(top["exp"].(float64))
	if gotExp != subExp {
		t.Fatalf("exp MUST be min(chain exp); got %d, want %d", gotExp, subExp)
	}

	// Non-spec claims MUST be absent
	if _, has := top["aud"]; has {
		t.Fatalf("aud is non-spec in resolve-response and MUST NOT be present")
	}
	if _, has := top["trust_anchor"]; has {
		t.Fatalf("trust_anchor is non-spec in resolve-response and MUST NOT be present")
	}
	if _, has := top["validation_status"]; has {
		t.Fatalf("validation_status is non-spec in resolve-response and MUST NOT be present")
	}
}
