package resolver

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveEntity(t *testing.T) {
	// Mock TA server that returns a subordinate entity statement
	taServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Placeholder handler
	}))
	defer taServer.Close()

	// Set the actual handler after server creation
	taServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/resolve" {
			sub := r.URL.Query().Get("sub")
			if sub == "http://rp.example.com" {
				// Return RP's entity statement issued by TA
				w.Header().Set("Content-Type", "application/jwt")
				w.WriteHeader(http.StatusOK)
				// Construct JWT with correct issuer
				header := `{"typ":"JWT","alg":"RS256"}`
				payload := fmt.Sprintf(`{"iss":"%s","sub":"http://rp.example.com","iat":1634320000,"exp":1634323600,"authority_hints":["%s"]}`, taServer.URL, taServer.URL)
				jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
				w.Write([]byte(jwt))
			}
		}
	})

	config := &Config{
		TrustAnchors:       []string{taServer.URL},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	}

	resolver, err := NewFederationResolver(config)
	require.NoError(t, err)

	ctx := context.Background()
	entity, err := resolver.ResolveEntity(ctx, "http://rp.example.com", taServer.URL, false)

	assert.NoError(t, err)
	assert.Equal(t, "http://rp.example.com", entity.Subject)
	assert.Equal(t, taServer.URL, entity.Issuer)
}

func TestResolveTrustChain(t *testing.T) {
	// Create servers with placeholders, then update URLs
	taServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handler will be set later
	}))
	defer taServer.Close()

	rpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handler will be set later
	}))
	defer rpServer.Close()

	// Set RP server handler
	rpServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(http.StatusOK)
		header := `{"typ":"JWT","alg":"RS256"}`
		payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"authority_hints":["%s"]}`, rpServer.URL, rpServer.URL, taServer.URL)
		jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
		w.Write([]byte(jwt))
	})

	// Update TA server handler with RP URL
	taServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/resolve" {
			sub := r.URL.Query().Get("sub")
			if sub == rpServer.URL {
				// For trust-chain resolution, return a JWT with trust_chain array
				w.Header().Set("Content-Type", "application/jwt")
				w.WriteHeader(http.StatusOK)
				
				// Create subordinate entity JWT
				subHeader := `{"typ":"JWT","alg":"RS256"}`
				subPayload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"authority_hints":["%s"]}`, taServer.URL, sub, taServer.URL)
				subJWT := base64.RawURLEncoding.EncodeToString([]byte(subHeader)) + "." + base64.RawURLEncoding.EncodeToString([]byte(subPayload)) + ".signature"
				
				// Create TA entity JWT
				taHeader := `{"typ":"JWT","alg":"RS256"}`
				taPayload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600}`, taServer.URL, taServer.URL)
				taJWT := base64.RawURLEncoding.EncodeToString([]byte(taHeader)) + "." + base64.RawURLEncoding.EncodeToString([]byte(taPayload)) + ".signature"
				
				// Create trust-chain JWT
				header := `{"typ":"JWT","alg":"RS256"}`
				payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","trust_anchor":"%s","iat":1634320000,"exp":1634323600,"trust_chain":["%s","%s"]}`, taServer.URL, sub, taServer.URL, subJWT, taJWT)
				jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
				w.Write([]byte(jwt))
			}
		} else if r.URL.Path == "/.well-known/openid-federation" {
			w.Header().Set("Content-Type", "application/jwt")
			w.WriteHeader(http.StatusOK)
			header := `{"typ":"JWT","alg":"RS256"}`
			payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600}`, taServer.URL, taServer.URL)
			jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
			w.Write([]byte(jwt))
		}
	})

	config := &Config{
		TrustAnchors:       []string{taServer.URL},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	}

	resolver, err := NewFederationResolver(config)
	require.NoError(t, err)

	ctx := context.Background()
	chain, err := resolver.ResolveTrustChain(ctx, rpServer.URL, false)

	assert.NoError(t, err)
	assert.Len(t, chain.Chain, 2) // RP and TA
	assert.Equal(t, rpServer.URL, chain.EntityID)
	assert.Equal(t, taServer.URL, chain.TrustAnchor)
}

func TestResolveTrustChainFallback(t *testing.T) {
	// Test the fallback logic when subordinate has no authority_hints
	taMux := http.NewServeMux()
	taServer := httptest.NewServer(taMux)
	defer taServer.Close()

	rpMux := http.NewServeMux()
	rpServer := httptest.NewServer(rpMux)
	defer rpServer.Close()

	// Set TA server handlers
	taMux.HandleFunc("/.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(http.StatusOK)
		header := `{"typ":"JWT","alg":"RS256"}`
		payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600}`, taServer.URL, taServer.URL)
		jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
		w.Write([]byte(jwt))
	})
	taMux.HandleFunc("/resolve", func(w http.ResponseWriter, r *http.Request) {
		// Return empty trust chain to trigger fallback
		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(""))
	})

	// Set RP server handler - returns entity statement WITHOUT authority_hints
	rpMux.HandleFunc("/.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(http.StatusOK)
		header := `{"typ":"JWT","alg":"RS256"}`
		payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600}`, taServer.URL, rpServer.URL)
		jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
		w.Write([]byte(jwt))
	})

	config := &Config{
		TrustAnchors:       []string{taServer.URL},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	}

	resolver, err := NewFederationResolver(config)
	require.NoError(t, err)

	ctx := context.Background()
	chain, err := resolver.ResolveTrustChain(ctx, rpServer.URL, false)

	assert.NoError(t, err)
	assert.Len(t, chain.Chain, 2) // Should have RP and TA due to fallback
	assert.Equal(t, rpServer.URL, chain.EntityID)
	assert.Equal(t, taServer.URL, chain.TrustAnchor)
}

func TestCreateSignedTrustChainResponse(t *testing.T) {
	config := &Config{
		EnableSigning:      true,
		ResolverEntityID:   "http://resolver.example.com",
		TrustAnchors:       []string{"http://ta.example.com"},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	}

	resolver, err := NewFederationResolver(config)
	require.NoError(t, err)

	// Mock trust chain
	chain := &CachedTrustChain{
		EntityID:    "http://rp.example.com",
		TrustAnchor: "http://ta.example.com",
		Chain: []CachedEntityStatement{
			{Subject: "http://rp.example.com", Statement: "jwt1"},
			{Subject: "http://ta.example.com", Statement: "jwt2"},
		},
	}

	// Since signing requires authorization, we'll test that it fails gracefully
	_, err = resolver.CreateSignedTrustChainResponse(chain, "http://ta.example.com")
	assert.Error(t, err) // Expect error due to no signing key or authorization
}