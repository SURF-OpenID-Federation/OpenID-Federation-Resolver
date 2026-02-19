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

// TestResolveTrustChain and related chain building tests
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

				// Create trust-chain JWT with only the subordinate entity statement
				header := `{"typ":"JWT","alg":"RS256"}`
				payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","trust_anchor":"%s","iat":1634320000,"exp":1634323600,"trust_chain":["%s"]}`, taServer.URL, sub, taServer.URL, subJWT)
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
	assert.Len(t, chain.Chain, 3) // RP, subordinate, TA
	assert.Equal(t, rpServer.URL, chain.EntityID)
	assert.Equal(t, taServer.URL, chain.TrustAnchor)

	// NEW: Assert the first element is a self-signed Entity Configuration
	first := chain.Chain[0]
	assert.Equal(t, rpServer.URL, first.Issuer, "First element in chain should be self-signed (iss == entityID)")
	assert.Equal(t, rpServer.URL, first.Subject, "First element in chain should be self-signed (sub == entityID)")
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

func TestResolveTrustChainWithIntermediary(t *testing.T) {
	// Test chain building: RP -> Intermediary -> TA
	// Create servers for TA, Intermediary, and RP
	taServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handler will be set later
	}))
	defer taServer.Close()

	intermediaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handler will be set later
	}))
	defer intermediaryServer.Close()

	rpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handler will be set later
	}))
	defer rpServer.Close()

	// Set RP server handler - points to intermediary
	rpServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(http.StatusOK)
		header := `{"typ":"JWT","alg":"RS256"}`
		payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"authority_hints":["%s"]}`, intermediaryServer.URL, rpServer.URL, intermediaryServer.URL)
		jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
		w.Write([]byte(jwt))
	})

	// Set Intermediary server handler - points to TA and can resolve RP
	intermediaryServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/resolve" {
			sub := r.URL.Query().Get("sub")
			if sub == rpServer.URL {
				// Return RP's entity statement issued by intermediary
				w.Header().Set("Content-Type", "application/jwt")
				w.WriteHeader(http.StatusOK)
				header := `{"typ":"JWT","alg":"RS256"}`
				payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"authority_hints":["%s"]}`, intermediaryServer.URL, sub, intermediaryServer.URL)
				jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
				w.Write([]byte(jwt))
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		} else {
			// Return intermediary's own entity statement
			w.Header().Set("Content-Type", "application/jwt")
			w.WriteHeader(http.StatusOK)
			header := `{"typ":"JWT","alg":"RS256"}`
			payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"authority_hints":["%s"]}`, taServer.URL, intermediaryServer.URL, taServer.URL)
			jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
			w.Write([]byte(jwt))
		}
	})

	// Set TA server handler - can resolve intermediary
	taServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/resolve" {
			sub := r.URL.Query().Get("sub")
			if sub == intermediaryServer.URL {
				// Return intermediary's entity statement issued by TA
				w.Header().Set("Content-Type", "application/jwt")
				w.WriteHeader(http.StatusOK)
				header := `{"typ":"JWT","alg":"RS256"}`
				payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"authority_hints":["%s"]}`, taServer.URL, sub, taServer.URL)
				jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
				w.Write([]byte(jwt))
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		} else {
			// Return TA's own entity statement
			w.Header().Set("Content-Type", "application/jwt")
			w.WriteHeader(http.StatusOK)
			header := `{"typ":"JWT","alg":"RS256"}`
			payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600}`, taServer.URL, taServer.URL)
			jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
			w.Write([]byte(jwt))
		}
	})

	config := &Config{
		TrustAnchors:       []string{taServer.URL}, // Only TA is configured as trust anchor
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	}

	resolver, err := NewFederationResolver(config)
	require.NoError(t, err)

	ctx := context.Background()
	chain, err := resolver.ResolveTrustChain(ctx, rpServer.URL, false)

	assert.NoError(t, err)
	if assert.NotNil(t, chain) && len(chain.Chain) > 0 {
		assert.Len(t, chain.Chain, 3) // RP -> Intermediary -> TA
		assert.Equal(t, rpServer.URL, chain.EntityID)
		assert.Equal(t, taServer.URL, chain.TrustAnchor)

		// Verify chain order: RP, Intermediary, TA
		assert.Equal(t, rpServer.URL, chain.Chain[0].Subject)
		assert.Equal(t, intermediaryServer.URL, chain.Chain[1].Subject)
		assert.Equal(t, taServer.URL, chain.Chain[2].Subject)
	}
}

func TestResolveTrustChainWithMultipleIntermediaries(t *testing.T) {
	// Test chain building: RP -> Intermediary1 -> Intermediary2 -> TA
	taServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer taServer.Close()

	intermediary2Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer intermediary2Server.Close()

	intermediary1Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer intermediary1Server.Close()

	rpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer rpServer.Close()

	// Make RP return a direct entity statement pointing to intermediary1
	rpServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(http.StatusOK)
		header := `{"typ":"JWT","alg":"RS256"}`
		payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"authority_hints":["%s"]}`, intermediary1Server.URL, rpServer.URL, intermediary1Server.URL)
		jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
		w.Write([]byte(jwt))
	})

	// Set handlers in reverse dependency order
	taServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/resolve" {
			sub := r.URL.Query().Get("sub")
			if sub == intermediary2Server.URL {
				// Return intermediary2's entity statement issued by TA
				w.Header().Set("Content-Type", "application/jwt")
				w.WriteHeader(http.StatusOK)
				header := `{"typ":"JWT","alg":"RS256"}`
				payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"authority_hints":["%s"]}`, taServer.URL, sub, taServer.URL)
				jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
				w.Write([]byte(jwt))
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		} else {
			// Return TA's own entity statement
			w.Header().Set("Content-Type", "application/jwt")
			w.WriteHeader(http.StatusOK)
			header := `{"typ":"JWT","alg":"RS256"}`
			payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600}`, taServer.URL, taServer.URL)
			jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
			w.Write([]byte(jwt))
		}
	})

	intermediary2Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/resolve" {
			sub := r.URL.Query().Get("sub")
			if sub == intermediary1Server.URL {
				// Return intermediary1's entity statement issued by intermediary2
				w.Header().Set("Content-Type", "application/jwt")
				w.WriteHeader(http.StatusOK)
				header := `{"typ":"JWT","alg":"RS256"}`
				payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"authority_hints":["%s"]}`, intermediary2Server.URL, sub, intermediary2Server.URL)
				jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
				w.Write([]byte(jwt))
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		} else {
			// Return intermediary2's own entity statement
			w.Header().Set("Content-Type", "application/jwt")
			w.WriteHeader(http.StatusOK)
			header := `{"typ":"JWT","alg":"RS256"}`
			payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"authority_hints":["%s"]}`, taServer.URL, intermediary2Server.URL, taServer.URL)
			jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
			w.Write([]byte(jwt))
		}
	})

	intermediary1Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/resolve" {
			sub := r.URL.Query().Get("sub")
			if sub == rpServer.URL {
				// Return RP's entity statement issued by intermediary1
				w.Header().Set("Content-Type", "application/jwt")
				w.WriteHeader(http.StatusOK)
				header := `{"typ":"JWT","alg":"RS256"}`
				payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"authority_hints":["%s"]}`, intermediary1Server.URL, sub, intermediary1Server.URL)
				jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
				w.Write([]byte(jwt))
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		} else {
			// Return intermediary1's own entity statement
			w.Header().Set("Content-Type", "application/jwt")
			w.WriteHeader(http.StatusOK)
			header := `{"typ":"JWT","alg":"RS256"}`
			payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"authority_hints":["%s"]}`, intermediary2Server.URL, intermediary1Server.URL, intermediary2Server.URL)
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
	if assert.NotNil(t, chain) && len(chain.Chain) > 0 {
		assert.Len(t, chain.Chain, 4) // RP -> Intermediary1 -> Intermediary2 -> TA
	}
}

func TestResolveTrustChainWithDuplicateEntries(t *testing.T) {
	// Simulate a federation /resolve that returns duplicate entries (RP x2, Intermediary x2, TA x1)
	taServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer taServer.Close()

	// Now set handler which can reference taServer.URL safely
	taServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/resolve" {
			sub := r.URL.Query().Get("sub")
			if sub == "https://rp.example" {
				// Build duplicated chain: rp self-signed x2, intermediary self-signed x2, ta self-signed
				// Create RP self-signed
				header := `{"typ":"JWT","alg":"RS256"}`
				rpPayload := `{"iss":"https://rp.example","sub":"https://rp.example","iat":1634320000,"exp":1634323600}`
				rpJWT := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(rpPayload)) + ".sig"

				// Create intermediary self-signed
				interPayload := `{"iss":"https://int.example","sub":"https://int.example","iat":1634320000,"exp":1634323600}`
				interJWT := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(interPayload)) + ".sig"

				// TA self-signed
				taPayload := `{"iss":"` + taServer.URL + `","sub":"` + taServer.URL + `","iat":1634320000,"exp":1634323600}`
				taJWT := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(taPayload)) + ".sig"

				// trust_chain array with duplicates
				payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","trust_anchor":"%s","trust_chain":["%s","%s","%s","%s","%s"]}`,
					taServer.URL, sub, taServer.URL, rpJWT, rpJWT, interJWT, interJWT, taJWT)
				jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
				w.Header().Set("Content-Type", "application/jwt")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(jwt))
				return
			}
		}
		// default well-known
		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(http.StatusOK)
		header := `{"typ":"JWT","alg":"RS256"}`
		payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600}`, taServer.URL, taServer.URL)
		jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
		w.Write([]byte(jwt))
	})
	defer taServer.Close()

	config := &Config{
		TrustAnchors:       []string{taServer.URL},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	}

	resolver, err := NewFederationResolver(config)
	require.NoError(t, err)

	ctx := context.Background()
	chain, err := resolver.ResolveTrustChain(ctx, "https://rp.example", false)

	assert.NoError(t, err)
	// Should collapse duplicates and return canonical RP -> intermediary -> TA
	assert.Len(t, chain.Chain, 3)
	// RP first
	assert.Equal(t, "https://rp.example", chain.Chain[0].Subject)
	// intermediary second
	assert.Equal(t, "https://int.example", chain.Chain[1].Subject)
	// TA last
	assert.Equal(t, taServer.URL, chain.Chain[2].Subject)
}
