package resolver

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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
				subPayload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600}`, taServer.URL, sub)
				subJWT := base64.RawURLEncoding.EncodeToString([]byte(subHeader)) + "." + base64.RawURLEncoding.EncodeToString([]byte(subPayload)) + ".signature"

				leafHeader := `{"typ":"JWT","alg":"RS256"}`
				leafPayload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"authority_hints":["%s"]}`, rpServer.URL, rpServer.URL, taServer.URL)
				leafJWT := base64.RawURLEncoding.EncodeToString([]byte(leafHeader)) + "." + base64.RawURLEncoding.EncodeToString([]byte(leafPayload)) + ".signature"

				// Create trust-chain JWT with leaf + subordinate
				header := `{"typ":"JWT","alg":"RS256"}`
				payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","trust_anchor":"%s","iat":1634320000,"exp":1634323600,"trust_chain":["%s","%s"]}`, taServer.URL, sub, taServer.URL, leafJWT, subJWT)
				jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
				w.Write([]byte(jwt))
			}
		} else if r.URL.Path == "/fetch" {
			sub := r.URL.Query().Get("sub")
			w.Header().Set("Content-Type", "application/jwt")
			w.WriteHeader(http.StatusOK)
			header := `{"typ":"JWT","alg":"RS256"}`
			payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600}`, taServer.URL, sub)
			jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
			w.Write([]byte(jwt))
		} else if r.URL.Path == "/.well-known/openid-federation" {
			w.Header().Set("Content-Type", "application/jwt")
			w.WriteHeader(http.StatusOK)
			header := `{"typ":"JWT","alg":"RS256"}`
			payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"metadata":{"federation_entity":{"federation_fetch_endpoint":"%s/fetch"}}}`, taServer.URL, taServer.URL, taServer.URL)
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
	require.GreaterOrEqual(t, len(chain.Chain), 3) // RP EC, TA→RP, TA EC
	assert.Equal(t, rpServer.URL, chain.EntityID)
	assert.Equal(t, taServer.URL, chain.TrustAnchor)

	// NEW: Assert the first element is a self-signed Entity Configuration
	first := chain.Chain[0]
	assert.Equal(t, rpServer.URL, first.Issuer, "First element in chain should be self-signed (iss == entityID)")
	assert.Equal(t, rpServer.URL, first.Subject, "First element in chain should be self-signed (sub == entityID)")
}

func TestResolveTrustChainFallback(t *testing.T) {
	// Leaf directly under TA: EC_leaf + SubStmt(TA→leaf) + EC_TA
	taMux := http.NewServeMux()
	taServer := httptest.NewServer(taMux)
	defer taServer.Close()

	rpMux := http.NewServeMux()
	rpServer := httptest.NewServer(rpMux)
	defer rpServer.Close()

	taMux.HandleFunc("/.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(http.StatusOK)
		header := `{"typ":"JWT","alg":"RS256"}`
		payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"metadata":{"federation_entity":{"federation_fetch_endpoint":"%s/fetch"}}}`, taServer.URL, taServer.URL, taServer.URL)
		jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
		_, _ = w.Write([]byte(jwt))
	})
	taMux.HandleFunc("/fetch", func(w http.ResponseWriter, r *http.Request) {
		sub := r.URL.Query().Get("sub")
		if sub != rpServer.URL {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(http.StatusOK)
		header := `{"typ":"JWT","alg":"RS256"}`
		payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600}`, taServer.URL, sub)
		jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
		_, _ = w.Write([]byte(jwt))
	})
	taMux.HandleFunc("/resolve", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	rpMux.HandleFunc("/.well-known/openid-federation", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(http.StatusOK)
		header := `{"typ":"JWT","alg":"RS256"}`
		payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"authority_hints":["%s"]}`, rpServer.URL, rpServer.URL, taServer.URL)
		jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
		_, _ = w.Write([]byte(jwt))
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
	require.NotNil(t, chain)
	require.GreaterOrEqual(t, len(chain.Chain), 3) // EC_RP, TA→RP, EC_TA
	assert.Equal(t, rpServer.URL, chain.EntityID)
	assert.Equal(t, taServer.URL, chain.TrustAnchor)
	assert.Equal(t, rpServer.URL, chain.Chain[0].Issuer)
	assert.Equal(t, rpServer.URL, chain.Chain[0].Subject)
	assert.Equal(t, taServer.URL, chain.Chain[1].Issuer)
	assert.Equal(t, rpServer.URL, chain.Chain[1].Subject)
}

func TestResolveTrustChainCompletesMissingTAToIntermediary(t *testing.T) {
	// Reproduces the PoC bug: TA /resolve returns only
	//   [EC_leaf, SubStmt(Int→leaf)]
	// and the resolver must complete with
	//   SubStmt(TA→Int) via /fetch and EC_TA via well-known.
	taServer := httptest.NewServer(nil)
	defer taServer.Close()
	intServer := httptest.NewServer(nil)
	defer intServer.Close()
	rpServer := httptest.NewServer(nil)
	defer rpServer.Close()

	mkJWT := func(iss, sub string, extra string) string {
		header := `{"typ":"entity-statement+jwt","alg":"ES256"}`
		payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600%s}`, iss, sub, extra)
		return base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
			base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
	}

	rpEC := mkJWT(rpServer.URL, rpServer.URL, fmt.Sprintf(`,"authority_hints":["%s"]`, intServer.URL))
	intToRP := mkJWT(intServer.URL, rpServer.URL, "")
	taToInt := mkJWT(taServer.URL, intServer.URL, "")
	taEC := mkJWT(taServer.URL, taServer.URL, fmt.Sprintf(
		`,"metadata":{"federation_entity":{"federation_fetch_endpoint":"%s/fetch"}}`, taServer.URL))
	intEC := mkJWT(intServer.URL, intServer.URL, fmt.Sprintf(`,"authority_hints":["%s"]`, taServer.URL))

	rpServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		_, _ = w.Write([]byte(rpEC))
	})
	intServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fetch":
			if r.URL.Query().Get("sub") == rpServer.URL {
				w.Header().Set("Content-Type", "application/entity-statement+jwt")
				_, _ = w.Write([]byte(intToRP))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		default:
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			_, _ = w.Write([]byte(intEC))
		}
	})
	taServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/resolve":
			// Incomplete trust_chain: leaf EC + Int→RP only (the production bug)
			header := `{"typ":"resolve-response+jwt","alg":"ES256"}`
			payload := fmt.Sprintf(
				`{"iss":"%s","sub":"%s","trust_anchor":"%s","iat":1634320000,"exp":1634323600,"trust_chain":["%s","%s"]}`,
				taServer.URL, rpServer.URL, taServer.URL, rpEC, intToRP)
			jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
				base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
			w.Header().Set("Content-Type", "application/resolve-response+jwt")
			_, _ = w.Write([]byte(jwt))
		case "/fetch":
			if r.URL.Query().Get("sub") == intServer.URL {
				w.Header().Set("Content-Type", "application/entity-statement+jwt")
				_, _ = w.Write([]byte(taToInt))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		default:
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			_, _ = w.Write([]byte(taEC))
		}
	})

	resolver, err := NewFederationResolver(&Config{
		TrustAnchors:       []string{taServer.URL},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	})
	require.NoError(t, err)

	chain, err := resolver.ResolveTrustChainWithAnchor(context.Background(), rpServer.URL, taServer.URL, true)
	require.NoError(t, err)
	require.NotNil(t, chain)
	require.Equal(t, "valid", chain.Status)
	require.GreaterOrEqual(t, len(chain.Chain), 4, "expected EC_leaf, Int→leaf, TA→Int, EC_TA")

	assert.Equal(t, rpServer.URL, chain.Chain[0].Issuer)
	assert.Equal(t, rpServer.URL, chain.Chain[0].Subject)

	assert.Equal(t, intServer.URL, chain.Chain[1].Issuer)
	assert.Equal(t, rpServer.URL, chain.Chain[1].Subject)

	foundTAToInt := false
	foundTAEC := false
	for _, e := range chain.Chain {
		if e.Issuer == taServer.URL && e.Subject == intServer.URL {
			foundTAToInt = true
		}
		if e.Issuer == taServer.URL && e.Subject == taServer.URL {
			foundTAEC = true
		}
	}
	assert.True(t, foundTAToInt, "missing SubStmt(TA→intermediary)")
	assert.True(t, foundTAEC, "missing TA Entity Configuration")
}

func TestResolveTrustChainCompletesWhenIntermediaryWellKnownDown(t *testing.T) {
	// PoC production case: TA /resolve returns only [EC_leaf, Int→leaf],
	// and the intermediary well-known is unreachable. Completion must still
	// /fetch TA→Int and the TA Entity Configuration.
	taServer := httptest.NewServer(nil)
	defer taServer.Close()
	intServer := httptest.NewServer(nil)
	defer intServer.Close()
	rpServer := httptest.NewServer(nil)
	defer rpServer.Close()

	mkJWT := func(iss, sub string, extra string) string {
		header := `{"typ":"entity-statement+jwt","alg":"ES256"}`
		payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600%s}`, iss, sub, extra)
		return base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
			base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
	}

	rpEC := mkJWT(rpServer.URL, rpServer.URL, fmt.Sprintf(`,"authority_hints":["%s"]`, intServer.URL))
	intToRP := mkJWT(intServer.URL, rpServer.URL, "")
	taToInt := mkJWT(taServer.URL, intServer.URL, "")
	taEC := mkJWT(taServer.URL, taServer.URL, fmt.Sprintf(
		`,"metadata":{"federation_entity":{"federation_fetch_endpoint":"%s/fetch"}}`, taServer.URL))

	rpServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		_, _ = w.Write([]byte(rpEC))
	})
	intServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("intermediary well-known down"))
	})
	taServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/resolve":
			header := `{"typ":"resolve-response+jwt","alg":"ES256"}`
			payload := fmt.Sprintf(
				`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"trust_chain":["%s","%s"]}`,
				taServer.URL, rpServer.URL, rpEC, intToRP)
			jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
				base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
			w.Header().Set("Content-Type", "application/resolve-response+jwt")
			_, _ = w.Write([]byte(jwt))
		case "/fetch":
			if r.URL.Query().Get("sub") == intServer.URL {
				w.Header().Set("Content-Type", "application/entity-statement+jwt")
				_, _ = w.Write([]byte(taToInt))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		default:
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			_, _ = w.Write([]byte(taEC))
		}
	})

	resolver, err := NewFederationResolver(&Config{
		TrustAnchors:       []string{taServer.URL},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	})
	require.NoError(t, err)

	chain, err := resolver.ResolveTrustChainWithAnchor(context.Background(), rpServer.URL, taServer.URL, true)
	require.NoError(t, err)
	require.NotNil(t, chain)
	require.Equal(t, "valid", chain.Status)
	require.GreaterOrEqual(t, len(chain.Chain), 4, "expected EC_leaf, Int→leaf, TA→Int, EC_TA even when intermediary EC is down")

	foundTAToInt := false
	foundTAEC := false
	for _, e := range chain.Chain {
		if e.Issuer == taServer.URL && e.Subject == intServer.URL {
			foundTAToInt = true
		}
		if e.Issuer == taServer.URL && e.Subject == taServer.URL {
			foundTAEC = true
		}
	}
	assert.True(t, foundTAToInt, "missing SubStmt(TA→intermediary)")
	assert.True(t, foundTAEC, "missing TA Entity Configuration")
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
		payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"authority_hints":["%s"]}`, rpServer.URL, rpServer.URL, intermediaryServer.URL)
		jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
		w.Write([]byte(jwt))
	})

	// Set Intermediary server handler - points to TA and can fetch RP
	intermediaryServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fetch" || r.URL.Path == "/resolve" {
			sub := r.URL.Query().Get("sub")
			if sub == rpServer.URL {
				// Return RP's subordinate statement issued by intermediary
				w.Header().Set("Content-Type", "application/jwt")
				w.WriteHeader(http.StatusOK)
				header := `{"typ":"JWT","alg":"RS256"}`
				payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600}`, intermediaryServer.URL, sub)
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
			payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"authority_hints":["%s"],"metadata":{"federation_entity":{"federation_fetch_endpoint":"%s/fetch"}}}`, intermediaryServer.URL, intermediaryServer.URL, taServer.URL, intermediaryServer.URL)
			jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
			w.Write([]byte(jwt))
		}
	})

	// Set TA server handler - can fetch intermediary
	taServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fetch" || r.URL.Path == "/resolve" {
			sub := r.URL.Query().Get("sub")
			if sub == intermediaryServer.URL {
				// Return intermediary's subordinate statement issued by TA
				w.Header().Set("Content-Type", "application/jwt")
				w.WriteHeader(http.StatusOK)
				header := `{"typ":"JWT","alg":"RS256"}`
				payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600}`, taServer.URL, sub)
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
			payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"metadata":{"federation_entity":{"federation_fetch_endpoint":"%s/fetch"}}}`, taServer.URL, taServer.URL, taServer.URL)
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
		require.GreaterOrEqual(t, len(chain.Chain), 4) // EC_RP, Int→RP, TA→Int, EC_TA
		assert.Equal(t, rpServer.URL, chain.EntityID)
		assert.Equal(t, taServer.URL, chain.TrustAnchor)

		assert.Equal(t, rpServer.URL, chain.Chain[0].Issuer)
		assert.Equal(t, rpServer.URL, chain.Chain[0].Subject)
		assert.Equal(t, intermediaryServer.URL, chain.Chain[1].Issuer)
		assert.Equal(t, rpServer.URL, chain.Chain[1].Subject)

		foundTAToInt := false
		foundTAEC := false
		for _, e := range chain.Chain {
			if e.Issuer == taServer.URL && e.Subject == intermediaryServer.URL {
				foundTAToInt = true
			}
			if e.Issuer == taServer.URL && e.Subject == taServer.URL {
				foundTAEC = true
			}
		}
		assert.True(t, foundTAToInt)
		assert.True(t, foundTAEC)
	}
}

func TestResolveTrustChainWithMultipleIntermediaries(t *testing.T) {
	// RP -> Int1 -> Int2 -> TA
	taServer := httptest.NewServer(nil)
	defer taServer.Close()
	int2 := httptest.NewServer(nil)
	defer int2.Close()
	int1 := httptest.NewServer(nil)
	defer int1.Close()
	rpServer := httptest.NewServer(nil)
	defer rpServer.Close()

	mk := func(iss, sub, extra string) string {
		h := `{"typ":"JWT","alg":"RS256"}`
		p := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600%s}`, iss, sub, extra)
		return base64.RawURLEncoding.EncodeToString([]byte(h)) + "." + base64.RawURLEncoding.EncodeToString([]byte(p)) + ".sig"
	}

	rpServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(mk(rpServer.URL, rpServer.URL, fmt.Sprintf(`,"authority_hints":["%s"]`, int1.URL))))
	})
	int1.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fetch" && r.URL.Query().Get("sub") == rpServer.URL {
			_, _ = w.Write([]byte(mk(int1.URL, rpServer.URL, "")))
			return
		}
		_, _ = w.Write([]byte(mk(int1.URL, int1.URL, fmt.Sprintf(`,"authority_hints":["%s"],"metadata":{"federation_entity":{"federation_fetch_endpoint":"%s/fetch"}}`, int2.URL, int1.URL))))
	})
	int2.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fetch" && r.URL.Query().Get("sub") == int1.URL {
			_, _ = w.Write([]byte(mk(int2.URL, int1.URL, "")))
			return
		}
		_, _ = w.Write([]byte(mk(int2.URL, int2.URL, fmt.Sprintf(`,"authority_hints":["%s"],"metadata":{"federation_entity":{"federation_fetch_endpoint":"%s/fetch"}}`, taServer.URL, int2.URL))))
	})
	taServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fetch" && r.URL.Query().Get("sub") == int2.URL {
			_, _ = w.Write([]byte(mk(taServer.URL, int2.URL, "")))
			return
		}
		if r.URL.Path == "/resolve" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(mk(taServer.URL, taServer.URL, fmt.Sprintf(`,"metadata":{"federation_entity":{"federation_fetch_endpoint":"%s/fetch"}}`, taServer.URL))))
	})

	resolver, err := NewFederationResolver(&Config{
		TrustAnchors:       []string{taServer.URL},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	})
	require.NoError(t, err)

	chain, err := resolver.ResolveTrustChain(context.Background(), rpServer.URL, true)
	require.NoError(t, err)
	require.NotNil(t, chain)
	require.GreaterOrEqual(t, len(chain.Chain), 5) // EC_RP, Int1→RP, Int2→Int1, TA→Int2, EC_TA

	assert.Equal(t, rpServer.URL, chain.Chain[0].Issuer)
	assert.Equal(t, rpServer.URL, chain.Chain[0].Subject)
	assert.Equal(t, int1.URL, chain.Chain[1].Issuer)
	assert.Equal(t, rpServer.URL, chain.Chain[1].Subject)

	found := map[string]bool{}
	for _, e := range chain.Chain {
		found[e.Issuer+"→"+e.Subject] = true
	}
	assert.True(t, found[int2.URL+"→"+int1.URL], "missing Int2→Int1")
	assert.True(t, found[taServer.URL+"→"+int2.URL], "missing TA→Int2")
	assert.True(t, found[taServer.URL+"→"+taServer.URL], "missing TA EC")
}

func TestResolveTrustChainWithDuplicateEntries(t *testing.T) {
	// Federation /resolve returns duplicate entries; resolver must dedupe and keep a TA-rooted chain.
	taServer := httptest.NewServer(nil)
	defer taServer.Close()
	intServer := httptest.NewServer(nil)
	defer intServer.Close()
	rpServer := httptest.NewServer(nil)
	defer rpServer.Close()

	mk := func(iss, sub, extra string) string {
		h := `{"typ":"JWT","alg":"RS256"}`
		p := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600%s}`, iss, sub, extra)
		return base64.RawURLEncoding.EncodeToString([]byte(h)) + "." + base64.RawURLEncoding.EncodeToString([]byte(p)) + ".sig"
	}

	rpEC := mk(rpServer.URL, rpServer.URL, fmt.Sprintf(`,"authority_hints":["%s"]`, intServer.URL))
	intToRP := mk(intServer.URL, rpServer.URL, "")
	taToInt := mk(taServer.URL, intServer.URL, "")
	taEC := mk(taServer.URL, taServer.URL, fmt.Sprintf(`,"metadata":{"federation_entity":{"federation_fetch_endpoint":"%s/fetch"}}`, taServer.URL))
	intEC := mk(intServer.URL, intServer.URL, fmt.Sprintf(`,"authority_hints":["%s"]`, taServer.URL))

	rpServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(rpEC))
	})
	intServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fetch" {
			_, _ = w.Write([]byte(intToRP))
			return
		}
		_, _ = w.Write([]byte(intEC))
	})
	taServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/resolve":
			header := `{"typ":"JWT","alg":"RS256"}`
			payload := fmt.Sprintf(
				`{"iss":"%s","sub":"%s","trust_anchor":"%s","trust_chain":["%s","%s","%s","%s","%s","%s"]}`,
				taServer.URL, rpServer.URL, taServer.URL,
				rpEC, rpEC, intToRP, intToRP, taToInt, taEC)
			jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
				base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
			_, _ = w.Write([]byte(jwt))
		case "/fetch":
			_, _ = w.Write([]byte(taToInt))
		default:
			_, _ = w.Write([]byte(taEC))
		}
	})

	resolver, err := NewFederationResolver(&Config{
		TrustAnchors:       []string{taServer.URL},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	})
	require.NoError(t, err)

	chain, err := resolver.ResolveTrustChain(context.Background(), rpServer.URL, true)
	require.NoError(t, err)
	require.NotNil(t, chain)
	require.GreaterOrEqual(t, len(chain.Chain), 4)

	seen := map[string]int{}
	for _, e := range chain.Chain {
		seen[e.Issuer+" "+e.Subject]++
	}
	for k, n := range seen {
		assert.Equal(t, 1, n, "duplicate entry for %s", k)
	}
	assert.Equal(t, rpServer.URL, chain.Chain[0].Issuer)
	assert.Equal(t, rpServer.URL, chain.Chain[0].Subject)
}

func TestParseTrustChainIntermediarySelfSignedReplaced(t *testing.T) {
	// Resolve response mixes intermediary EC with Int→RP subordinate; resolver must
	// prefer the subordinate and complete with TA→Int + TA EC.
	taServer := httptest.NewServer(nil)
	defer taServer.Close()
	intServer := httptest.NewServer(nil)
	defer intServer.Close()
	rpServer := httptest.NewServer(nil)
	defer rpServer.Close()

	mk := func(iss, sub, extra string) string {
		h := `{"typ":"JWT","alg":"RS256"}`
		p := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600%s}`, iss, sub, extra)
		return base64.RawURLEncoding.EncodeToString([]byte(h)) + "." + base64.RawURLEncoding.EncodeToString([]byte(p)) + ".sig"
	}

	rpEC := mk(rpServer.URL, rpServer.URL, fmt.Sprintf(`,"authority_hints":["%s"]`, intServer.URL))
	intEC := mk(intServer.URL, intServer.URL, fmt.Sprintf(`,"authority_hints":["%s"]`, taServer.URL))
	intToRP := mk(intServer.URL, rpServer.URL, "")
	taToInt := mk(taServer.URL, intServer.URL, "")
	taEC := mk(taServer.URL, taServer.URL, fmt.Sprintf(`,"metadata":{"federation_entity":{"federation_fetch_endpoint":"%s/fetch"}}`, taServer.URL))

	rpServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(rpEC))
	})
	intServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(intEC))
	})
	taServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/resolve":
			header := `{"typ":"JWT","alg":"RS256"}`
			payload := fmt.Sprintf(
				`{"iss":"%s","sub":"%s","trust_anchor":"%s","iat":1634320000,"exp":1634323600,"trust_chain":["%s","%s","%s","%s"]}`,
				taServer.URL, rpServer.URL, taServer.URL, rpEC, intEC, intToRP, taEC)
			jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
				base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
			_, _ = w.Write([]byte(jwt))
		case "/fetch":
			_, _ = w.Write([]byte(taToInt))
		default:
			_, _ = w.Write([]byte(taEC))
		}
	})

	resolver, err := NewFederationResolver(&Config{
		TrustAnchors:       []string{taServer.URL},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	})
	require.NoError(t, err)

	chain, err := resolver.ResolveTrustChain(context.Background(), rpServer.URL, true)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chain.Chain), 4)

	assert.Equal(t, rpServer.URL, chain.Chain[0].Subject)
	assert.Equal(t, rpServer.URL, chain.Chain[0].Issuer)
	assert.Equal(t, rpServer.URL, chain.Chain[1].Subject)
	assert.Equal(t, intServer.URL, chain.Chain[1].Issuer)
	assert.NotEqual(t, chain.Chain[1].Issuer, chain.Chain[1].Subject)

	foundTAToInt := false
	foundTAEC := false
	for _, e := range chain.Chain {
		if e.Issuer == taServer.URL && e.Subject == intServer.URL {
			foundTAToInt = true
		}
		if e.Issuer == taServer.URL && e.Subject == taServer.URL {
			foundTAEC = true
		}
	}
	assert.True(t, foundTAToInt)
	assert.True(t, foundTAEC)
}

func TestResolveTrustChainCompletesMissingOnlyTAEC(t *testing.T) {
	// Live PoC shape: TA /resolve already has
	//   [EC_leaf, Int→leaf, TA→Int]
	// and only the TA Entity Configuration is missing.
	taServer := httptest.NewServer(nil)
	defer taServer.Close()
	intServer := httptest.NewServer(nil)
	defer intServer.Close()
	rpServer := httptest.NewServer(nil)
	defer rpServer.Close()

	rpEC := unsignedEntityJWT(rpServer.URL, rpServer.URL, fmt.Sprintf(`,"authority_hints":["%s"]`, intServer.URL))
	intToRP := unsignedEntityJWT(intServer.URL, rpServer.URL, "")
	taToInt := unsignedEntityJWT(taServer.URL, intServer.URL, "")
	taEC := unsignedEntityJWT(taServer.URL, taServer.URL, fmt.Sprintf(
		`,"metadata":{"federation_entity":{"federation_fetch_endpoint":"%s/fetch"}}`, taServer.URL))

	rpServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		_, _ = w.Write([]byte(rpEC))
	})
	intServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	taServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/resolve":
			header := `{"typ":"resolve-response+jwt","alg":"ES256"}`
			payload := fmt.Sprintf(
				`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"trust_chain":["%s","%s","%s"]}`,
				taServer.URL, rpServer.URL, rpEC, intToRP, taToInt)
			jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
				base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
			w.Header().Set("Content-Type", "application/resolve-response+jwt")
			_, _ = w.Write([]byte(jwt))
		case "/fetch":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			_, _ = w.Write([]byte(taEC))
		}
	})

	res, err := NewFederationResolver(&Config{
		TrustAnchors:       []string{taServer.URL},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	})
	require.NoError(t, err)

	chain, err := res.ResolveTrustChainWithAnchor(context.Background(), rpServer.URL, taServer.URL, true)
	require.NoError(t, err)
	require.Equal(t, "valid", chain.Status)
	assertCanonicalChain(t, chain, [][2]string{
		{rpServer.URL, rpServer.URL},
		{intServer.URL, rpServer.URL},
		{taServer.URL, intServer.URL},
		{taServer.URL, taServer.URL},
	})
}

func TestResolveTrustChainValidatesSignatures(t *testing.T) {
	taServer := httptest.NewServer(nil)
	defer taServer.Close()
	rpServer := httptest.NewServer(nil)
	defer rpServer.Close()

	taEnt, err := newTestEntity(taServer.URL)
	require.NoError(t, err)
	rpEnt, err := newTestEntity(rpServer.URL)
	require.NoError(t, err)

	now := time.Now()
	iat := now.Unix()
	exp := now.Add(time.Hour).Unix()

	signEC := func(ent *testEntity, hints []string, extraMeta map[string]interface{}) string {
		fed := map[string]interface{}{}
		for k, v := range extraMeta {
			fed[k] = v
		}
		token, err := ent.SignEntityStatement(context.Background(), map[string]interface{}{
			"iss":             ent.EntityID,
			"sub":             ent.EntityID,
			"iat":             iat,
			"exp":             exp,
			"authority_hints": hints,
			"jwks":            ent.GetJWKS(),
			"metadata":        map[string]interface{}{"federation_entity": fed},
		})
		require.NoError(t, err)
		return token
	}
	signSub := func(issuer *testEntity, subject string) string {
		token, err := issuer.SignEntityStatement(context.Background(), map[string]interface{}{
			"iss":  issuer.EntityID,
			"sub":  subject,
			"iat":  iat,
			"exp":  exp,
			"jwks": map[string]interface{}{"keys": []interface{}{}},
		})
		require.NoError(t, err)
		return token
	}

	rpEC := signEC(rpEnt, []string{taServer.URL}, nil)
	taToRP := signSub(taEnt, rpServer.URL)
	taEC := signEC(taEnt, nil, map[string]interface{}{
		"federation_fetch_endpoint": taServer.URL + "/fetch",
	})

	rpServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		_, _ = w.Write([]byte(rpEC))
	})
	taServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		switch r.URL.Path {
		case "/resolve":
			w.WriteHeader(http.StatusNotFound)
		case "/fetch":
			if r.URL.Query().Get("sub") == rpServer.URL {
				_, _ = w.Write([]byte(taToRP))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		default:
			_, _ = w.Write([]byte(taEC))
		}
	})

	res, err := NewFederationResolver(&Config{
		TrustAnchors:       []string{taServer.URL},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: true,
	})
	require.NoError(t, err)

	chain, err := res.ResolveTrustChainWithAnchor(context.Background(), rpServer.URL, taServer.URL, true)
	require.NoError(t, err)
	require.Equal(t, "valid", chain.Status)
	assertCanonicalChain(t, chain, [][2]string{
		{rpServer.URL, rpServer.URL},
		{taServer.URL, rpServer.URL},
		{taServer.URL, taServer.URL},
	})
	for i, e := range chain.Chain {
		assert.True(t, e.Validated, "chain[%d] should be signature-validated", i)
	}
}

func TestResolveTrustChainCannotReachTrustAnchor(t *testing.T) {
	taServer := httptest.NewServer(nil)
	defer taServer.Close()
	deadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer deadServer.Close()
	intServer := httptest.NewServer(nil)
	defer intServer.Close()
	rpServer := httptest.NewServer(nil)
	defer rpServer.Close()

	rpEC := unsignedEntityJWT(rpServer.URL, rpServer.URL, fmt.Sprintf(`,"authority_hints":["%s"]`, intServer.URL))
	intEC := unsignedEntityJWT(intServer.URL, intServer.URL, fmt.Sprintf(
		`,"authority_hints":["%s"],"metadata":{"federation_entity":{"federation_fetch_endpoint":"%s/fetch"}}`,
		deadServer.URL, intServer.URL))
	intToRP := unsignedEntityJWT(intServer.URL, rpServer.URL, "")
	taEC := unsignedEntityJWT(taServer.URL, taServer.URL, fmt.Sprintf(
		`,"metadata":{"federation_entity":{"federation_fetch_endpoint":"%s/fetch"}}`, taServer.URL))

	rpServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(rpEC))
	})
	intServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fetch" && r.URL.Query().Get("sub") == rpServer.URL {
			_, _ = w.Write([]byte(intToRP))
			return
		}
		_, _ = w.Write([]byte(intEC))
	})
	taServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/resolve" || r.URL.Path == "/fetch" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(taEC))
	})

	res, err := NewFederationResolver(&Config{
		TrustAnchors:       []string{taServer.URL},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	})
	require.NoError(t, err)

	chain, err := res.ResolveTrustChain(context.Background(), rpServer.URL, true)
	assert.Error(t, err)
	require.NotNil(t, chain)
	assert.NotEqual(t, "valid", chain.Status)
}

func TestResolveTrustChainStopsAtNearestConfiguredTrustAnchor(t *testing.T) {
	// PoC shape: local TA is itself a subordinate of a superior TA (eduGAIN).
	// Without an explicit trust_anchor, the chain must root at the local TA
	// even if the superior is also configured and listed first, and even if
	// the local TA /resolve JWT names the superior as trust_anchor.
	superior := httptest.NewServer(nil)
	defer superior.Close()
	localTA := httptest.NewServer(nil)
	defer localTA.Close()
	intServer := httptest.NewServer(nil)
	defer intServer.Close()
	rpServer := httptest.NewServer(nil)
	defer rpServer.Close()

	rpEC := unsignedEntityJWT(rpServer.URL, rpServer.URL, fmt.Sprintf(`,"authority_hints":["%s"]`, intServer.URL))
	intToRP := unsignedEntityJWT(intServer.URL, rpServer.URL, "")
	intEC := unsignedEntityJWT(intServer.URL, intServer.URL, fmt.Sprintf(
		`,"authority_hints":["%s"],"metadata":{"federation_entity":{"federation_fetch_endpoint":"%s/fetch"}}`,
		localTA.URL, intServer.URL))
	localToInt := unsignedEntityJWT(localTA.URL, intServer.URL, "")
	localEC := unsignedEntityJWT(localTA.URL, localTA.URL, fmt.Sprintf(
		`,"authority_hints":["%s"],"metadata":{"federation_entity":{"federation_fetch_endpoint":"%s/fetch"}}`,
		superior.URL, localTA.URL))
	superiorToLocal := unsignedEntityJWT(superior.URL, localTA.URL, "")
	superiorEC := unsignedEntityJWT(superior.URL, superior.URL, fmt.Sprintf(
		`,"metadata":{"federation_entity":{"federation_fetch_endpoint":"%s/fetch"}}`, superior.URL))

	rpServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(rpEC))
	})
	intServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fetch" && r.URL.Query().Get("sub") == rpServer.URL {
			_, _ = w.Write([]byte(intToRP))
			return
		}
		_, _ = w.Write([]byte(intEC))
	})
	localTA.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/resolve":
			_, _ = w.Write([]byte(unsignedResolveJWT(localTA.URL, rpServer.URL, superior.URL, rpEC, intToRP, localToInt)))
		case "/fetch":
			if r.URL.Query().Get("sub") == intServer.URL {
				_, _ = w.Write([]byte(localToInt))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		default:
			_, _ = w.Write([]byte(localEC))
		}
	})
	superior.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/resolve":
			_, _ = w.Write([]byte(unsignedResolveJWT(superior.URL, rpServer.URL, superior.URL, rpEC, intToRP, localToInt, superiorToLocal)))
		case "/fetch":
			if r.URL.Query().Get("sub") == localTA.URL {
				_, _ = w.Write([]byte(superiorToLocal))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		default:
			_, _ = w.Write([]byte(superiorEC))
		}
	})

	res, err := NewFederationResolver(&Config{
		TrustAnchors:       []string{superior.URL, localTA.URL},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	})
	require.NoError(t, err)

	chain, err := res.ResolveTrustChain(context.Background(), rpServer.URL, true)
	require.NoError(t, err)
	require.Equal(t, "valid", chain.Status)
	assert.Equal(t, localTA.URL, chain.TrustAnchor)
	assertCanonicalChain(t, chain, [][2]string{
		{rpServer.URL, rpServer.URL},
		{intServer.URL, rpServer.URL},
		{localTA.URL, intServer.URL},
		{localTA.URL, localTA.URL},
	})

	explicitLocal, err := res.ResolveTrustChainWithAnchor(context.Background(), rpServer.URL, localTA.URL, true)
	require.NoError(t, err)
	require.Equal(t, "valid", explicitLocal.Status)
	assert.Equal(t, localTA.URL, explicitLocal.TrustAnchor)
	assertCanonicalChain(t, explicitLocal, [][2]string{
		{rpServer.URL, rpServer.URL},
		{intServer.URL, rpServer.URL},
		{localTA.URL, intServer.URL},
		{localTA.URL, localTA.URL},
	})

	explicitHigh, err := res.ResolveTrustChainWithAnchor(context.Background(), rpServer.URL, superior.URL, true)
	require.NoError(t, err)
	require.Equal(t, "valid", explicitHigh.Status)
	assert.Equal(t, superior.URL, explicitHigh.TrustAnchor)
	assertCanonicalChain(t, explicitHigh, [][2]string{
		{rpServer.URL, rpServer.URL},
		{intServer.URL, rpServer.URL},
		{localTA.URL, intServer.URL},
		{superior.URL, localTA.URL},
		{superior.URL, superior.URL},
	})
}

func TestResolveTrustChainDoesNotFollowTAAuthorityHints(t *testing.T) {
	// Live PoC: TA /resolve already returns
	//   [EC_RP, Int→RP, poc2TA→Int]
	// with trust_anchor=eduGAIN, and the poc2 TA Entity Configuration has
	// authority_hints to eduGAIN. Completing the chain must append the poc2
	// TA EC, not SubStmt(eduGAIN→poc2) + EC_eduGAIN.
	superior := httptest.NewServer(nil)
	defer superior.Close()
	localTA := httptest.NewServer(nil)
	defer localTA.Close()
	intServer := httptest.NewServer(nil)
	defer intServer.Close()
	rpServer := httptest.NewServer(nil)
	defer rpServer.Close()

	rpEC := unsignedEntityJWT(rpServer.URL, rpServer.URL, fmt.Sprintf(`,"authority_hints":["%s"]`, intServer.URL))
	intToRP := unsignedEntityJWT(intServer.URL, rpServer.URL, "")
	localToInt := unsignedEntityJWT(localTA.URL, intServer.URL, "")
	localEC := unsignedEntityJWT(localTA.URL, localTA.URL, fmt.Sprintf(
		`,"authority_hints":["%s"],"metadata":{"federation_entity":{"federation_fetch_endpoint":"%s/fetch"}}`,
		superior.URL, localTA.URL))
	superiorToLocal := unsignedEntityJWT(superior.URL, localTA.URL, "")
	superiorEC := unsignedEntityJWT(superior.URL, superior.URL, fmt.Sprintf(
		`,"metadata":{"federation_entity":{"federation_fetch_endpoint":"%s/fetch"}}`, superior.URL))

	rpServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(rpEC))
	})
	intServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	localTA.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/resolve":
			_, _ = w.Write([]byte(unsignedResolveJWT(localTA.URL, rpServer.URL, superior.URL, rpEC, intToRP, localToInt)))
		case "/fetch":
			w.WriteHeader(http.StatusNotFound)
		default:
			_, _ = w.Write([]byte(localEC))
		}
	})
	superior.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fetch":
			if r.URL.Query().Get("sub") == localTA.URL {
				_, _ = w.Write([]byte(superiorToLocal))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		default:
			_, _ = w.Write([]byte(superiorEC))
		}
	})

	res, err := NewFederationResolver(&Config{
		TrustAnchors:       []string{localTA.URL},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	})
	require.NoError(t, err)

	chain, err := res.ResolveTrustChainWithAnchor(context.Background(), rpServer.URL, localTA.URL, true)
	require.NoError(t, err)
	require.Equal(t, "valid", chain.Status)
	assert.Equal(t, localTA.URL, chain.TrustAnchor)
	assertCanonicalChain(t, chain, [][2]string{
		{rpServer.URL, rpServer.URL},
		{intServer.URL, rpServer.URL},
		{localTA.URL, intServer.URL},
		{localTA.URL, localTA.URL},
	})
	for i, e := range chain.Chain {
		assert.NotEqual(t, superior.URL, e.Issuer, "chain[%d] walked past the requested TA to %s", i, e.Issuer)
		assert.NotEqual(t, superior.URL, e.Subject, "chain[%d] walked past the requested TA to %s", i, e.Subject)
	}
}

func unsignedEntityJWT(iss, sub, extra string) string {
	header := `{"typ":"entity-statement+jwt","alg":"ES256"}`
	payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600%s}`, iss, sub, extra)
	return base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
}

func unsignedResolveJWT(iss, sub, trustAnchor string, chain ...string) string {
	quoted := make([]string, len(chain))
	for i, s := range chain {
		quoted[i] = fmt.Sprintf("%q", s)
	}
	header := `{"typ":"resolve-response+jwt","alg":"ES256"}`
	payload := fmt.Sprintf(
		`{"iss":"%s","sub":"%s","trust_anchor":"%s","iat":1634320000,"exp":1634323600,"trust_chain":[%s]}`,
		iss, sub, trustAnchor, strings.Join(quoted, ","))
	return base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
}

func assertCanonicalChain(t *testing.T, chain *CachedTrustChain, pairs [][2]string) {
	t.Helper()
	require.Len(t, chain.Chain, len(pairs))
	for i, pair := range pairs {
		assert.Equal(t, pair[0], chain.Chain[i].Issuer, "chain[%d].iss", i)
		assert.Equal(t, pair[1], chain.Chain[i].Subject, "chain[%d].sub", i)
	}
}
