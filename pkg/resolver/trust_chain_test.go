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
