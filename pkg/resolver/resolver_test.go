package resolver

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
	assert.Len(t, chain.Chain, 2) // RP and TA
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

func TestExtractFederationListEndpoint(t *testing.T) {
	config := &Config{
		TrustAnchors:       []string{"http://ta.example.com"},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	}

	resolver, err := NewFederationResolver(config)
	require.NoError(t, err)

	tests := []struct {
		name        string
		entity      *CachedEntityStatement
		expectedURL string
		expectError bool
	}{
		{
			name: "valid federation_list_endpoint",
			entity: &CachedEntityStatement{
				ParsedClaims: map[string]interface{}{
					"metadata": map[string]interface{}{
						"federation_entity": map[string]interface{}{
							"federation_list_endpoint": "http://ta.example.com/federation_list",
						},
					},
				},
			},
			expectedURL: "http://ta.example.com/federation_list",
			expectError: false,
		},
		{
			name: "missing federation_list_endpoint",
			entity: &CachedEntityStatement{
				ParsedClaims: map[string]interface{}{
					"metadata": map[string]interface{}{
						"federation_entity": map[string]interface{}{},
					},
				},
			},
			expectedURL: "",
			expectError: true,
		},
		{
			name: "missing federation_entity metadata",
			entity: &CachedEntityStatement{
				ParsedClaims: map[string]interface{}{},
			},
			expectedURL: "",
			expectError: true,
		},
		{
			name: "federation_list_endpoint is false",
			entity: &CachedEntityStatement{
				ParsedClaims: map[string]interface{}{
					"metadata": map[string]interface{}{
						"federation_entity": map[string]interface{}{
							"federation_list_endpoint": false,
						},
					},
				},
			},
			expectedURL: "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, err := resolver.ExtractFederationListEndpoint(tt.entity)

			if tt.expectError {
				assert.Error(t, err)
				assert.Empty(t, url)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedURL, url)
			}
		})
	}
}

func TestQueryFederationListEndpoint(t *testing.T) {
	// Create test server for federation list endpoint
	listServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check query parameters
		entityType := r.URL.Query().Get("entity_type")
		trustMarked := r.URL.Query().Get("trust_marked")
		trustMarkType := r.URL.Query().Get("trust_mark_type")
		intermediate := r.URL.Query().Get("intermediate")

		// Return different responses based on parameters
		if entityType == "openid_relying_party" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			response := `["http://rp1.example.com", "http://rp2.example.com"]`
			w.Write([]byte(response))
		} else if trustMarked == "true" && trustMarkType == "test_mark" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			response := `["http://trusted-rp.example.com"]`
			w.Write([]byte(response))
		} else if intermediate == "true" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			response := `["http://intermediate1.example.com", "http://intermediate2.example.com"]`
			w.Write([]byte(response))
		} else {
			// Default response - all federation members
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			response := `["http://rp1.example.com", "http://op1.example.com", "http://intermediate1.example.com"]`
			w.Write([]byte(response))
		}
	}))
	defer listServer.Close()

	config := &Config{
		TrustAnchors:       []string{"http://ta.example.com"},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	}

	resolver, err := NewFederationResolver(config)
	require.NoError(t, err)

	ctx := context.Background()

	tests := []struct {
		name            string
		endpoint        string
		entityType      string
		trustMarked     string
		trustMarkType   string
		intermediate    string
		expectedMembers []string
		expectError     bool
	}{
		{
			name:            "query without parameters",
			endpoint:        listServer.URL,
			entityType:      "",
			trustMarked:     "",
			trustMarkType:   "",
			intermediate:    "",
			expectedMembers: []string{"http://rp1.example.com", "http://op1.example.com", "http://intermediate1.example.com"},
			expectError:     false,
		},
		{
			name:            "query with entity_type filter",
			endpoint:        listServer.URL,
			entityType:      "openid_relying_party",
			trustMarked:     "",
			trustMarkType:   "",
			intermediate:    "",
			expectedMembers: []string{"http://rp1.example.com", "http://rp2.example.com"},
			expectError:     false,
		},
		{
			name:            "query with trust_marked filter",
			endpoint:        listServer.URL,
			entityType:      "",
			trustMarked:     "true",
			trustMarkType:   "test_mark",
			intermediate:    "",
			expectedMembers: []string{"http://trusted-rp.example.com"},
			expectError:     false,
		},
		{
			name:            "query with intermediate filter",
			endpoint:        listServer.URL,
			entityType:      "",
			trustMarked:     "",
			trustMarkType:   "",
			intermediate:    "true",
			expectedMembers: []string{"http://intermediate1.example.com", "http://intermediate2.example.com"},
			expectError:     false,
		},
		{
			name:            "invalid endpoint",
			endpoint:        "http://invalid-endpoint.example.com",
			entityType:      "",
			trustMarked:     "",
			trustMarkType:   "",
			intermediate:    "",
			expectedMembers: nil,
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			members, err := resolver.QueryFederationListEndpoint(ctx, tt.endpoint, tt.entityType, tt.trustMarked, tt.trustMarkType, tt.intermediate)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedMembers, members)
			}
		})
	}
}

func TestQueryFederationListEndpointInvalidResponse(t *testing.T) {
	// Create test server that returns invalid JSON
	invalidServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer invalidServer.Close()

	config := &Config{
		TrustAnchors:       []string{"http://ta.example.com"},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	}

	resolver, err := NewFederationResolver(config)
	require.NoError(t, err)

	ctx := context.Background()
	_, err = resolver.QueryFederationListEndpoint(ctx, invalidServer.URL, "", "", "", "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid character")
}

func TestQueryFederationListEndpointHTTPError(t *testing.T) {
	// Create test server that returns HTTP error
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer errorServer.Close()

	config := &Config{
		TrustAnchors:       []string{"http://ta.example.com"},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	}

	resolver, err := NewFederationResolver(config)
	require.NoError(t, err)

	ctx := context.Background()
	_, err = resolver.QueryFederationListEndpoint(ctx, errorServer.URL, "", "", "", "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestQueryFederationListEndpointJWTResponse(t *testing.T) {
	// Create test server that returns federation list as JWT
	jwtServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(http.StatusOK)

		// Create JWT with federation_list claim
		header := `{"typ":"JWT","alg":"RS256"}`
		payload := `{"iss":"http://ta.example.com","sub":"http://ta.example.com","iat":1634320000,"exp":1634323600,"federation_list":["http://rp1.example.com","http://op1.example.com","http://intermediate1.example.com"]}`
		jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
		w.Write([]byte(jwt))
	}))
	defer jwtServer.Close()

	config := &Config{
		TrustAnchors:       []string{"http://ta.example.com"},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	}

	resolver, err := NewFederationResolver(config)
	require.NoError(t, err)

	ctx := context.Background()
	members, err := resolver.QueryFederationListEndpoint(ctx, jwtServer.URL, "", "", "", "")

	assert.NoError(t, err)
	assert.Equal(t, []string{"http://rp1.example.com", "http://op1.example.com", "http://intermediate1.example.com"}, members)
}

func TestQueryFederationListEndpointJWTResponseWithFilters(t *testing.T) {
	// Create test server that returns filtered federation list as JWT
	jwtServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entityType := r.URL.Query().Get("entity_type")

		var federationList []string
		if entityType == "openid_relying_party" {
			federationList = []string{"http://rp1.example.com", "http://rp2.example.com"}
		} else {
			federationList = []string{"http://rp1.example.com", "http://op1.example.com", "http://intermediate1.example.com"}
		}

		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(http.StatusOK)

		// Create JWT with federation_list claim - properly encode the array
		header := `{"typ":"JWT","alg":"RS256"}`
		federationListJSON, _ := json.Marshal(federationList)
		payload := fmt.Sprintf(`{"iss":"http://ta.example.com","sub":"http://ta.example.com","iat":1634320000,"exp":1634323600,"federation_list":%s}`, string(federationListJSON))
		jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
		w.Write([]byte(jwt))
	}))
	defer jwtServer.Close()

	config := &Config{
		TrustAnchors:       []string{"http://ta.example.com"},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	}

	resolver, err := NewFederationResolver(config)
	require.NoError(t, err)

	ctx := context.Background()

	// Test with entity_type filter
	members, err := resolver.QueryFederationListEndpoint(ctx, jwtServer.URL, "openid_relying_party", "", "", "")
	assert.NoError(t, err)
	assert.Equal(t, []string{"http://rp1.example.com", "http://rp2.example.com"}, members)

	// Test without filter
	members, err = resolver.QueryFederationListEndpoint(ctx, jwtServer.URL, "", "", "", "")
	assert.NoError(t, err)
	assert.Equal(t, []string{"http://rp1.example.com", "http://op1.example.com", "http://intermediate1.example.com"}, members)
}

func TestParseFederationListJWT(t *testing.T) {
	config := &Config{
		TrustAnchors:       []string{"http://ta.example.com"},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	}

	resolver, err := NewFederationResolver(config)
	require.NoError(t, err)

	tests := []struct {
		name        string
		jwtStr      string
		expected    []string
		expectError bool
	}{
		{
			name: "valid JWT with federation_list",
			jwtStr: func() string {
				header := `{"typ":"JWT","alg":"RS256"}`
				payload := `{"iss":"http://ta.example.com","sub":"http://ta.example.com","iat":1634320000,"exp":1634323600,"federation_list":["http://rp1.example.com","http://op1.example.com"]}`
				return base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
			}(),
			expected:    []string{"http://rp1.example.com", "http://op1.example.com"},
			expectError: false,
		},
		{
			name: "JWT without federation_list claim",
			jwtStr: func() string {
				header := `{"typ":"JWT","alg":"RS256"}`
				payload := `{"iss":"http://ta.example.com","sub":"http://ta.example.com","iat":1634320000,"exp":1634323600}`
				return base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
			}(),
			expected:    nil,
			expectError: true,
		},
		{
			name:        "invalid JWT format",
			jwtStr:      "invalid.jwt.format",
			expected:    nil,
			expectError: true,
		},
		{
			name: "federation_list not an array",
			jwtStr: func() string {
				header := `{"typ":"JWT","alg":"RS256"}`
				payload := `{"iss":"http://ta.example.com","sub":"http://ta.example.com","iat":1634320000,"exp":1634323600,"federation_list":"not-an-array"}`
				return base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
			}(),
			expected:    nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := resolver.parseFederationListJWT(tt.jwtStr)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
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

	rpServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(http.StatusOK)
		header := `{"typ":"JWT","alg":"RS256"}`
		payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"authority_hints":["%s"]}`, intermediary1Server.URL, rpServer.URL, intermediary1Server.URL)
		jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
		w.Write([]byte(jwt))
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
	assert.Len(t, chain.Chain, 4) // RP -> Intermediary1 -> Intermediary2 -> TA
	assert.Equal(t, rpServer.URL, chain.EntityID)
	assert.Equal(t, taServer.URL, chain.TrustAnchor)

	// Verify chain order
	assert.Equal(t, rpServer.URL, chain.Chain[0].Subject)
	assert.Equal(t, intermediary1Server.URL, chain.Chain[1].Subject)
	assert.Equal(t, intermediary2Server.URL, chain.Chain[2].Subject)
	assert.Equal(t, taServer.URL, chain.Chain[3].Subject)
}

func TestResolveTrustChainIntermediaryNotConfiguredAsTA(t *testing.T) {
	// Test that chains work even when intermediaries are not configured as trust anchors
	taServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer taServer.Close()

	intermediaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer intermediaryServer.Close()

	rpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer rpServer.Close()

	// Set handlers
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

	rpServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(http.StatusOK)
		header := `{"typ":"JWT","alg":"RS256"}`
		payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"authority_hints":["%s"]}`, intermediaryServer.URL, rpServer.URL, intermediaryServer.URL)
		jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
		w.Write([]byte(jwt))
	})

	// Note: Only TA is configured as trust anchor, intermediary is NOT
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
	assert.Len(t, chain.Chain, 3) // Should still build the chain through the intermediary
	assert.Equal(t, rpServer.URL, chain.EntityID)
	assert.Equal(t, taServer.URL, chain.TrustAnchor)
}

func TestParseTrustChainJWT_Dedup(t *testing.T) {
	// Build a trust_chain JWT that contains duplicate subordinate entries for the same subject
	rp := "http://rp.example.com"
	intermediary := "http://intermediary.example.com"
	ta := "http://ta.example.com"

	header := `{"typ":"JWT","alg":"RS256"}`

	// Self-signed RP entity configuration
	rpSelfPayload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600}`, rp, rp)
	rpSelfJWT := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(rpSelfPayload)) + ".signature"

	// Subordinate statement for RP issued by intermediary
	rpSubPayload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600}`, intermediary, rp)
	rpSubJWT := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(rpSubPayload)) + ".signature"

	// TA self-signed
	taPayload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600}`, ta, ta)
	taJWT := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(taPayload)) + ".signature"

	// Top-level trust_chain JWT issued by TA containing self-signed RP, subordinate, and TA
	trustChainPayload := fmt.Sprintf(`{"iss":"%s","sub":"%s","trust_anchor":"%s","iat":1634320000,"exp":1634323600,"trust_chain":["%s","%s","%s"]}`,
		ta, rp, ta, rpSelfJWT, rpSubJWT, taJWT)
	trustChainJWT := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(trustChainPayload)) + ".signature"

	config := &Config{
		TrustAnchors:       []string{ta},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	}

	resolver, err := NewFederationResolver(config)
	require.NoError(t, err)

	// Parse the trust chain JWT and expect deduplication to leave two unique entities: RP and TA
	chain, err := resolver.parseTrustChainJWT(rp, trustChainJWT, "http://fetch", ta)
	require.NoError(t, err)

	// Expect RP and TA (duplicates removed)
	if assert.NotNil(t, chain) {
		assert.Equal(t, 2, len(chain), "expected deduped chain to contain 2 unique entities (RP and TA)")
		// First should be the self-signed RP entry
		assert.Equal(t, rp, chain[0].Subject)
		// Last should be the TA
		assert.Equal(t, ta, chain[len(chain)-1].Subject)
	}
}
