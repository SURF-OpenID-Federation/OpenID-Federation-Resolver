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

// TestResolveEntity copied from resolver_test.go
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

// ExtractFederationListEndpoint and query tests follow (copied)
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
