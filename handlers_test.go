package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"resolver/pkg/resolver"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFederationListHandler(t *testing.T) {
	// Setup test servers
	var taURL string
	taServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-federation" {
			// Return TA's entity statement with federation_list_endpoint
			w.Header().Set("Content-Type", "application/jwt")
			w.WriteHeader(http.StatusOK)
			header := `{"typ":"JWT","alg":"RS256"}`
			payload := fmt.Sprintf(`{
				"iss":"%s",
				"sub":"%s",
				"iat":1634320000,
				"exp":1634323600,
				"metadata": {
					"federation_entity": {
						"federation_list_endpoint": "%s/federation_list"
					}
				}
			}`, taURL, taURL, taURL)
			jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
			w.Write([]byte(jwt))
		} else if r.URL.Path == "/federation_list" {
			// Return federation list
			entityType := r.URL.Query().Get("entity_type")
			if entityType == "openid_relying_party" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				response := `["http://rp1.example.com", "http://rp2.example.com"]`
				w.Write([]byte(response))
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				response := `["http://rp1.example.com", "http://op1.example.com", "http://intermediate1.example.com"]`
				w.Write([]byte(response))
			}
		}
	}))
	defer taServer.Close()

	taURL = taServer.URL // Set URL after server creation

	// Setup resolver config
	testConfig := &Config{
		Service: struct {
			Name     string
			Host     string
			LogLevel string
		}{
			Name: "test-resolver",
		},
		TrustAnchors: []string{taURL},
		Resolver: struct {
			MaxRetries         int
			RequestTimeout     time.Duration
			ValidateSignatures bool
			AllowSelfSigned    bool
			ConcurrentFetches  int
			SkipTLSVerify      bool
		}{
			MaxRetries:         3,
			RequestTimeout:     5 * time.Second,
			ValidateSignatures: false,
			AllowSelfSigned:    true,
			ConcurrentFetches:  10,
			SkipTLSVerify:      false,
		},
	}

	var err error
	testFedResolver, err := resolver.NewFederationResolver(&resolver.Config{
		TrustAnchors:       testConfig.TrustAnchors,
		RequestTimeout:     testConfig.Resolver.RequestTimeout,
		ValidateSignatures: testConfig.Resolver.ValidateSignatures,
		AllowSelfSigned:    testConfig.Resolver.AllowSelfSigned,
		ConcurrentFetches:  testConfig.Resolver.ConcurrentFetches,
		SkipTLSVerify:      testConfig.Resolver.SkipTLSVerify,
	})
	require.NoError(t, err)

	// Temporarily set global variables for test
	originalConfig := config
	originalFedResolver := fedResolver
	config = testConfig
	fedResolver = testFedResolver
	defer func() {
		config = originalConfig
		fedResolver = originalFedResolver
	}()

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/federation_list", federationListHandler)

	tests := []struct {
		name           string
		queryParams    string
		expectedStatus int
		checkResponse  func(t *testing.T, body string)
	}{
		{
			name:           "successful federation list request",
			queryParams:    "trust_anchor=" + url.QueryEscape(taURL),
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"iss":"`+taURL+`"`)
				assert.Contains(t, body, `"sub":"`+taURL+`"`)
				assert.Contains(t, body, `"federation_list"`)
				assert.Contains(t, body, `"federation_list_endpoint":true`)
				assert.Contains(t, body, "http://rp1.example.com")
				assert.Contains(t, body, "http://op1.example.com")
			},
		},
		{
			name:           "federation list with entity_type filter",
			queryParams:    "trust_anchor=" + url.QueryEscape(taURL) + "&entity_type=openid_relying_party",
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"iss":"`+taURL+`"`)
				assert.Contains(t, body, `"sub":"`+taURL+`"`)
				assert.Contains(t, body, `"federation_list"`)
				assert.Contains(t, body, "http://rp1.example.com")
				assert.Contains(t, body, "http://rp2.example.com")
				// Should not contain other entity types
				assert.NotContains(t, body, "http://op1.example.com")
			},
		},
		{
			name:           "missing trust_anchor parameter",
			queryParams:    "",
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "Missing required parameter 'trust_anchor'")
			},
		},
		{
			name:           "unauthorized trust anchor",
			queryParams:    "trust_anchor=" + url.QueryEscape("http://unauthorized.example.com"),
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "The Trust Anchor cannot be found or used")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req, err := http.NewRequest("GET", "/federation_list?"+tt.queryParams, nil)
			require.NoError(t, err)

			// Create response recorder
			w := httptest.NewRecorder()

			// Create Gin context
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			// Call handler
			federationListHandler(c)

			// Check status
			assert.Equal(t, tt.expectedStatus, w.Code)

			// Check response body
			body := w.Body.String()
			tt.checkResponse(t, body)
		})
	}
}

func TestFederationListHandlerTrustAnchorWithoutListEndpoint(t *testing.T) {
	// Setup test server for TA without federation_list_endpoint
	var taURL string
	taServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-federation" {
			// Return TA's entity statement WITHOUT federation_list_endpoint
			w.Header().Set("Content-Type", "application/jwt")
			w.WriteHeader(http.StatusOK)
			header := `{"typ":"JWT","alg":"RS256"}`
			payload := fmt.Sprintf(`{
				"iss":"%s",
				"sub":"%s",
				"iat":1634320000,
				"exp":1634323600,
				"metadata": {
					"federation_entity": {}
				}
			}`, taURL, taURL)
			jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
			w.Write([]byte(jwt))
		}
	}))
	defer taServer.Close()

	taURL = taServer.URL // Set URL after server creation

	// Setup resolver config
	testConfig := &Config{
		Service: struct {
			Name     string
			Host     string
			LogLevel string
		}{
			Name: "test-resolver",
		},
		TrustAnchors: []string{taURL},
		Resolver: struct {
			MaxRetries         int
			RequestTimeout     time.Duration
			ValidateSignatures bool
			AllowSelfSigned    bool
			ConcurrentFetches  int
			SkipTLSVerify      bool
		}{
			MaxRetries:         3,
			RequestTimeout:     5 * time.Second,
			ValidateSignatures: false,
			AllowSelfSigned:    true,
			ConcurrentFetches:  10,
			SkipTLSVerify:      false,
		},
	}

	var err error
	testFedResolver, err := resolver.NewFederationResolver(&resolver.Config{
		TrustAnchors:       testConfig.TrustAnchors,
		RequestTimeout:     testConfig.Resolver.RequestTimeout,
		ValidateSignatures: testConfig.Resolver.ValidateSignatures,
		AllowSelfSigned:    testConfig.Resolver.AllowSelfSigned,
		ConcurrentFetches:  testConfig.Resolver.ConcurrentFetches,
		SkipTLSVerify:      testConfig.Resolver.SkipTLSVerify,
	})
	require.NoError(t, err)

	// Temporarily set global variables for test
	originalConfig := config
	originalFedResolver := fedResolver
	config = testConfig
	fedResolver = testFedResolver
	defer func() {
		config = originalConfig
		fedResolver = originalFedResolver
	}()

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/federation_list", federationListHandler)

	// Create request
	req, err := http.NewRequest("GET", "/federation_list?trust_anchor="+url.QueryEscape(taURL), nil)
	require.NoError(t, err)

	// Create response recorder
	w := httptest.NewRecorder()

	// Create Gin context
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Call handler
	federationListHandler(c)

	// Check status
	assert.Equal(t, http.StatusOK, w.Code)

	// Check response body - should return empty list with federation_list_endpoint: false
	body := w.Body.String()
	assert.Contains(t, body, `"iss":"`+taURL+`"`)
	assert.Contains(t, body, `"sub":"`+taURL+`"`)
	assert.Contains(t, body, `"federation_list":[]`)
	assert.Contains(t, body, `"federation_list_endpoint":false`)
}

func TestFederationListHandlerInvalidTrustAnchorURL(t *testing.T) {
	// Setup resolver config
	testConfig := &Config{
		Service: struct {
			Name     string
			Host     string
			LogLevel string
		}{
			Name: "test-resolver",
		},
		TrustAnchors: []string{"http://ta.example.com"},
		Resolver: struct {
			MaxRetries         int
			RequestTimeout     time.Duration
			ValidateSignatures bool
			AllowSelfSigned    bool
			ConcurrentFetches  int
			SkipTLSVerify      bool
		}{
			MaxRetries:         3,
			RequestTimeout:     5 * time.Second,
			ValidateSignatures: false,
			AllowSelfSigned:    true,
			ConcurrentFetches:  10,
			SkipTLSVerify:      false,
		},
	}

	var err error
	testFedResolver, err := resolver.NewFederationResolver(&resolver.Config{
		TrustAnchors:       testConfig.TrustAnchors,
		RequestTimeout:     testConfig.Resolver.RequestTimeout,
		ValidateSignatures: testConfig.Resolver.ValidateSignatures,
		AllowSelfSigned:    testConfig.Resolver.AllowSelfSigned,
		ConcurrentFetches:  testConfig.Resolver.ConcurrentFetches,
		SkipTLSVerify:      testConfig.Resolver.SkipTLSVerify,
	})
	require.NoError(t, err)

	// Temporarily set global variables for test
	originalConfig := config
	originalFedResolver := fedResolver
	config = testConfig
	fedResolver = testFedResolver
	defer func() {
		config = originalConfig
		fedResolver = originalFedResolver
	}()

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/federation_list", federationListHandler)

	// Test with invalid URL
	req, err := http.NewRequest("GET", "/federation_list?trust_anchor=http://%25", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	federationListHandler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "Invalid trust anchor")
}

func TestFederationListHandlerWithOptionalParameters(t *testing.T) {
	// Setup test servers
	var taURL string
	taServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-federation" {
			// Return TA's entity statement with federation_list_endpoint
			w.Header().Set("Content-Type", "application/jwt")
			w.WriteHeader(http.StatusOK)
			header := `{"typ":"JWT","alg":"RS256"}`
			payload := fmt.Sprintf(`{
				"iss":"%s",
				"sub":"%s",
				"iat":1634320000,
				"exp":1634323600,
				"metadata": {
					"federation_entity": {
						"federation_list_endpoint": "%s/federation_list"
					}
				}
			}`, taURL, taURL, taURL)
			jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
			w.Write([]byte(jwt))
		} else if r.URL.Path == "/federation_list" {
			// Check that optional parameters are passed through
			entityType := r.URL.Query().Get("entity_type")
			trustMarked := r.URL.Query().Get("trust_marked")
			trustMarkType := r.URL.Query().Get("trust_mark_type")
			intermediate := r.URL.Query().Get("intermediate")

			// Return response indicating parameters were received
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			response := fmt.Sprintf(`["params_received:entity_type=%s,trust_marked=%s,trust_mark_type=%s,intermediate=%s"]`,
				entityType, trustMarked, trustMarkType, intermediate)
			w.Write([]byte(response))
		}
	}))
	defer taServer.Close()

	taURL = taServer.URL // Set URL after server creation

	// Setup resolver config
	testConfig := &Config{
		Service: struct {
			Name     string
			Host     string
			LogLevel string
		}{
			Name: "test-resolver",
		},
		TrustAnchors: []string{taURL},
		Resolver: struct {
			MaxRetries         int
			RequestTimeout     time.Duration
			ValidateSignatures bool
			AllowSelfSigned    bool
			ConcurrentFetches  int
			SkipTLSVerify      bool
		}{
			MaxRetries:         3,
			RequestTimeout:     5 * time.Second,
			ValidateSignatures: false,
			AllowSelfSigned:    true,
			ConcurrentFetches:  10,
			SkipTLSVerify:      false,
		},
	}

	var err error
	testFedResolver, err := resolver.NewFederationResolver(&resolver.Config{
		TrustAnchors:       testConfig.TrustAnchors,
		RequestTimeout:     testConfig.Resolver.RequestTimeout,
		ValidateSignatures: testConfig.Resolver.ValidateSignatures,
		AllowSelfSigned:    testConfig.Resolver.AllowSelfSigned,
		ConcurrentFetches:  testConfig.Resolver.ConcurrentFetches,
		SkipTLSVerify:      testConfig.Resolver.SkipTLSVerify,
	})
	require.NoError(t, err)

	// Temporarily set global variables for test
	originalConfig := config
	originalFedResolver := fedResolver
	config = testConfig
	fedResolver = testFedResolver
	defer func() {
		config = originalConfig
		fedResolver = originalFedResolver
	}()

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/federation_list", federationListHandler)

	// Test with all optional parameters
	params := "trust_anchor=" + url.QueryEscape(taURL) +
		"&entity_type=openid_relying_party" +
		"&trust_marked=true" +
		"&trust_mark_type=test_mark" +
		"&intermediate=false"

	req, err := http.NewRequest("GET", "/federation_list?"+params, nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	federationListHandler(c)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "params_received:entity_type=openid_relying_party")
	assert.Contains(t, body, "trust_marked=true")
	assert.Contains(t, body, "trust_mark_type=test_mark")
	assert.Contains(t, body, "intermediate=false")
}
