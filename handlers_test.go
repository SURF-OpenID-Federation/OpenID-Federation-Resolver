package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			w.WriteHeader(http.StatusOK)
			header := `{"typ":"entity-statement+jwt","alg":"RS256"}`
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
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			w.WriteHeader(http.StatusOK)
			header := `{"typ":"entity-statement+jwt","alg":"RS256"}`
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

func TestFederationCollectionHandler(t *testing.T) {
	var taURL string
	makeStatement := func(entityID, entityType string, extra map[string]interface{}) string {
		header := `{"typ":"entity-statement+jwt","alg":"RS256"}`
		metadata := map[string]interface{}{}
		if entityType != "" {
			metadata[entityType] = map[string]interface{}{}
			if extra != nil {
				for k, v := range extra {
					metadata[entityType].(map[string]interface{})[k] = v
				}
			}
		}
		payloadMap := map[string]interface{}{
			"iss":      entityID,
			"sub":      entityID,
			"iat":      1634320000,
			"exp":      1634323600,
			"metadata": metadata,
		}
		payload, _ := json.Marshal(payloadMap)
		jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
		return jwt
	}

	taServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-federation":
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			w.WriteHeader(http.StatusOK)
			payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"metadata":{"federation_entity":{"federation_list_endpoint":"%s/federation_list"}}}`, taURL, taURL, taURL)
			jwt := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"entity-statement+jwt","alg":"RS256"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
			_, _ = w.Write([]byte(jwt))
		case "/federation_list":
			entityType := r.URL.Query().Get("entity_type")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if entityType == "openid_provider" {
				_, _ = w.Write([]byte(fmt.Sprintf(`["%s/op1","%s/op2"]`, taURL, taURL)))
				return
			}
			if entityType == "openid_relying_party" {
				_, _ = w.Write([]byte(fmt.Sprintf(`["%s/rp1"]`, taURL)))
				return
			}
			// No filter - return all entities
			_, _ = w.Write([]byte(fmt.Sprintf(`["%s/op1","%s/op2","%s/rp1"]`, taURL, taURL, taURL)))
		case "/resolve":
			sub := r.URL.Query().Get("sub")
			w.Header().Set("Content-Type", "application/jwt")
			w.WriteHeader(http.StatusOK)
			if strings.HasSuffix(sub, "/op1") {
				stmt := makeStatement(sub, "openid_provider", map[string]interface{}{"display_name": "OP One", "logo_uri": "https://op1.example/logo.png"})
				_, _ = w.Write([]byte(stmt))
				return
			}
			if strings.HasSuffix(sub, "/op2") {
				stmt := makeStatement(sub, "openid_provider", map[string]interface{}{"display_name": "OP Two"})
				_, _ = w.Write([]byte(stmt))
				return
			}
			stmt := makeStatement(sub, "openid_relying_party", map[string]interface{}{"display_name": "RP One"})
			_, _ = w.Write([]byte(stmt))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer taServer.Close()

	taURL = taServer.URL

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
			MaxRetries:         1,
			RequestTimeout:     5 * time.Second,
			ValidateSignatures: false,
			AllowSelfSigned:    true,
			ConcurrentFetches:  10,
			SkipTLSVerify:      false,
		},
	}

	testFedResolver, err := resolver.NewFederationResolver(&resolver.Config{
		TrustAnchors:       testConfig.TrustAnchors,
		RequestTimeout:     testConfig.Resolver.RequestTimeout,
		ValidateSignatures: testConfig.Resolver.ValidateSignatures,
		AllowSelfSigned:    testConfig.Resolver.AllowSelfSigned,
		ConcurrentFetches:  testConfig.Resolver.ConcurrentFetches,
		SkipTLSVerify:      testConfig.Resolver.SkipTLSVerify,
	})
	require.NoError(t, err)

	originalConfig := config
	originalFedResolver := fedResolver
	config = testConfig
	fedResolver = testFedResolver
	defer func() {
		config = originalConfig
		fedResolver = originalFedResolver
	}()

	gin.SetMode(gin.TestMode)

	t.Run("filters entities and returns pagination", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/collection?trust_anchor="+url.QueryEscape(taURL)+"&entity_type=openid_provider&limit=1", nil)
		require.NoError(t, err)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		federationCollectionHandler(c)

		require.Equal(t, http.StatusOK, w.Code)
		var response struct {
			Entities     []map[string]interface{} `json:"entities"`
			NextEntityID string                   `json:"next_entity_id"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		require.Len(t, response.Entities, 1)
		assert.NotEmpty(t, response.NextEntityID)
		assert.Equal(t, taURL+"/op1", response.Entities[0]["entity_id"])
	})

	t.Run("defaults trust anchor when single configured", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/collection?entity_type=openid_provider", nil)
		require.NoError(t, err)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		federationCollectionHandler(c)

		require.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("unsupported parameters", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/collection?trust_anchor="+url.QueryEscape(taURL)+"&trust_mark_type=https%3A%2F%2Fexample.com%2Ftm", nil)
		require.NoError(t, err)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		federationCollectionHandler(c)

		require.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "unsupported_parameter")
	})

	t.Run("collects all entities without type filter", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/collection?trust_anchor="+url.QueryEscape(taURL), nil)
		require.NoError(t, err)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		federationCollectionHandler(c)

		require.Equal(t, http.StatusOK, w.Code)
		var response struct {
			Entities    []map[string]interface{} `json:"entities"`
			LastUpdated int64                    `json:"last_updated"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		require.Len(t, response.Entities, 3) // op1, op2, rp1

		// Check that we have both entity types
		entityTypes := make(map[string]bool)
		for _, entity := range response.Entities {
			types, ok := entity["entity_types"].([]interface{})
			require.True(t, ok)
			for _, et := range types {
				entityTypes[et.(string)] = true
			}
		}
		assert.True(t, entityTypes["openid_provider"])
		assert.True(t, entityTypes["openid_relying_party"])
		assert.True(t, response.LastUpdated > 0)
	})

	t.Run("collects entities of specific type", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/collection?trust_anchor="+url.QueryEscape(taURL)+"&entity_type=openid_relying_party", nil)
		require.NoError(t, err)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		federationCollectionHandler(c)

		require.Equal(t, http.StatusOK, w.Code)
		var response struct {
			Entities []map[string]interface{} `json:"entities"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		require.Len(t, response.Entities, 1)

		entity := response.Entities[0]
		assert.Equal(t, taURL+"/rp1", entity["entity_id"])
		types, ok := entity["entity_types"].([]interface{})
		require.True(t, ok)
		assert.Contains(t, types, "openid_relying_party")
	})

	t.Run("returns empty list when no entities match filter", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/collection?trust_anchor="+url.QueryEscape(taURL)+"&entity_type=trust_mark_issuer", nil)
		require.NoError(t, err)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		federationCollectionHandler(c)

		require.Equal(t, http.StatusOK, w.Code)
		var response struct {
			Entities []map[string]interface{} `json:"entities"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Len(t, response.Entities, 0)
	})

	t.Run("paginates with from_entity_id", func(t *testing.T) {
		// First get all entities to know the order
		req, err := http.NewRequest("GET", "/collection?trust_anchor="+url.QueryEscape(taURL), nil)
		require.NoError(t, err)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		federationCollectionHandler(c)
		require.Equal(t, http.StatusOK, w.Code)

		var allResponse struct {
			Entities []map[string]interface{} `json:"entities"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &allResponse))
		require.True(t, len(allResponse.Entities) >= 2)

		// Use the first entity's ID as from_entity_id
		firstEntityID := allResponse.Entities[0]["entity_id"].(string)
		req, err = http.NewRequest("GET", "/collection?trust_anchor="+url.QueryEscape(taURL)+"&from_entity_id="+url.QueryEscape(firstEntityID), nil)
		require.NoError(t, err)
		w = httptest.NewRecorder()
		c, _ = gin.CreateTestContext(w)
		c.Request = req

		federationCollectionHandler(c)
		require.Equal(t, http.StatusOK, w.Code)

		var paginatedResponse struct {
			Entities []map[string]interface{} `json:"entities"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &paginatedResponse))

		// Should get all entities except the first one
		assert.Len(t, paginatedResponse.Entities, len(allResponse.Entities)-1)
		// First entity in paginated response should not be the from_entity_id
		assert.NotEqual(t, firstEntityID, paginatedResponse.Entities[0]["entity_id"])
	})

	t.Run("includes UI metadata when available", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/collection?trust_anchor="+url.QueryEscape(taURL)+"&entity_type=openid_provider", nil)
		require.NoError(t, err)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		federationCollectionHandler(c)

		require.Equal(t, http.StatusOK, w.Code)
		var response struct {
			Entities []map[string]interface{} `json:"entities"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		require.True(t, len(response.Entities) >= 1)

		// Check that UI info is included for entities that have it
		for _, entity := range response.Entities {
			if entity["entity_id"] == taURL+"/op1" {
				uiInfos, ok := entity["ui_infos"].(map[string]interface{})
				require.True(t, ok)
				opUI, ok := uiInfos["openid_provider"].(map[string]interface{})
				require.True(t, ok)
				assert.Equal(t, "OP One", opUI["display_name"])
				assert.Equal(t, "https://op1.example/logo.png", opUI["logo_uri"])
			}
		}
	})

	t.Run("handles trust anchor without list endpoint", func(t *testing.T) {
		// Create a separate test server without federation_list_endpoint
		taServerNoList := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/openid-federation" {
				w.Header().Set("Content-Type", "application/entity-statement+jwt")
				w.WriteHeader(http.StatusOK)
				payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"metadata":{"federation_entity":{}}}`, r.Host, r.Host)
				jwt := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"entity-statement+jwt","alg":"RS256"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
				_, _ = w.Write([]byte(jwt))
			}
		}))
		defer taServerNoList.Close()

		// Temporarily add this server to the configured trust anchors
		originalConfig := config
		config.TrustAnchors = append(config.TrustAnchors, taServerNoList.URL)
		defer func() { config = originalConfig }()

		req, err := http.NewRequest("GET", "/collection?trust_anchor="+url.QueryEscape(taServerNoList.URL), nil)
		require.NoError(t, err)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		federationCollectionHandler(c)

		require.Equal(t, http.StatusOK, w.Code)
		var response struct {
			Entities []map[string]interface{} `json:"entities"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Len(t, response.Entities, 0)
	})

	t.Run("rejects invalid trust anchor", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/collection?trust_anchor="+url.QueryEscape("http://invalid.example.com"), nil)
		require.NoError(t, err)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		federationCollectionHandler(c)

		require.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), "invalid_trust_anchor")
	})

	t.Run("requires trust anchor parameter when multiple configured", func(t *testing.T) {
		// Temporarily add another trust anchor to config
		originalConfig := config
		config.TrustAnchors = append(config.TrustAnchors, "http://another.example.com")
		defer func() { config = originalConfig }()

		req, err := http.NewRequest("GET", "/collection", nil)
		require.NoError(t, err)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		federationCollectionHandler(c)

		require.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "invalid_request")
		assert.Contains(t, w.Body.String(), "trust_anchor")
	})
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
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			w.WriteHeader(http.StatusOK)
			header := `{"typ":"entity-statement+jwt","alg":"RS256"}`
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

func TestResolveTrustChainHandler_ReturnsCompactJWTWithStatementAndContentType(t *testing.T) {
	// Setup TA server that returns its own entity-statement and a leaf statement
	var taURL string
	leafID := "https://leaf.example"
	taServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-federation":
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			w.WriteHeader(http.StatusOK)
			header := `{"typ":"entity-statement+jwt","alg":"RS256"}`
			payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":%d,"exp":%d,"metadata": {"federation_entity": {"federation_resolve_endpoint": "%s/resolve"}}, "jwks": {"keys": []}}`, taURL, taURL, 1634320000, 1634323600, taURL)
			jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
			w.Write([]byte(jwt))
		case "/resolve":
			// Return leaf entity-statement (compact JWT)
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			w.WriteHeader(http.StatusOK)
			h := `{"typ":"entity-statement+jwt","alg":"RS256"}`
			p := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":%d,"exp":%d,"metadata": {"openid_provider": {"issuer":"%s"}}, "jwks": {"keys": []}}`, taURL, leafID, 1634320000, 1634323600, leafID)
			j := base64.RawURLEncoding.EncodeToString([]byte(h)) + "." + base64.RawURLEncoding.EncodeToString([]byte(p)) + ".signature"
			w.Write([]byte(j))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer taServer.Close()
	taURL = taServer.URL

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

	testFedResolver, err := resolver.NewFederationResolver(&resolver.Config{
		TrustAnchors:       testConfig.TrustAnchors,
		RequestTimeout:     testConfig.Resolver.RequestTimeout,
		ValidateSignatures: testConfig.Resolver.ValidateSignatures,
		AllowSelfSigned:    testConfig.Resolver.AllowSelfSigned,
		ConcurrentFetches:  testConfig.Resolver.ConcurrentFetches,
		SkipTLSVerify:      testConfig.Resolver.SkipTLSVerify,
	})
	require.NoError(t, err)

	// Prepare resolver to be able to sign responses for the TA
	require.NoError(t, testFedResolver.InitializeResolverKeys())
	reg := &resolver.TrustAnchorRegistration{EntityID: taURL, ExpiresAt: time.Now().Add(1 * time.Hour)}
	require.NoError(t, testFedResolver.RegisterTrustAnchor(reg))

	// Temporarily set globals
	originalConfig := config
	originalFedResolver := fedResolver
	config = testConfig
	fedResolver = testFedResolver
	defer func() {
		config = originalConfig
		fedResolver = originalFedResolver
	}()

	// Mount handler and call it
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/v1/trust-chain/*entityId", resolveTrustChainHandler)

	req, err := http.NewRequest("GET", "/api/v1/trust-chain/"+url.QueryEscape(leafID)+"?trust_anchor="+url.QueryEscape(taURL), nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	// populate the wildcard route param so handler sees the entityId
	c.Params = gin.Params{{Key: "entityId", Value: leafID}}

	resolveTrustChainHandler(c)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)
	// handler should return a compact JWT with matching media type
	assert.Equal(t, "application/resolve-response+jwt", w.Header().Get("Content-Type"))

	body := strings.TrimSpace(w.Body.String())
	parts := strings.Split(body, ".")
	if len(parts) != 3 {
		t.Fatalf("expected compact JWT from resolver, got: %s", body)
	}

	// header typ must be resolve-response+jwt
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	assert.Contains(t, string(headerBytes), `"typ":"resolve-response+jwt"`)

	// payload must contain metadata.statement (inner entity-statement)
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	if !strings.Contains(string(payloadBytes), "metadata") || !strings.Contains(string(payloadBytes), "statement") {
		t.Fatalf("expected metadata.statement in resolver payload, got: %s", string(payloadBytes))
	}

	// extract metadata.statement and ensure it's a JWT
	// quick parse: look for "statement":"<jwt>"
	if !strings.Contains(string(payloadBytes), "statement\":\"") {
		// acceptable if metadata.statement is nested elsewhere; at minimum ensure trust_chain exists
		if !strings.Contains(string(payloadBytes), "trust_chain") {
			t.Fatalf("resolver payload missing trust_chain or metadata.statement: %s", string(payloadBytes))
		}
	}
}
