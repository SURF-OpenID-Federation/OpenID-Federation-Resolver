package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"resolver/pkg/resolver"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestMainPageServesOperationsConsole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/", mainPageHandler)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "Operations")
	require.Contains(t, w.Body.String(), "data-theme=\"dark\"")
	require.NotContains(t, w.Body.String(), "/api/v1/cache/stats")
}

func TestOpenAPIAndSwaggerAvailable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/v1/openapi.json", openAPISpecHandler)
	r.GET("/api/v1/docs", swaggerUIHandler)

	spec := httptest.NewRecorder()
	r.ServeHTTP(spec, httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil))
	require.Equal(t, http.StatusOK, spec.Code)
	require.Contains(t, spec.Body.String(), `"openapi"`)
	require.Contains(t, spec.Body.String(), "/api/v1/ops")

	docs := httptest.NewRecorder()
	r.ServeHTTP(docs, httptest.NewRequest(http.MethodGet, "/api/v1/docs", nil))
	require.Equal(t, http.StatusOK, docs.Code)
	require.Contains(t, docs.Body.String(), "swagger-ui")
}

func TestOpsSnapshotHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	testConfig := &Config{}
	testConfig.Service.Name = "test-resolver"
	testConfig.TrustAnchors = []string{"https://ta.example"}
	testConfig.Resolver.ConcurrentFetches = 10

	fed, err := resolver.NewFederationResolver(&resolver.Config{
		TrustAnchors:      testConfig.TrustAnchors,
		RequestTimeout:    2 * time.Second,
		ConcurrentFetches: 10,
	})
	require.NoError(t, err)

	originalConfig := config
	originalFed := fedResolver
	config = testConfig
	fedResolver = fed
	t.Cleanup(func() {
		config = originalConfig
		fedResolver = originalFed
	})

	r := gin.New()
	r.GET("/api/v1/ops", opsSnapshotHandler)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/ops", nil))
	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Contains(t, string(body["service"]), "test-resolver")
	require.Contains(t, string(body["metrics"]), "uptime_seconds")
	require.True(t, strings.Contains(string(body["cache"]), "entity_cache_size"))

	var registered []string
	require.NoError(t, json.Unmarshal(body["registered_trust_anchors"], &registered))
	require.Empty(t, registered)

	require.NoError(t, fed.RegisterTrustAnchor(&resolver.TrustAnchorRegistration{
		EntityID:  "https://ta.example",
		ExpiresAt: time.Now().Add(time.Hour),
	}))
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/api/v1/ops", nil))
	require.Equal(t, http.StatusOK, w2.Code)
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &body))
	require.NoError(t, json.Unmarshal(body["registered_trust_anchors"], &registered))
	require.Equal(t, []string{"https://ta.example"}, registered)
}

func TestSetupRoutesProtectsOperatorLeavesFederationOpen(t *testing.T) {
	gin.SetMode(gin.TestMode)
	origKey, origTA := apiKey, taAPIToken
	apiKey = "op-secret"
	taAPIToken = "ta-secret"
	t.Cleanup(func() {
		apiKey, taAPIToken = origKey, origTA
	})

	r := gin.New()
	setupRoutes(r)

	fed := httptest.NewRecorder()
	r.ServeHTTP(fed, httptest.NewRequest(http.MethodGet, "/api/v1/federation_list", nil))
	require.NotEqual(t, http.StatusUnauthorized, fed.Code)

	status := httptest.NewRecorder()
	r.ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/api/v1/auth/status", nil))
	require.Equal(t, http.StatusOK, status.Code)
	require.Contains(t, status.Body.String(), `"operator_required":true`)

	ops := httptest.NewRecorder()
	r.ServeHTTP(ops, httptest.NewRequest(http.MethodGet, "/api/v1/ops", nil))
	require.Equal(t, http.StatusUnauthorized, ops.Code)

	authed := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ops", nil)
	req.Header.Set("Authorization", "Bearer op-secret")
	r.ServeHTTP(authed, req)
	require.NotEqual(t, http.StatusUnauthorized, authed.Code)

	reg := httptest.NewRecorder()
	r.ServeHTTP(reg, httptest.NewRequest(http.MethodPost, "/api/v1/register-trust-anchor", nil))
	require.Equal(t, http.StatusUnauthorized, reg.Code)

	regOK := httptest.NewRecorder()
	taReq := httptest.NewRequest(http.MethodPost, "/api/v1/register-trust-anchor", nil)
	taReq.Header.Set("Authorization", "Bearer ta-secret")
	r.ServeHTTP(regOK, taReq)
	require.NotEqual(t, http.StatusUnauthorized, regOK.Code)
}
