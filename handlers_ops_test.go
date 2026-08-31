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
	require.Contains(t, w.Body.String(), "OIDF")
	require.Contains(t, w.Body.String(), "Resolver")
	require.Contains(t, w.Body.String(), "Operations")
	require.Contains(t, w.Body.String(), "data-theme=\"dark\"")
	require.NotContains(t, w.Body.String(), "/api/v1/cache/stats")
}

func TestAdminPageServesAdminUI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/admin", adminPageHandler)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin", nil))
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "Federation Admin")
	require.Contains(t, w.Body.String(), "/admin/v1/configuration")
	require.Contains(t, w.Body.String(), "/static/admin/admin.css")
	require.NotContains(t, w.Body.String(), "data-theme=\"dark\"")
}

func TestAdminPageRedirectsWhenOIDCConfigured(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("ADMIN_AUTH_ISSUER", "https://idp.example.com")
	t.Setenv("ADMIN_AUTH_CLIENT_ID", "resolver-admin")
	t.Setenv("ADMIN_AUTH_LOGIN_URL", "")

	r := gin.New()
	registerAdminUI(r)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Accept", "text/html")
	req.Host = "resolver.example.com"
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusFound, w.Code)
	require.Contains(t, w.Header().Get("Location"), "/admin/login")
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
	require.Contains(t, spec.Body.String(), "/admin/v1")
	require.Contains(t, spec.Body.String(), "/admin/v1/tokens")
	require.NotContains(t, spec.Body.String(), `"/api/v1/keys"`)
	require.NotContains(t, spec.Body.String(), `"/api/v1/tokens"`)
	require.NotContains(t, spec.Body.String(), `"/api/v1/config":`)

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
	require.Contains(t, body, "entity_id")

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
	require.Contains(t, w2.Body.String(), `"signing"`)
}

func TestLegacyConfigAndTokenRoutesRemoved(t *testing.T) {
	gin.SetMode(gin.TestMode)
	origKey := apiKey
	apiKey = ""
	t.Cleanup(func() { apiKey = origKey })

	r := gin.New()
	setupRoutes(r)

	list := httptest.NewRecorder()
	r.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil))
	require.Equal(t, http.StatusNotFound, list.Code)

	rot := httptest.NewRecorder()
	r.ServeHTTP(rot, httptest.NewRequest(http.MethodPost, "/api/v1/keys/rotate", nil))
	require.Equal(t, http.StatusNotFound, rot.Code)

	cfgGet := httptest.NewRecorder()
	r.ServeHTTP(cfgGet, httptest.NewRequest(http.MethodGet, "/api/v1/config", nil))
	require.Equal(t, http.StatusNotFound, cfgGet.Code)

	cfgPost := httptest.NewRecorder()
	r.ServeHTTP(cfgPost, httptest.NewRequest(http.MethodPost, "/api/v1/config", nil))
	require.Equal(t, http.StatusNotFound, cfgPost.Code)

	tok := httptest.NewRecorder()
	r.ServeHTTP(tok, httptest.NewRequest(http.MethodGet, "/api/v1/tokens", nil))
	require.Equal(t, http.StatusNotFound, tok.Code)

	who := httptest.NewRecorder()
	r.ServeHTTP(who, httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil))
	require.Equal(t, http.StatusNotFound, who.Code)
}

func TestSetupRoutesProtectsMutationsLeavesGetsOpen(t *testing.T) {
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
	require.Contains(t, status.Body.String(), `"ta_admin_required":true`)

	verify := httptest.NewRecorder()
	r.ServeHTTP(verify, httptest.NewRequest(http.MethodGet, "/api/v1/auth/verify", nil))
	require.Equal(t, http.StatusUnauthorized, verify.Code)

	verifyOK := httptest.NewRecorder()
	vReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/verify", nil)
	vReq.Header.Set("X-API-Key", "op-secret")
	r.ServeHTTP(verifyOK, vReq)
	require.Equal(t, http.StatusOK, verifyOK.Code)
	require.Contains(t, verifyOK.Body.String(), `"ok":true`)

	ops := httptest.NewRecorder()
	r.ServeHTTP(ops, httptest.NewRequest(http.MethodGet, "/api/v1/ops", nil))
	require.NotEqual(t, http.StatusUnauthorized, ops.Code)

	clear := httptest.NewRecorder()
	r.ServeHTTP(clear, httptest.NewRequest(http.MethodPost, "/admin/v1/cache/clear-all", nil))
	require.Equal(t, http.StatusUnauthorized, clear.Code)

	clearWrong := httptest.NewRecorder()
	wrongReq := httptest.NewRequest(http.MethodPost, "/admin/v1/cache/clear-all", nil)
	wrongReq.Header.Set("Authorization", "Bearer ta-secret")
	r.ServeHTTP(clearWrong, wrongReq)
	require.Equal(t, http.StatusUnauthorized, clearWrong.Code)

	adminKeys := httptest.NewRecorder()
	r.ServeHTTP(adminKeys, httptest.NewRequest(http.MethodPost, "/admin/v1/keys", nil))
	require.Equal(t, http.StatusUnauthorized, adminKeys.Code)

	reg := httptest.NewRecorder()
	r.ServeHTTP(reg, httptest.NewRequest(http.MethodPost, "/api/v1/register-trust-anchor", nil))
	require.Equal(t, http.StatusUnauthorized, reg.Code)

	regWithAPIKey := httptest.NewRecorder()
	opReq := httptest.NewRequest(http.MethodPost, "/api/v1/register-trust-anchor", nil)
	opReq.Header.Set("Authorization", "Bearer op-secret")
	r.ServeHTTP(regWithAPIKey, opReq)
	require.Equal(t, http.StatusUnauthorized, regWithAPIKey.Code)

	regOK := httptest.NewRecorder()
	taReq := httptest.NewRequest(http.MethodPost, "/api/v1/register-trust-anchor", nil)
	taReq.Header.Set("Authorization", "Bearer ta-secret")
	r.ServeHTTP(regOK, taReq)
	require.NotEqual(t, http.StatusUnauthorized, regOK.Code)
}
