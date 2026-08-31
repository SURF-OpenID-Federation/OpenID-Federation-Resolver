package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"resolver/pkg/admin"
	"resolver/pkg/adminaudit"
	"resolver/pkg/resolver"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

const adminTestKey = "admin-v1-test-key"

func testAdminRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	dir := t.TempDir()
	origAPI, origCfg, origFed, origStore := apiKey, config, fedResolver, adminStore
	apiKey = adminTestKey
	config = &Config{DataPath: dir, TrustAnchors: []string{"https://ta.example"}}
	config.Service.Name = "Federation Resolver"
	adminStore = nil

	fed, err := resolver.NewFederationResolver(&resolver.Config{
		RequestTimeout:   2 * time.Second,
		ResolverEntityID: "https://resolver.example.org",
		OrganizationName: "Federation Resolver",
		TrustAnchors:     []string{"https://ta.example"},
		EnableSigning:    true,
	})
	require.NoError(t, err)
	require.NoError(t, fed.InitializeResolverKeys())
	fedResolver = fed

	t.Setenv("RESOLVER_ENTITY_ID", "https://resolver.example.org")
	t.Setenv("SERVICE_NAME", "Federation Resolver")

	t.Cleanup(func() {
		apiKey, config, fedResolver, adminStore = origAPI, origCfg, origFed, origStore
		adminaudit.SetForTest(nil)
	})

	r := gin.New()
	registerAdmin(r)
	return r
}

func adminDo(t *testing.T, r http.Handler, method, path, key string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestAdminNodeClassifiesAsDraftResolver(t *testing.T) {
	r := testAdminRouter(t)

	w := adminDo(t, r, http.MethodGet, "/admin/v1", "", nil)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, w.Header().Get("Content-Type"), "application/problem+json")
	require.Contains(t, w.Body.String(), "unauthorized")

	w = adminDo(t, r, http.MethodGet, "/admin/v1", adminTestKey, nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	kind, doc := admin.ClassifyResponse(w.Code, w.Body.Bytes())
	require.Equal(t, admin.SpecID, kind)
	require.NotNil(t, doc)
	require.Equal(t, admin.Spec, doc.Spec)
	require.Equal(t, admin.DefaultBase, doc.Base)
	require.Equal(t, []string{admin.ResolverRole}, doc.Roles)
	require.Equal(t, "https://resolver.example.org", doc.EntityID)
	require.Contains(t, doc.Capabilities, "keys")
	require.Contains(t, doc.Capabilities, "configuration")
	require.Contains(t, doc.Capabilities, "audit")
	_, hasSubs := doc.Capabilities["subordinates"]
	require.False(t, hasSubs)
	_, hasTM := doc.Capabilities["trust_marks"]
	require.False(t, hasTM)
}

func TestAdminUnsupportedResources(t *testing.T) {
	r := testAdminRouter(t)
	for _, path := range []string{"/admin/v1/subordinates", "/admin/v1/trust-marks"} {
		w := adminDo(t, r, http.MethodGet, path, adminTestKey, nil)
		require.Equal(t, http.StatusNotFound, w.Code, path)
		require.Contains(t, w.Body.String(), "unsupported_resource")
	}
}

func TestAdminConfigurationETagAndStatement(t *testing.T) {
	r := testAdminRouter(t)

	w := adminDo(t, r, http.MethodGet, "/admin/v1/configuration", adminTestKey, nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	etag := w.Header().Get("ETag")
	require.NotEmpty(t, etag)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))
	require.Equal(t, "https://resolver.example.org", doc["entity_id"])

	bad := httptest.NewRequest(http.MethodPut, "/admin/v1/configuration", strings.NewReader(`{"entity_id":"https://evil.example"}`))
	bad.Header.Set("X-API-Key", adminTestKey)
	bad.Header.Set("Content-Type", "application/json")
	bad.Header.Set("If-Match", etag)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, bad)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())

	put := httptest.NewRequest(http.MethodPut, "/admin/v1/configuration", strings.NewReader(`{
		"entity_id":"https://resolver.example.org",
		"lifetime":3600,
		"authority_hints":["https://ta.example"],
		"trust_anchor_hints":["https://ta.example"],
		"metadata":{"federation_entity":{"organization_name":"Admin Overlay Org","federation_resolve_endpoint":"https://resolver.example.org/api/v1/resolve"}}
	}`))
	put.Header.Set("X-API-Key", adminTestKey)
	put.Header.Set("Content-Type", "application/json")
	put.Header.Set("If-Match", etag)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, put)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	w = adminDo(t, r, http.MethodGet, "/admin/v1/configuration/statement", adminTestKey, nil)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Header().Get("Content-Type"), "application/entity-statement+jwt")
	claims := decodeAdminJWTPayload(t, w.Body.String())
	md := claims["metadata"].(map[string]any)
	fed := md["federation_entity"].(map[string]any)
	require.Equal(t, "Admin Overlay Org", fed["organization_name"])
	require.Equal(t, []any{"https://ta.example"}, claims["authority_hints"])
}

func TestAdminKeysListRotateDelete(t *testing.T) {
	r := testAdminRouter(t)

	w := adminDo(t, r, http.MethodGet, "/admin/v1/keys", adminTestKey, nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var page struct {
		Items []admin.KeyDocument `json:"items"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
	require.NotEmpty(t, page.Items)
	signing := ""
	for _, k := range page.Items {
		if k.Signing {
			signing = k.Kid
		}
	}
	require.NotEmpty(t, signing)

	del := adminDo(t, r, http.MethodDelete, "/admin/v1/keys/"+signing, adminTestKey, nil)
	require.Equal(t, http.StatusConflict, del.Code, del.Body.String())
	require.Contains(t, del.Body.String(), "last_signing_key")

	time.Sleep(1100 * time.Millisecond)
	created := adminDo(t, r, http.MethodPost, "/admin/v1/keys", adminTestKey, map[string]any{
		"generate": map[string]any{"alg": "ES256"},
	})
	require.Equal(t, http.StatusCreated, created.Code, created.Body.String())

	w = adminDo(t, r, http.MethodGet, "/admin/v1/keys", adminTestKey, nil)
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
	require.GreaterOrEqual(t, len(page.Items), 2)

	del = adminDo(t, r, http.MethodDelete, "/admin/v1/keys/"+signing, adminTestKey, nil)
	require.Equal(t, http.StatusNoContent, del.Code, del.Body.String())
}

func TestAdminAuditListAfterMutation(t *testing.T) {
	r := testAdminRouter(t)

	w := adminDo(t, r, http.MethodGet, "/admin/v1/audit", adminTestKey, nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var before struct {
		Items []adminaudit.Entry `json:"items"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &before))

	time.Sleep(1100 * time.Millisecond)
	w = adminDo(t, r, http.MethodPost, "/admin/v1/keys", adminTestKey, map[string]any{"generate": map[string]any{"alg": "ES256"}})
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	w = adminDo(t, r, http.MethodGet, "/admin/v1/audit", adminTestKey, nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var after struct {
		Items []adminaudit.Entry `json:"items"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &after))
	require.Greater(t, len(after.Items), len(before.Items), "expected a new audit row, before=%d after=%d body=%s", len(before.Items), len(after.Items), w.Body.String())

	found := false
	for _, e := range after.Items {
		if e.Action == "keys.create" && e.Method == http.MethodPost && e.Status == http.StatusCreated {
			found = true
			require.NotEmpty(t, e.Actor, "expected actor on audit row")
			break
		}
	}
	require.True(t, found, "missing keys.create in %+v", after.Items)

	w = adminDo(t, r, http.MethodGet, "/admin/v1/audit", adminTestKey, nil)
	var again struct {
		Items []adminaudit.Entry `json:"items"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &again))
	require.Equal(t, len(after.Items), len(again.Items), "GET audit should not record itself: %d -> %d", len(after.Items), len(again.Items))
}

func decodeAdminJWTPayload(t *testing.T, compact string) map[string]any {
	t.Helper()
	parts := strings.Split(strings.TrimSpace(compact), ".")
	require.Len(t, parts, 3)
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var obj map[string]any
	require.NoError(t, json.Unmarshal(raw, &obj))
	return obj
}
