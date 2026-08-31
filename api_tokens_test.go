package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"resolver/pkg/apitokens"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestTokenRoutesCreateListRevoke(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("API_PAT_PEPPER", "test-pepper")
	apitokens.SetForTest(nil)
	t.Cleanup(func() { apitokens.SetForTest(nil) })

	_, err := apitokens.Init(t.TempDir())
	require.NoError(t, err)

	origKey := apiKey
	apiKey = "op-secret"
	t.Cleanup(func() { apiKey = origKey })

	r := gin.New()
	g := r.Group("/admin/v1", adminAuthMiddleware())
	registerTokenRoutes(g)

	create := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"name": "lab", "ttl_days": 7})
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "op-secret")
	r.ServeHTTP(create, req)
	require.Equal(t, http.StatusCreated, create.Code)

	var created struct {
		Token string `json:"token"`
		PAT   struct {
			ID string `json:"id"`
		} `json:"pat"`
	}
	require.NoError(t, json.Unmarshal(create.Body.Bytes(), &created))
	require.NotEmpty(t, created.Token)
	require.NotEmpty(t, created.PAT.ID)
	require.Contains(t, create.Body.String(), `"created_by":"api-key"`)

	list := httptest.NewRecorder()
	listReq := httptest.NewRequest(http.MethodGet, "/admin/v1/tokens", nil)
	listReq.Header.Set("X-API-Key", "op-secret")
	r.ServeHTTP(list, listReq)
	require.Equal(t, http.StatusOK, list.Code)
	require.Contains(t, list.Body.String(), `"lab"`)

	patOnTokens := httptest.NewRecorder()
	patReq := httptest.NewRequest(http.MethodGet, "/admin/v1/tokens", nil)
	patReq.Header.Set("X-API-Key", created.Token)
	r.ServeHTTP(patOnTokens, patReq)
	require.Equal(t, http.StatusForbidden, patOnTokens.Code)

	rev := httptest.NewRecorder()
	delReq := httptest.NewRequest(http.MethodDelete, "/admin/v1/tokens/"+created.PAT.ID, nil)
	delReq.Header.Set("X-API-Key", "op-secret")
	r.ServeHTTP(rev, delReq)
	require.Equal(t, http.StatusOK, rev.Code)
}

func TestOperatorAuthAcceptsPAT(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("API_PAT_PEPPER", "test-pepper")
	apitokens.SetForTest(nil)
	t.Cleanup(func() { apitokens.SetForTest(nil) })

	store, err := apitokens.Init(t.TempDir())
	require.NoError(t, err)
	plain, _, err := store.CreatePAT("ops", 24*time.Hour, apitokens.TokenActor{}, time.Now())
	require.NoError(t, err)

	origKey := apiKey
	apiKey = "op-secret"
	t.Cleanup(func() { apiKey = origKey })

	r := gin.New()
	r.POST("/admin/v1/cache/clear-all", operatorAuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	unauth := httptest.NewRecorder()
	r.ServeHTTP(unauth, httptest.NewRequest(http.MethodPost, "/admin/v1/cache/clear-all", nil))
	require.Equal(t, http.StatusUnauthorized, unauth.Code)

	okPAT := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/cache/clear-all", nil)
	req.Header.Set("X-API-Key", plain)
	r.ServeHTTP(okPAT, req)
	require.Equal(t, http.StatusOK, okPAT.Code)
}
