package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestTokenAuthOpenWhenUnset(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/ops", tokenAuthMiddleware(nil, operatorWWWAuthenticate), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ops", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
}

func TestTokenAuthBearerAndAPIKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/ops", tokenAuthMiddleware([]string{"op-secret"}, operatorWWWAuthenticate), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	unauth := httptest.NewRecorder()
	r.ServeHTTP(unauth, httptest.NewRequest(http.MethodGet, "/ops", nil))
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("missing auth: %d", unauth.Code)
	}
	if unauth.Header().Get("WWW-Authenticate") != operatorWWWAuthenticate {
		t.Fatalf("WWW-Authenticate: %q", unauth.Header().Get("WWW-Authenticate"))
	}

	wrong := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ops", nil)
	req.Header.Set("Authorization", "Bearer nope")
	r.ServeHTTP(wrong, req)
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", wrong.Code)
	}

	okBearer := httptest.NewRecorder()
	good := httptest.NewRequest(http.MethodGet, "/ops", nil)
	good.Header.Set("Authorization", "Bearer op-secret")
	r.ServeHTTP(okBearer, good)
	if okBearer.Code != http.StatusOK {
		t.Fatalf("bearer: %d", okBearer.Code)
	}

	okHeader := httptest.NewRecorder()
	key := httptest.NewRequest(http.MethodGet, "/ops", nil)
	key.Header.Set("X-API-Key", "op-secret")
	r.ServeHTTP(okHeader, key)
	if okHeader.Code != http.StatusOK {
		t.Fatalf("X-API-Key: %d", okHeader.Code)
	}
}

func TestTAAdminAcceptsTATokenOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/register", tokenAuthMiddleware([]string{"ta-secret"}, taAdminWWWAuthenticate), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	unauth := httptest.NewRecorder()
	r.ServeHTTP(unauth, httptest.NewRequest(http.MethodPost, "/register", nil))
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("missing auth: %d", unauth.Code)
	}

	wrong := httptest.NewRecorder()
	opReq := httptest.NewRequest(http.MethodPost, "/register", nil)
	opReq.Header.Set("Authorization", "Bearer op-secret")
	r.ServeHTTP(wrong, opReq)
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("operator token: %d", wrong.Code)
	}

	ok := httptest.NewRecorder()
	taReq := httptest.NewRequest(http.MethodPost, "/register", nil)
	taReq.Header.Set("Authorization", "Bearer ta-secret")
	r.ServeHTTP(ok, taReq)
	if ok.Code != http.StatusOK {
		t.Fatalf("ta token: %d", ok.Code)
	}
}

func TestAuthStatusReflectsConfiguredKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)
	origKey, origTA := apiKey, taAPIToken
	t.Cleanup(func() {
		apiKey, taAPIToken = origKey, origTA
	})

	apiKey, taAPIToken = "", ""
	open := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(open)
	authStatusHandler(c)
	if open.Code != http.StatusOK || !strings.Contains(open.Body.String(), `"operator_required":false`) || !strings.Contains(open.Body.String(), `"ta_admin_required":false`) {
		t.Fatalf("unset: %d %s", open.Code, open.Body.String())
	}

	apiKey = "op"
	locked := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(locked)
	authStatusHandler(c2)
	if !strings.Contains(locked.Body.String(), `"operator_required":true`) || !strings.Contains(locked.Body.String(), `"ta_admin_required":false`) {
		t.Fatalf("api key: %s", locked.Body.String())
	}

	apiKey, taAPIToken = "", "ta-only"
	taOnly := httptest.NewRecorder()
	c3, _ := gin.CreateTestContext(taOnly)
	authStatusHandler(c3)
	if !strings.Contains(taOnly.Body.String(), `"operator_required":false`) || !strings.Contains(taOnly.Body.String(), `"ta_admin_required":true`) {
		t.Fatalf("ta only: %s", taOnly.Body.String())
	}
}
