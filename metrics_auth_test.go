package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestMetricsAuthMiddlewareOpenWhenEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/metrics", metricsAuthMiddleware(""), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
}

func TestMetricsAuthMiddlewareRequiresBearer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/metrics", metricsAuthMiddleware("secret-token"), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	unauth := httptest.NewRecorder()
	r.ServeHTTP(unauth, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("missing auth: %d", unauth.Code)
	}
	if unauth.Header().Get("WWW-Authenticate") != metricsWWWAuthenticate {
		t.Fatalf("WWW-Authenticate: %q", unauth.Header().Get("WWW-Authenticate"))
	}

	wrong := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer nope")
	r.ServeHTTP(wrong, req)
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", wrong.Code)
	}

	ok := httptest.NewRecorder()
	good := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	good.Header.Set("Authorization", "Bearer secret-token")
	r.ServeHTTP(ok, good)
	if ok.Code != http.StatusOK || ok.Body.String() != "ok" {
		t.Fatalf("valid token: %d %q", ok.Code, ok.Body.String())
	}

	lower := httptest.NewRecorder()
	bearer := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	bearer.Header.Set("Authorization", "bearer secret-token")
	r.ServeHTTP(lower, bearer)
	if lower.Code != http.StatusOK {
		t.Fatalf("lowercase bearer: %d", lower.Code)
	}
}

func TestMetricsHandlerOpenWhenTokenEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/metrics", metricsAuthMiddleware(""), metricsHandler)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "go_goroutines") {
		t.Fatalf("expected prometheus output, got %q", w.Body.String())
	}
}

func TestMetricsHandlerRequiresBearer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/metrics", metricsAuthMiddleware("metrics-secret"), metricsHandler)

	unauth := httptest.NewRecorder()
	r.ServeHTTP(unauth, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("missing auth: %d", unauth.Code)
	}

	ok := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer metrics-secret")
	r.ServeHTTP(ok, req)
	if ok.Code != http.StatusOK {
		t.Fatalf("valid token: %d", ok.Code)
	}
}
