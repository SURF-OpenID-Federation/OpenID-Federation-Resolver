package main

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestMaxConcurrencyMiddlewareReturns429(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(maxConcurrencyMiddleware(1))
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	r.GET("/slow", func(c *gin.Context) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		c.Status(http.StatusOK)
	})
	r.GET("/health", func(c *gin.Context) { c.Status(http.StatusOK) })

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/slow", nil))
		require.Equal(t, http.StatusOK, w.Code)
	}()
	<-started

	var tooMany int
	var mu sync.Mutex
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/slow", nil))
			if w.Code == http.StatusTooManyRequests {
				mu.Lock()
				tooMany++
				mu.Unlock()
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	require.Equal(t, 2, tooMany)

	health := httptest.NewRecorder()
	r.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/health", nil))
	require.Equal(t, http.StatusOK, health.Code)
}

func TestPublicRoutesOmitAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	setupPublicRoutes(r)
	setupNoRoute(r)

	ops := httptest.NewRecorder()
	r.ServeHTTP(ops, httptest.NewRequest(http.MethodGet, "/api/v1/ops", nil))
	require.Equal(t, http.StatusNotFound, ops.Code)

	reg := httptest.NewRecorder()
	r.ServeHTTP(reg, httptest.NewRequest(http.MethodPost, "/api/v1/register-trust-anchor", nil))
	require.Equal(t, http.StatusNotFound, reg.Code)

	resolve := httptest.NewRecorder()
	r.ServeHTTP(resolve, httptest.NewRequest(http.MethodGet, "/api/v1/resolve", nil))
	require.NotEqual(t, http.StatusNotFound, resolve.Code)
}
