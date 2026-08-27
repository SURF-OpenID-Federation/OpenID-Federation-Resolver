package main

import (
	"strings"
	"time"

	"resolver/pkg/metrics"

	"github.com/gin-gonic/gin"
)

func httpMetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		path := c.FullPath()
		if path == "" || skipHTTPMetrics(path) {
			return
		}
		metrics.RecordHTTPRequest(c.Request.Method, path, c.Writer.Status(), time.Since(start))
	}
}

func skipHTTPMetrics(path string) bool {
	switch path {
	case "/", "/metrics", "/health", "/api/v1/ops", "/api/v1/docs", "/api/v1/openapi.json", "/api/v1/auth/status":
		return true
	}
	return strings.HasPrefix(path, "/static")
}

func maxConcurrencyMiddleware(n int) gin.HandlerFunc {
	if n <= 0 {
		return func(c *gin.Context) { c.Next() }
	}
	sem := make(chan struct{}, n)
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		if path == "/health" || path == "/metrics" {
			c.Next()
			return
		}
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
			c.Next()
		default:
			c.Header("Retry-After", "1")
			c.AbortWithStatusJSON(429, gin.H{"error": "too_many_requests"})
		}
	}
}
