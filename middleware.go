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
