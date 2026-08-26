package main

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const metricsWWWAuthenticate = `Bearer realm="metrics"`

// metricsAuthMiddleware requires Authorization: Bearer when token is non-empty.
// An empty token leaves GET /metrics unauthenticated (default for internal scrape).
func metricsAuthMiddleware(token string) gin.HandlerFunc {
	expected := strings.TrimSpace(token)
	if expected == "" {
		return func(c *gin.Context) { c.Next() }
	}
	want := []byte(expected)
	return func(c *gin.Context) {
		got, ok := bearerToken(c.GetHeader("Authorization"))
		if !ok || subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			c.Header("WWW-Authenticate", metricsWWWAuthenticate)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}

func bearerToken(header string) (string, bool) {
	const prefix = "Bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	tok := strings.TrimSpace(header[len(prefix):])
	return tok, tok != ""
}
