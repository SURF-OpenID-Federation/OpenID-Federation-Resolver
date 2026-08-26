package main

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	operatorWWWAuthenticate = `Bearer realm="resolver"`
	taAdminWWWAuthenticate  = `Bearer realm="resolver-ta"`
)

// tokenAuthMiddleware requires a presented secret to match one of tokens.
// Accepted sources: Authorization: Bearer, or X-API-Key.
// An empty candidate list leaves the route unauthenticated.
func tokenAuthMiddleware(tokens []string, wwwAuthenticate string) gin.HandlerFunc {
	wanted := uniqueNonEmpty(tokens)
	if len(wanted) == 0 {
		return func(c *gin.Context) { c.Next() }
	}
	if wwwAuthenticate == "" {
		wwwAuthenticate = operatorWWWAuthenticate
	}
	return func(c *gin.Context) {
		got := presentedAPIToken(c)
		if !tokenMatchesAny(got, wanted) {
			c.Header("WWW-Authenticate", wwwAuthenticate)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
			})
			return
		}
		c.Next()
	}
}

func presentedAPIToken(c *gin.Context) string {
	if tok, ok := bearerToken(c.GetHeader("Authorization")); ok {
		return tok
	}
	return strings.TrimSpace(c.GetHeader("X-API-Key"))
}

func tokenMatchesAny(got string, wanted []string) bool {
	if got == "" || len(wanted) == 0 {
		return false
	}
	gotb := []byte(got)
	match := false
	for _, want := range wanted {
		wb := []byte(want)
		if len(gotb) != len(wb) {
			continue
		}
		if subtle.ConstantTimeCompare(gotb, wb) == 1 {
			match = true
		}
	}
	return match
}

func uniqueNonEmpty(tokens []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(tokens))
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

func operatorAuthMiddleware() gin.HandlerFunc {
	return tokenAuthMiddleware([]string{apiKey}, operatorWWWAuthenticate)
}

func taAdminAuthMiddleware() gin.HandlerFunc {
	return tokenAuthMiddleware([]string{apiKey, taAPIToken}, taAdminWWWAuthenticate)
}

func authStatusHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"operator_required": strings.TrimSpace(apiKey) != "",
		"ta_admin_required": strings.TrimSpace(apiKey) != "" || strings.TrimSpace(taAPIToken) != "",
	})
}
