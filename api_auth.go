package main

import (
	"crypto/subtle"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"resolver/pkg/admin"
	"resolver/pkg/adminauth"
	"resolver/pkg/apitokens"

	"github.com/gin-gonic/gin"
)

const (
	operatorWWWAuthenticate = `Bearer realm="resolver"`
	taAdminWWWAuthenticate  = `Bearer realm="resolver-ta"`
)

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

func patAuthenticates(secret string) bool {
	store := apitokens.Get()
	if store == nil {
		return false
	}
	return store.Authenticate(strings.TrimSpace(secret), time.Now()) == nil
}

func envAPIKeyMatches(presented string) bool {
	return tokenMatchesAny(presented, uniqueNonEmpty([]string{apiKey}))
}

func operatorCredentialOK(presented string) bool {
	presented = strings.TrimSpace(presented)
	if envAPIKeyMatches(presented) || patAuthenticates(presented) {
		return true
	}
	return strings.TrimSpace(apiKey) == "" && !adminauth.AdminAuthConfigured() && presented == ""
}

func abortOperatorUnauthorized(c *gin.Context) {
	c.Header("WWW-Authenticate", operatorWWWAuthenticate)
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
}

func markOperatorAuthMethod(c *gin.Context, presented string) {
	if envAPIKeyMatches(presented) {
		c.Set(adminauth.AdminContextAuthMethodKey, string(adminauth.AuthKindLegacyKey))
		return
	}
	if patAuthenticates(presented) {
		c.Set(adminauth.AdminContextAuthMethodKey, string(adminauth.AuthKindPAT))
	}
}

func operatorAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		got := presentedAPIToken(c)
		if operatorCredentialOK(got) {
			markOperatorAuthMethod(c, got)
			c.Next()
			return
		}
		if adminauth.AdminAuthConfigured() {
			adminauth.AdminAuthMiddleware()(c)
			return
		}
		abortOperatorUnauthorized(c)
	}
}

func taAdminAuthMiddleware() gin.HandlerFunc {
	return tokenAuthMiddleware([]string{taAPIToken}, taAdminWWWAuthenticate)
}

func adminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		got := presentedAPIToken(c)
		if operatorCredentialOK(got) {
			markOperatorAuthMethod(c, got)
			c.Next()
			return
		}
		if adminauth.AdminAuthConfigured() {
			adminauth.AdminAuthMiddleware()(c)
			return
		}
		admin.Unauthorized(c, "missing or invalid authentication")
	}
}

func authStatusHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"operator_required": strings.TrimSpace(apiKey) != "" || adminauth.AdminAuthConfigured(),
		"ta_admin_required": strings.TrimSpace(taAPIToken) != "",
		"oidc_client":       adminauth.AdminOIDCClientConfigured(),
	})
}

func authVerifyHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func adminHomeURL() string {
	if u := strings.TrimSpace(os.Getenv("PUBLIC_HOME_URL")); u != "" {
		return u
	}
	return "/"
}

func registerAdminUI(router *gin.Engine) {
	if router == nil {
		return
	}
	router.GET("/admin/login", adminauth.HandleAdminOIDCLogin)
	router.GET("/admin/callback", adminauth.HandleAdminOIDCCallback)
	router.GET("/admin/logoff", adminauth.HandleAdminOIDCLogoff(adminHomeURL()))
	if adminauth.AdminAuthConfigured() {
		auth := adminauth.AdminAuthMiddleware()
		router.GET("/admin", auth, adminPageHandler)
		router.GET("/admin/", auth, adminPageHandler)
	} else {
		router.GET("/admin", adminPageHandler)
		router.GET("/admin/", adminPageHandler)
	}
	if adminauth.AdminOIDCClientConfigured() {
		log.Printf("Admin OIDC client enabled (GET /admin/login, /admin/callback)")
	}
}
