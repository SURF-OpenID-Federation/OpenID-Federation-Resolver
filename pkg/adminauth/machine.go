package adminauth

import (
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"resolver/pkg/apitokens"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const (
	AdminContextAuthMethodKey  = "admin_auth_method"
	AdminContextAuthScopesKey  = "admin_auth_scopes"
	AdminContextTokenPrefixKey = "admin_auth_token_prefix"
)

type AuthKind string

const (
	AuthKindPAT        AuthKind = "pat"
	AuthKindBreakGlass AuthKind = "break_glass"
	AuthKindLegacyKey  AuthKind = "api_key"
)

func APITokenStoreActive() bool {
	return apitokens.Get() != nil
}

func ExtractAPIKeyFromRequest(xAPIKey, authorization string) string {
	if k := strings.TrimSpace(xAPIKey); k != "" {
		return k
	}
	authz := strings.TrimSpace(authorization)
	if len(authz) >= 7 && strings.EqualFold(authz[:7], "bearer ") {
		return strings.TrimSpace(authz[7:])
	}
	return ""
}

func tryMachineAuth(c *gin.Context, secret string, _ bool) bool {
	store := apitokens.Get()
	secret = strings.TrimSpace(secret)
	if store == nil || !apitokens.LooksLikePAT(secret) {
		return false
	}
	err := store.Authenticate(secret, time.Now())
	if err != nil {
		log.Printf("[api-tokens] auth failed err=%v", err)
		if errors.Is(err, apitokens.ErrTokenRevoked) {
			writeAdminUnauthorized(c, "token revoked")
		}
		return false
	}
	c.Set(AdminContextAuthMethodKey, string(AuthKindPAT))
	c.Set(AdminContextAuthScopesKey, []string{apitokens.ScopeAPIFull})
	return true
}

func TokenManageScope() string {
	if s := strings.TrimSpace(os.Getenv("ADMIN_AUTH_TOKEN_MANAGE_SCOPE")); s != "" {
		return s
	}
	return strings.TrimSpace(os.Getenv("ADMIN_AUTH_REQUIRED_SCOPE"))
}

func HasTokenManageAuthority(c *gin.Context) bool {
	if method, _ := c.Get(AdminContextAuthMethodKey); method == string(AuthKindPAT) {
		return false
	}
	if !AdminAuthConfigured() {
		return true
	}
	if method, _ := c.Get(AdminContextAuthMethodKey); method == string(AuthKindLegacyKey) {
		return true
	}
	if envAPIKeyMatches(ExtractAPIKeyFromRequest(c.GetHeader("X-API-Key"), c.GetHeader("Authorization"))) {
		return true
	}
	if !HasOIDCAdminSession(c) {
		return false
	}
	required := TokenManageScope()
	if required == "" {
		return true
	}
	return oidcClaimsHaveScope(c, required)
}

func oidcClaimsHaveScope(c *gin.Context, required string) bool {
	if v, ok := c.Get(AdminContextJWTClaimsKey); ok {
		if mc, ok := v.(jwt.MapClaims); ok && hasRequiredScope(mc, required) {
			return true
		}
	}
	if v, ok := c.Get(AdminContextUserinfoClaimsKey); ok {
		if claims, ok := v.(map[string]interface{}); ok {
			mc := jwt.MapClaims{}
			for k, val := range claims {
				mc[k] = val
			}
			if hasRequiredScope(mc, required) {
				return true
			}
		}
	}
	return false
}

func RequireTokenManage() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !HasTokenManageAuthority(c) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":             "forbidden",
				"error_description": "token management requires OIDC (or ENV API_KEY); a PAT cannot mint more PATs",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

func adminOIDCHTTPClient() *http.Client {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	v := strings.ToLower(strings.TrimSpace(os.Getenv("TLS_INSECURE_SKIP_VERIFY")))
	if v == "1" || v == "true" || v == "yes" {
		tc.InsecureSkipVerify = true
	}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tc,
		},
	}
}
