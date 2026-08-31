package adminauth

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// PickDisplayNameFromUserInfoClaims returns preferred_username, else email, else sub.
func PickDisplayNameFromUserInfoClaims(claims map[string]interface{}) string {
	if s := stringClaim(claims, "preferred_username"); s != "" {
		return s
	}
	if s := stringClaim(claims, "email"); s != "" {
		return s
	}
	return stringClaim(claims, "sub")
}

func stringClaim(claims map[string]interface{}, key string) string {
	v, ok := claims[key]
	if !ok || v == nil {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	default:
		return fmt.Sprint(s)
	}
}

// HasOIDCAdminSession is true when the request was authenticated with UserInfo (access token) or a Bearer JWT, not API key alone.
func HasOIDCAdminSession(c *gin.Context) bool {
	_, okU := c.Get(AdminContextUserinfoClaimsKey)
	_, okJ := c.Get(AdminContextJWTClaimsKey)
	return okU || okJ
}

// BannerDisplayNameFromContext returns a label for the /admin banner from claims stored by AdminAuthMiddleware.
func BannerDisplayNameFromContext(c *gin.Context) string {
	if v, ok := c.Get(AdminContextUserinfoClaimsKey); ok {
		if claims, ok := v.(map[string]interface{}); ok {
			dn := PickDisplayNameFromUserInfoClaims(claims)
			if dn != "" {
				return dn
			}
			return "Signed in"
		}
	}
	if v, ok := c.Get(AdminContextJWTClaimsKey); ok {
		if mc, ok := v.(jwt.MapClaims); ok {
			dn := PickDisplayNameFromJWTClaims(mc)
			if dn != "" {
				return dn
			}
			return "Signed in"
		}
	}
	return ""
}

// HandleAdminWhoami returns the current admin identity for the banner (UserInfo or JWT claims).
// Expects to run behind the same auth as AdminAuthMiddleware (already passed).
func HandleAdminWhoami(c *gin.Context) {
	if method, ok := c.Get(AdminContextAuthMethodKey); ok {
		if m, ok := method.(string); ok && (m == string(AuthKindPAT) || m == string(AuthKindBreakGlass)) {
			a := TokenActorFromContext(c)
			prefix, _ := c.Get(AdminContextTokenPrefixKey)
			name, _ := c.Get(AdminContextTokenNameKey)
			c.JSON(http.StatusOK, gin.H{
				"auth_method":        m,
				"display_name":       a.Label(),
				"preferred_username": nil,
				"email":              nil,
				"sub":                a.Sub,
				"iss":                a.Iss,
				"token_prefix":       prefix,
				"token_name":         name,
			})
			return
		}
	}
	if v, ok := c.Get(AdminContextUserinfoClaimsKey); ok {
		if claims, ok := v.(map[string]interface{}); ok {
			c.JSON(http.StatusOK, gin.H{
				"auth_method":        "oidc_access_token",
				"display_name":       PickDisplayNameFromUserInfoClaims(claims),
				"preferred_username": stringClaim(claims, "preferred_username"),
				"email":              stringClaim(claims, "email"),
				"sub":                stringClaim(claims, "sub"),
			})
			return
		}
	}
	if v, ok := c.Get(AdminContextJWTClaimsKey); ok {
		if mc, ok := v.(jwt.MapClaims); ok {
			dn := PickDisplayNameFromJWTClaims(mc)
			sub, _ := mc["sub"].(string)
			email, _ := mc["email"].(string)
			pref, _ := mc["preferred_username"].(string)
			c.JSON(http.StatusOK, gin.H{
				"auth_method":        "oidc_bearer",
				"display_name":       dn,
				"preferred_username": pref,
				"email":              email,
				"sub":                sub,
			})
			return
		}
	}

	issuerConfigured := strings.TrimSpace(os.Getenv("ADMIN_AUTH_ISSUER")) != ""

	// Prefer access-token header (e.g. oauth2-proxy) or httpOnly cookie → UserInfo
	tok := strings.TrimSpace(c.GetHeader(AdminAccessTokenHeader()))
	if tok == "" {
		tok = getCookieValue(c, accessTokenCookieName())
	}
	if tok != "" && issuerConfigured {
		claims, err := FetchUserInfoClaims(tok)
		if err == nil {
			c.JSON(http.StatusOK, gin.H{
				"auth_method":        "oidc_access_token",
				"display_name":       PickDisplayNameFromUserInfoClaims(claims),
				"preferred_username": stringClaim(claims, "preferred_username"),
				"email":              stringClaim(claims, "email"),
				"sub":                stringClaim(claims, "sub"),
			})
			return
		}
		// Unusual after middleware; fall through to bearer / api_key response
	}

	// Bearer JWT (already validated by middleware) or cookie
	authz := strings.TrimSpace(c.GetHeader("Authorization"))
	var raw string
	if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		raw = strings.TrimSpace(authz[len("Bearer "):])
	}
	if raw == "" {
		raw = getCookieValue(c, bearerCookieName())
	}
	if raw != "" {
		token, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
		if err == nil {
			if mc, ok := token.Claims.(jwt.MapClaims); ok {
				dn := PickDisplayNameFromJWTClaims(mc)
				sub, _ := mc["sub"].(string)
				email, _ := mc["email"].(string)
				pref, _ := mc["preferred_username"].(string)
				c.JSON(http.StatusOK, gin.H{
					"auth_method":        "oidc_bearer",
					"display_name":       dn,
					"preferred_username": pref,
					"email":              email,
					"sub":                sub,
				})
				return
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"auth_method":        "api_key",
		"display_name":       nil,
		"preferred_username": nil,
		"email":              nil,
		"sub":                nil,
	})
}

// PickDisplayNameFromJWTClaims returns preferred_username, email, or sub from JWT map claims.
func PickDisplayNameFromJWTClaims(mc jwt.MapClaims) string {
	if s, _ := mc["preferred_username"].(string); s != "" {
		return s
	}
	if s, _ := mc["email"].(string); s != "" {
		return s
	}
	if s, _ := mc["sub"].(string); s != "" {
		return s
	}
	return ""
}
