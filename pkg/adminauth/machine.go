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
	AdminContextTokenActorKey  = "admin_auth_token_actor"
	AdminContextTokenNameKey   = "admin_auth_token_name"
	AdminContextTokenIDKey     = "admin_auth_token_id"
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
	res, err := store.Authenticate(secret, time.Now())
	if err != nil {
		log.Printf("[api-tokens] auth failed prefix=%s err=%v", tokenPrefixForLog(secret), err)
		if errors.Is(err, apitokens.ErrTokenRevoked) {
			writeAdminUnauthorized(c, "token revoked")
		}
		return false
	}
	c.Set(AdminContextAuthMethodKey, string(AuthKindPAT))
	c.Set(AdminContextAuthScopesKey, []string{apitokens.ScopeAPIFull})
	c.Set(AdminContextTokenPrefixKey, res.Prefix)
	c.Set(AdminContextTokenActorKey, res.Actor)
	c.Set(AdminContextTokenNameKey, res.TokenName)
	c.Set(AdminContextTokenIDKey, res.TokenID)
	log.Printf("[api-tokens] authenticated kind=pat prefix=%s actor=%s", res.Prefix, res.Actor.Label())
	return true
}

func tokenPrefixForLog(secret string) string {
	secret = strings.TrimSpace(secret)
	parts := strings.SplitN(secret, "_", 4)
	if len(parts) >= 3 {
		return parts[0] + "_" + parts[1] + "_" + parts[2]
	}
	if len(secret) > 16 {
		return secret[:16]
	}
	return secret
}

// CreatorIdentityFromContext extracts the minting identity for PAT audit fields.
func CreatorIdentityFromContext(c *gin.Context) apitokens.TokenActor {
	iss := strings.TrimSpace(os.Getenv("ADMIN_AUTH_ISSUER"))
	if v, ok := c.Get(AdminContextUserinfoClaimsKey); ok {
		if claims, ok := v.(map[string]interface{}); ok {
			sub := stringClaim(claims, "sub")
			if s := stringClaim(claims, "iss"); s != "" {
				iss = s
			}
			return apitokens.TokenActor{Sub: sub, Iss: iss, Display: PickDisplayNameFromUserInfoClaims(claims)}
		}
	}
	if v, ok := c.Get(AdminContextJWTClaimsKey); ok {
		if mc, ok := v.(jwt.MapClaims); ok {
			sub, _ := mc["sub"].(string)
			if s, _ := mc["iss"].(string); s != "" {
				iss = s
			}
			return apitokens.TokenActor{Sub: sub, Iss: iss, Display: PickDisplayNameFromJWTClaims(mc)}
		}
	}
	if method, _ := c.Get(AdminContextAuthMethodKey); method == string(AuthKindLegacyKey) {
		return apitokens.TokenActor{Sub: "api-key", Iss: "local", Display: "api-key"}
	}
	return apitokens.TokenActor{Iss: iss}
}

// TokenActorFromContext returns the PAT creator stored at authenticate time.
func TokenActorFromContext(c *gin.Context) apitokens.TokenActor {
	if v, ok := c.Get(AdminContextTokenActorKey); ok {
		if a, ok := v.(apitokens.TokenActor); ok {
			return a
		}
	}
	return apitokens.TokenActor{}
}

// RequestActor is a display label for audit logs: PAT creator, else OIDC subject, else auth method.
func RequestActor(c *gin.Context) string {
	if v, ok := c.Get(AdminContextTokenActorKey); ok {
		if a, ok := v.(apitokens.TokenActor); ok {
			if label := a.Label(); label != "" {
				return label
			}
		}
	}
	if label := CreatorIdentityFromContext(c).Label(); label != "" {
		return label
	}
	if method, _ := c.Get(AdminContextAuthMethodKey); method != nil {
		if s, ok := method.(string); ok && s != "" {
			return s
		}
	}
	return ""
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
