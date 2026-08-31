package adminauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const defaultAdminJWKSCacheTTL = 5 * time.Minute

// Gin context keys for claims resolved during AdminAuthMiddleware (used by /admin HTML and /api/v1/whoami).
const (
	AdminContextUserinfoClaimsKey = "admin_auth_userinfo_claims"
	AdminContextJWTClaimsKey      = "admin_auth_jwt_claims"
)

// oidcMetadata holds fields from /.well-known/openid-configuration used for admin auth.
type oidcMetadata struct {
	Issuer                string `json:"issuer"`
	JWKSURI               string `json:"jwks_uri"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

var adminJWKSCache = struct {
	sync.RWMutex
	jwksURI string
	keys    []map[string]interface{}
	expires time.Time
}{}

var oidcMetadataCache = struct {
	sync.RWMutex
	issuer  string
	meta    *oidcMetadata
	expires time.Time
}{}

// userInfoHTTPStatusError indicates the UserInfo endpoint returned a non-200 response.
// We treat this as an authentication failure that requires re-authentication.
type userInfoHTTPStatusError struct {
	StatusCode int
}

func (e *userInfoHTTPStatusError) Error() string {
	return fmt.Sprintf("userinfo returned %d", e.StatusCode)
}

// AdminAuthConfigured reports whether any admin authentication method is configured
// via environment variables. A process-generated API_KEY (for optional runtime config)
// does not enable admin auth — that keeps ENV-only deployments behaviour-compatible.
func AdminAuthConfigured() bool {
	return strings.TrimSpace(os.Getenv("API_KEY")) != "" ||
		strings.TrimSpace(os.Getenv("ADMIN_AUTH_ISSUER")) != ""
}

// accessTokenCookieName is the httpOnly cookie used to carry the OAuth2 access token for UserInfo
// when the reverse proxy forwards X-Access-Token on navigation but not on fetch/XHR (common).
func accessTokenCookieName() string {
	if n := strings.TrimSpace(os.Getenv("ADMIN_AUTH_ACCESS_TOKEN_COOKIE")); n != "" {
		return n
	}
	return "oidf_admin_access"
}

// bearerCookieName is the httpOnly cookie used to carry a validated Bearer JWT for the same reason.
func bearerCookieName() string {
	if n := strings.TrimSpace(os.Getenv("ADMIN_AUTH_BEARER_COOKIE")); n != "" {
		return n
	}
	return "oidf_admin_bearer"
}

func adminCookieSecure(c *gin.Context) bool {
	if strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https") {
		return true
	}
	return c.Request.TLS != nil
}

func accessTokenCookieMaxAge() int {
	s := strings.TrimSpace(os.Getenv("ADMIN_AUTH_ACCESS_TOKEN_COOKIE_MAX_AGE"))
	if s == "" {
		return 28800 // 8h
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 60 {
		return 28800
	}
	return n
}

func bearerCookieMaxAge() int {
	s := strings.TrimSpace(os.Getenv("ADMIN_AUTH_BEARER_COOKIE_MAX_AGE"))
	if s == "" {
		return 28800
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 60 {
		return 28800
	}
	return n
}

func getCookieValue(c *gin.Context, name string) string {
	ck, err := c.Request.Cookie(name)
	if err != nil || ck == nil {
		return ""
	}
	return strings.TrimSpace(ck.Value)
}

func setAccessTokenCookie(c *gin.Context, rawToken string) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     accessTokenCookieName(),
		Value:    rawToken,
		Path:     "/",
		MaxAge:   accessTokenCookieMaxAge(),
		HttpOnly: true,
		Secure:   adminCookieSecure(c),
		SameSite: http.SameSiteLaxMode,
	})
}

func setBearerCookie(c *gin.Context, rawToken string) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     bearerCookieName(),
		Value:    rawToken,
		Path:     "/",
		MaxAge:   bearerCookieMaxAge(),
		HttpOnly: true,
		Secure:   adminCookieSecure(c),
		SameSite: http.SameSiteLaxMode,
	})
}

func clearAccessTokenCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     accessTokenCookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   adminCookieSecure(c),
		SameSite: http.SameSiteLaxMode,
	})
}

func clearBearerCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     bearerCookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   adminCookieSecure(c),
		SameSite: http.SameSiteLaxMode,
	})
}

// AdminAuthMiddleware allows admin access using either:
//   - X-API-Key header matching API_KEY
//   - Access token in X-Access-Token (header name configurable via ADMIN_AUTH_ACCESS_TOKEN_HEADER),
//     validated with a GET to the OIDC UserInfo endpoint (from issuer discovery or ADMIN_AUTH_USERINFO_URL).
//     Intended for oauth2-proxy and similar proxies that pass the upstream access token in a custom header.
//   - Authorization: Bearer <token>, validated as a JWT against the authorization server's JWKS
//
// Configuration:
// - ADMIN_AUTH_ISSUER (required for bearer / userinfo validation)
// - ADMIN_AUTH_JWKS_URI (optional, discovered from issuer metadata if omitted)
// - ADMIN_AUTH_USERINFO_URL (optional, overrides userinfo_endpoint from discovery)
// - ADMIN_AUTH_ACCESS_TOKEN_HEADER (optional, default X-Access-Token)
// - ADMIN_AUTH_AUDIENCE (optional but recommended for JWT bearer)
// - ADMIN_AUTH_REQUIRED_SCOPE (optional, JWT bearer only)
func AdminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		reqKey := ExtractAPIKeyFromRequest(c.GetHeader("X-API-Key"), c.GetHeader("Authorization"))
		if tryMachineAuth(c, reqKey, true) {
			c.Next()
			return
		}
		if c.IsAborted() {
			return
		}
		// Only the ENV API_KEY unlocks admin UI/API (not a generated runtime-config key).
		if envAPIKeyMatches(c.GetHeader("X-API-Key")) {
			c.Set(AdminContextAuthMethodKey, string(AuthKindLegacyKey))
			c.Next()
			return
		}

		authz := strings.TrimSpace(c.GetHeader("Authorization"))
		var bearerTok string
		if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			bearerTok = strings.TrimSpace(authz[len("Bearer "):])
		}
		// Accept Authorization: Bearer <API_KEY> before treating the token as an OIDC JWT.
		if bearerTok != "" && envAPIKeyMatches(bearerTok) {
			c.Set(AdminContextAuthMethodKey, string(AuthKindLegacyKey))
			c.Next()
			return
		}

		accessHeader := strings.TrimSpace(os.Getenv("ADMIN_AUTH_ACCESS_TOKEN_HEADER"))
		if accessHeader == "" {
			accessHeader = "X-Access-Token"
		}
		headerAT := strings.TrimSpace(c.GetHeader(accessHeader))
		cookieAT := getCookieValue(c, accessTokenCookieName())
		atTok := headerAT
		if atTok == "" {
			atTok = cookieAT
		}
		if atTok != "" {
			claims, err := FetchUserInfoClaims(atTok)
			if err != nil {
				var userInfoErr *userInfoHTTPStatusError
				if errors.As(err, &userInfoErr) {
					if cookieAT != "" && headerAT == "" {
						clearAccessTokenCookie(c)
					}
					writeAdminUnauthorized(c, "Re-authentication required")
					return
				}
				if cookieAT != "" && headerAT == "" {
					clearAccessTokenCookie(c)
				}
				writeAdminForbidden(c, fmt.Sprintf("Invalid access token: %v", err))
				return
			}
			c.Set(AdminContextUserinfoClaimsKey, claims)
			// So fetch() to /api (no proxy-injected header) still authenticates via Cookie.
			setAccessTokenCookie(c, atTok)
			c.Next()
			return
		}

		if bearerTok == "" {
			bearerTok = getCookieValue(c, bearerCookieName())
		}
		if bearerTok != "" {
			if envAPIKeyMatches(bearerTok) {
				c.Set(AdminContextAuthMethodKey, string(AuthKindLegacyKey))
				c.Next()
				return
			}
			if err := validateBearerToken(bearerTok); err != nil {
				if ck := getCookieValue(c, bearerCookieName()); ck != "" && bearerTok == ck {
					clearBearerCookie(c)
				}
				writeAdminForbidden(c, fmt.Sprintf("Invalid bearer token: %v", err))
				return
			}
			// Claims for banner / whoami (signature already validated above).
			if t, _, err := jwt.NewParser().ParseUnverified(bearerTok, jwt.MapClaims{}); err == nil {
				if mc, ok := t.Claims.(jwt.MapClaims); ok {
					c.Set(AdminContextJWTClaimsKey, mc)
				}
			}
			setBearerCookie(c, bearerTok)
			c.Next()
			return
		}

		if !AdminAuthConfigured() {
			c.Next()
			return
		}

		writeAdminUnauthorized(c, "Provide X-API-Key, "+accessHeader+", or Authorization: Bearer <token>")
	}
}

func envAPIKeyMatches(provided string) bool {
	configured := strings.TrimSpace(os.Getenv("API_KEY"))
	if configured == "" || provided == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(configured), []byte(provided)) == 1
}

func validateBearerToken(rawToken string) error {
	issuer := strings.TrimSpace(os.Getenv("ADMIN_AUTH_ISSUER"))
	if issuer == "" {
		return fmt.Errorf("ADMIN_AUTH_ISSUER is not configured")
	}
	audience := strings.TrimSpace(os.Getenv("ADMIN_AUTH_AUDIENCE"))
	requiredScope := strings.TrimSpace(os.Getenv("ADMIN_AUTH_REQUIRED_SCOPE"))

	keys, err := getAdminJWKSKeys(issuer)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return fmt.Errorf("authorization server JWKS has no keys")
	}

	mapClaims := jwt.MapClaims{}
	keyfunc := func(token *jwt.Token) (interface{}, error) {
		if token.Method == nil {
			return nil, fmt.Errorf("missing token signing method")
		}
		kid, _ := token.Header["kid"].(string)
		alg, _ := token.Header["alg"].(string)

		for _, key := range keys {
			if kid != "" {
				if keyKid, _ := key["kid"].(string); keyKid != kid {
					continue
				}
			}
			if keyAlg, _ := key["alg"].(string); keyAlg != "" && alg != "" && keyAlg != alg {
				continue
			}
			pub, err := jwkToPublicKey(key)
			if err == nil {
				return pub, nil
			}
		}
		return nil, fmt.Errorf("no matching verification key found")
	}

	token, err := jwt.ParseWithClaims(rawToken, mapClaims, keyfunc)
	if err != nil {
		return err
	}
	if !token.Valid {
		return fmt.Errorf("token is not valid")
	}

	if err := verifyBearerClaims(mapClaims, issuer, audience, requiredScope); err != nil {
		return err
	}
	return nil
}

func verifyBearerClaims(claims jwt.MapClaims, issuer, audience, requiredScope string) error {
	now := time.Now()

	if iss, _ := claims.GetIssuer(); iss != issuer {
		return fmt.Errorf("unexpected issuer")
	}
	if audience != "" {
		aud, err := claims.GetAudience()
		if err != nil {
			return fmt.Errorf("invalid audience claim")
		}
		found := false
		for _, a := range aud {
			if a == audience {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("audience mismatch")
		}
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil || now.After(exp.Time) {
		return fmt.Errorf("token expired")
	}
	if nbf, err := claims.GetNotBefore(); err == nil && nbf != nil && now.Before(nbf.Time) {
		return fmt.Errorf("token not active yet")
	}

	if requiredScope != "" {
		if !hasRequiredScope(claims, requiredScope) {
			return fmt.Errorf("required scope %q is missing", requiredScope)
		}
	}
	return nil
}

func hasRequiredScope(claims jwt.MapClaims, requiredScope string) bool {
	if scopeString, ok := claims["scope"].(string); ok {
		for _, s := range strings.Fields(scopeString) {
			if s == requiredScope {
				return true
			}
		}
	}
	if scpSlice, ok := claims["scp"].([]interface{}); ok {
		for _, v := range scpSlice {
			if s, ok := v.(string); ok && s == requiredScope {
				return true
			}
		}
	}
	return false
}

// DiscoverOIDCMetadata fetches and caches OpenID Provider metadata for issuer.
func DiscoverOIDCMetadata(issuer string) (*OIDCMetadata, error) {
	m, err := ensureOIDCMetadata(issuer)
	if err != nil {
		return nil, err
	}
	return &OIDCMetadata{
		Issuer:                m.Issuer,
		JWKSURI:               m.JWKSURI,
		UserinfoEndpoint:      m.UserinfoEndpoint,
		AuthorizationEndpoint: m.AuthorizationEndpoint,
		TokenEndpoint:         m.TokenEndpoint,
		EndSessionEndpoint:    m.EndSessionEndpoint,
	}, nil
}

// OIDCMetadata is the public view of IdP discovery used by capabilities and clients.
type OIDCMetadata struct {
	Issuer                string
	JWKSURI               string
	UserinfoEndpoint      string
	AuthorizationEndpoint string
	TokenEndpoint         string
	EndSessionEndpoint    string
}

func ensureOIDCMetadata(issuer string) (*oidcMetadata, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if issuer == "" {
		return nil, fmt.Errorf("issuer is empty")
	}

	oidcMetadataCache.RLock()
	if time.Now().Before(oidcMetadataCache.expires) && oidcMetadataCache.meta != nil && oidcMetadataCache.issuer == issuer {
		m := oidcMetadataCache.meta
		oidcMetadataCache.RUnlock()
		return m, nil
	}
	oidcMetadataCache.RUnlock()

	wellKnown := issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequest(http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("issuer discovery returned %d", resp.StatusCode)
	}

	var metadata oidcMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, err
	}
	if metadata.JWKSURI == "" {
		return nil, fmt.Errorf("discovery metadata does not include jwks_uri")
	}
	if metadata.Issuer != "" && metadata.Issuer != issuer {
		return nil, fmt.Errorf("discovery issuer mismatch")
	}

	ttl := adminJWKSCacheTTL()
	oidcMetadataCache.Lock()
	oidcMetadataCache.issuer = issuer
	oidcMetadataCache.meta = &metadata
	oidcMetadataCache.expires = time.Now().Add(ttl)
	oidcMetadataCache.Unlock()

	return &metadata, nil
}

// FetchUserInfoClaims returns OIDC UserInfo JSON for an access token.
func FetchUserInfoClaims(accessToken string) (map[string]interface{}, error) {
	issuer := strings.TrimSpace(os.Getenv("ADMIN_AUTH_ISSUER"))
	if issuer == "" {
		return nil, fmt.Errorf("ADMIN_AUTH_ISSUER is not configured")
	}

	userinfoURL := strings.TrimSpace(os.Getenv("ADMIN_AUTH_USERINFO_URL"))
	if userinfoURL == "" {
		meta, err := ensureOIDCMetadata(issuer)
		if err != nil {
			return nil, err
		}
		userinfoURL = meta.UserinfoEndpoint
	}
	if userinfoURL == "" {
		return nil, fmt.Errorf("userinfo_endpoint missing in issuer metadata; set ADMIN_AUTH_USERINFO_URL")
	}

	req, err := http.NewRequest(http.MethodGet, userinfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("[admin-auth] UserInfo request to %s failed: %v", userinfoURL, err)
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 768))
		trim := strings.TrimSpace(string(snippet))
		if len(trim) > 500 {
			trim = trim[:500] + "…"
		}
		log.Printf("[admin-auth] UserInfo GET %s → HTTP %d (check IdP / token type: UserInfo expects an OAuth2 access token, not an ID token). Response body: %s",
			userinfoURL, resp.StatusCode, trim)
		return nil, &userInfoHTTPStatusError{StatusCode: resp.StatusCode}
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		log.Printf("[admin-auth] UserInfo %s returned 200 but non-JSON body: %v", userinfoURL, err)
		return nil, fmt.Errorf("userinfo response is not JSON: %w", err)
	}
	return body, nil
}

// AdminAccessTokenHeader returns the configured access-token header name (e.g. X-Access-Token).
func AdminAccessTokenHeader() string {
	h := strings.TrimSpace(os.Getenv("ADMIN_AUTH_ACCESS_TOKEN_HEADER"))
	if h == "" {
		return "X-Access-Token"
	}
	return h
}

func getAdminJWKSKeys(issuer string) ([]map[string]interface{}, error) {
	adminJWKSCache.RLock()
	if time.Now().Before(adminJWKSCache.expires) && len(adminJWKSCache.keys) > 0 {
		keys := make([]map[string]interface{}, len(adminJWKSCache.keys))
		copy(keys, adminJWKSCache.keys)
		adminJWKSCache.RUnlock()
		return keys, nil
	}
	adminJWKSCache.RUnlock()

	jwksURI := strings.TrimSpace(os.Getenv("ADMIN_AUTH_JWKS_URI"))
	if jwksURI == "" {
		meta, err := ensureOIDCMetadata(issuer)
		if err != nil {
			return nil, err
		}
		jwksURI = meta.JWKSURI
	}

	req, err := http.NewRequest(http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint returned %d", resp.StatusCode)
	}

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}

	ttl := adminJWKSCacheTTL()
	adminJWKSCache.Lock()
	adminJWKSCache.jwksURI = jwksURI
	adminJWKSCache.keys = jwks.Keys
	adminJWKSCache.expires = time.Now().Add(ttl)
	adminJWKSCache.Unlock()

	return jwks.Keys, nil
}

func adminJWKSCacheTTL() time.Duration {
	ttlSeconds := strings.TrimSpace(os.Getenv("ADMIN_AUTH_JWKS_CACHE_TTL_SECONDS"))
	if ttlSeconds == "" {
		return defaultAdminJWKSCacheTTL
	}
	n, err := strconv.Atoi(ttlSeconds)
	if err != nil || n < 10 {
		return defaultAdminJWKSCacheTTL
	}
	return time.Duration(n) * time.Second
}

func jwkToPublicKey(jwk map[string]interface{}) (interface{}, error) {
	kty, _ := jwk["kty"].(string)
	switch kty {
	case "RSA":
		nStr, _ := jwk["n"].(string)
		eStr, _ := jwk["e"].(string)
		if nStr == "" || eStr == "" {
			return nil, fmt.Errorf("invalid RSA jwk")
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
		if err != nil {
			return nil, err
		}
		n := new(big.Int).SetBytes(nBytes)
		e := 0
		for _, b := range eBytes {
			e = e<<8 + int(b)
		}
		return &rsa.PublicKey{N: n, E: e}, nil
	case "EC":
		crv, _ := jwk["crv"].(string)
		xStr, _ := jwk["x"].(string)
		yStr, _ := jwk["y"].(string)
		if crv == "" || xStr == "" || yStr == "" {
			return nil, fmt.Errorf("invalid EC jwk")
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
		if err != nil {
			return nil, err
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
		if err != nil {
			return nil, err
		}
		var curve elliptic.Curve
		switch crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve")
		}
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key type")
	}
}

func writeAdminUnauthorized(c *gin.Context, description string) {
	if shouldRedirectAdminUnauthorized(c) {
		c.Redirect(http.StatusFound, AdminLoginRedirectURL(c))
		c.Abort()
		return
	}
	c.JSON(http.StatusUnauthorized, gin.H{
		"error":             "unauthorized",
		"error_description": description,
	})
	c.Abort()
}

func writeAdminForbidden(c *gin.Context, description string) {
	c.JSON(http.StatusForbidden, gin.H{
		"error":             "forbidden",
		"error_description": description,
	})
	c.Abort()
}

// AdminLoginRedirectURL builds the OIDC login URL for browser re-authentication.
// Override with ADMIN_AUTH_LOGIN_URL; use {return_url} or %s for the post-login return target.
// When ADMIN_AUTH_CLIENT_ID is set, the default is the in-app client (/admin/login).
// Otherwise the default matches oauth2-proxy: /oauth2/start?rd=<return>&prompt=login
func AdminLoginRedirectURL(c *gin.Context) string {
	returnURL := adminReturnURL(c)
	template := strings.TrimSpace(os.Getenv("ADMIN_AUTH_LOGIN_URL"))
	if template == "" {
		if AdminOIDCClientConfigured() {
			return "/admin/login?rd=" + url.QueryEscape(returnURL)
		}
		return "/oauth2/start?rd=" + url.QueryEscape(returnURL) + "&prompt=login"
	}
	if strings.Contains(template, "{return_url}") {
		return strings.ReplaceAll(template, "{return_url}", url.QueryEscape(returnURL))
	}
	if strings.Contains(template, "%s") {
		return fmt.Sprintf(template, url.QueryEscape(returnURL))
	}
	return template
}

func adminReturnURL(c *gin.Context) string {
	scheme := "https"
	if proto := strings.TrimSpace(c.GetHeader("X-Forwarded-Proto")); proto != "" {
		scheme = proto
	} else if c.Request.TLS == nil {
		scheme = "http"
	}
	host := c.Request.Host
	if h := strings.TrimSpace(c.GetHeader("X-Forwarded-Host")); h != "" {
		host = strings.TrimSpace(strings.Split(h, ",")[0])
	}
	return scheme + "://" + host + c.Request.URL.RequestURI()
}

// shouldRedirectAdminUnauthorized sends browsers to the OIDC login page instead of JSON 401.
func shouldRedirectAdminUnauthorized(c *gin.Context) bool {
	if strings.TrimSpace(os.Getenv("ADMIN_AUTH_ISSUER")) == "" {
		return false
	}
	// Explicit API-key clients should keep JSON error responses.
	if strings.TrimSpace(c.GetHeader("X-API-Key")) != "" {
		return false
	}
	path := c.Request.URL.Path
	if path == "/admin/login" || path == "/admin/callback" || path == "/admin/logoff" {
		return false
	}
	if !strings.HasPrefix(path, "/admin") {
		return false
	}
	accept := c.GetHeader("Accept")
	if strings.Contains(accept, "text/html") {
		return true
	}
	if path == "/admin" && c.Request.Method == http.MethodGet {
		return true
	}
	if ref := c.GetHeader("Referer"); strings.Contains(ref, "/admin") {
		return true
	}
	return false
}
