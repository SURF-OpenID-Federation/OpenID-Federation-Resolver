package adminauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const (
	adminOIDCLoginPath    = "/admin/login"
	adminOIDCCallbackPath = "/admin/callback"
	adminOIDCStateCookie  = "oidf_admin_oidc"
	adminOIDCStateTTL     = 10 * time.Minute
)

// AdminOIDCClientConfigured is true when this process can run the authorization-code flow
// (issuer + client_id). oauth2-proxy remains the login front door when this is false.
func AdminOIDCClientConfigured() bool {
	return strings.TrimSpace(os.Getenv("ADMIN_AUTH_ISSUER")) != "" &&
		strings.TrimSpace(os.Getenv("ADMIN_AUTH_CLIENT_ID")) != ""
}

// AdminBrowserLoginTemplate is the login URL advertised to the admin UI and /api/v1/auth/capabilities.
// `{return_url}` is replaced by the current page. Override with ADMIN_AUTH_LOGIN_URL.
func AdminBrowserLoginTemplate() string {
	if t := strings.TrimSpace(os.Getenv("ADMIN_AUTH_LOGIN_URL")); t != "" {
		return t
	}
	if AdminOIDCClientConfigured() {
		return adminOIDCLoginPath + "?rd={return_url}"
	}
	return "/oauth2/start?rd={return_url}&prompt=login"
}

func adminOIDCClientID() string {
	return strings.TrimSpace(os.Getenv("ADMIN_AUTH_CLIENT_ID"))
}

func adminOIDCClientSecret() string {
	return strings.TrimSpace(os.Getenv("ADMIN_AUTH_CLIENT_SECRET"))
}

func idTokenCookieName() string {
	if n := strings.TrimSpace(os.Getenv("ADMIN_AUTH_ID_TOKEN_COOKIE")); n != "" {
		return n
	}
	return "oidf_admin_id"
}

func adminOIDCStateSecret() ([]byte, error) {
	for _, env := range []string{"ADMIN_AUTH_STATE_SECRET", "PASSPHRASE", "SESSION_SECRET"} {
		if s := strings.TrimSpace(os.Getenv(env)); s != "" {
			return []byte(s), nil
		}
	}
	return nil, fmt.Errorf("set ADMIN_AUTH_STATE_SECRET, PASSPHRASE, or SESSION_SECRET to sign login state")
}

func adminOIDCScopes() string {
	if s := strings.TrimSpace(os.Getenv("ADMIN_AUTH_SCOPES")); s != "" {
		return s
	}
	scopes := []string{"openid", "profile", "email"}
	if req := strings.TrimSpace(os.Getenv("ADMIN_AUTH_REQUIRED_SCOPE")); req != "" {
		found := false
		for _, s := range scopes {
			if s == req {
				found = true
				break
			}
		}
		if !found {
			scopes = append(scopes, req)
		}
	}
	return strings.Join(scopes, " ")
}

type oidcLoginState struct {
	State       string `json:"s"`
	Nonce       string `json:"n"`
	Verifier    string `json:"v"`
	ReturnURL   string `json:"r"`
	RedirectURI string `json:"u"`
	IssuedAt    int64  `json:"t"`
}

var pendingOIDC = struct {
	mu sync.Mutex
	m  map[string]oidcLoginState
}{m: make(map[string]oidcLoginState)}

func pendingOIDCPath() string {
	root := strings.TrimSpace(os.Getenv("DATA_PATH"))
	if root == "" {
		return ""
	}
	return filepath.Join(root, "admin-oidc-pending.json")
}

func gcPendingOIDCLocked() {
	now := time.Now()
	for k, st := range pendingOIDC.m {
		if st.IssuedAt == 0 || now.Sub(time.Unix(st.IssuedAt, 0)) > adminOIDCStateTTL {
			delete(pendingOIDC.m, k)
		}
	}
}

func loadPendingOIDCLocked() {
	path := pendingOIDCPath()
	if path == "" {
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var disk map[string]oidcLoginState
	if err := json.Unmarshal(raw, &disk); err != nil {
		return
	}
	if pendingOIDC.m == nil {
		pendingOIDC.m = make(map[string]oidcLoginState)
	}
	for k, st := range disk {
		pendingOIDC.m[k] = st
	}
	gcPendingOIDCLocked()
}

func persistPendingOIDCLocked() {
	path := pendingOIDCPath()
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		log.Printf("[admin-oidc] persist pending: %v", err)
		return
	}
	raw, err := json.Marshal(pendingOIDC.m)
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		log.Printf("[admin-oidc] persist pending: %v", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("[admin-oidc] persist pending: %v", err)
	}
}

func putPendingOIDC(st oidcLoginState) {
	if st.IssuedAt == 0 {
		st.IssuedAt = time.Now().Unix()
	}
	pendingOIDC.mu.Lock()
	defer pendingOIDC.mu.Unlock()
	if pendingOIDC.m == nil {
		pendingOIDC.m = make(map[string]oidcLoginState)
	}
	gcPendingOIDCLocked()
	pendingOIDC.m[st.State] = st
	persistPendingOIDCLocked()
}

func peekPendingOIDC(state string) (*oidcLoginState, bool) {
	state = strings.TrimSpace(state)
	if state == "" {
		return nil, false
	}
	pendingOIDC.mu.Lock()
	defer pendingOIDC.mu.Unlock()
	st, ok := pendingOIDC.m[state]
	if !ok {
		return nil, false
	}
	out := st
	return &out, true
}

func takePendingOIDC(state string) (*oidcLoginState, bool) {
	state = strings.TrimSpace(state)
	if state == "" {
		return nil, false
	}
	pendingOIDC.mu.Lock()
	defer pendingOIDC.mu.Unlock()
	if pendingOIDC.m == nil {
		pendingOIDC.m = make(map[string]oidcLoginState)
	}
	gcPendingOIDCLocked()
	if st, ok := pendingOIDC.m[state]; ok {
		delete(pendingOIDC.m, state)
		persistPendingOIDCLocked()
		return &st, true
	}
	loadPendingOIDCLocked()
	if st, ok := pendingOIDC.m[state]; ok {
		delete(pendingOIDC.m, state)
		persistPendingOIDCLocked()
		return &st, true
	}
	return nil, false
}

func encodeLoginState(st oidcLoginState) (string, error) {
	secret, err := adminOIDCStateSecret()
	if err != nil {
		return "", err
	}
	if st.IssuedAt == 0 {
		st.IssuedAt = time.Now().Unix()
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func decodeLoginState(val string) (*oidcLoginState, error) {
	secret, err := adminOIDCStateSecret()
	if err != nil {
		return nil, err
	}
	parts := strings.Split(val, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("malformed login state")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("malformed login state")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("malformed login state")
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(raw)
	if !hmac.Equal(mac.Sum(nil), sig) {
		return nil, fmt.Errorf("invalid login state")
	}
	var st oidcLoginState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("malformed login state")
	}
	if st.IssuedAt == 0 || time.Since(time.Unix(st.IssuedAt, 0)) > adminOIDCStateTTL {
		return nil, fmt.Errorf("login state expired")
	}
	return &st, nil
}

func randomB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func adminPublicOrigin(c *gin.Context) string {
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
	return scheme + "://" + host
}

func adminOIDCRedirectURI(c *gin.Context) string {
	if u := strings.TrimSpace(os.Getenv("ADMIN_AUTH_REDIRECT_URI")); u != "" {
		return u
	}
	return adminPublicOrigin(c) + adminOIDCCallbackPath
}

func requestHost(c *gin.Context) string {
	if h := strings.TrimSpace(c.GetHeader("X-Forwarded-Host")); h != "" {
		return strings.TrimSpace(strings.Split(h, ",")[0])
	}
	return c.Request.Host
}

func safeAdminReturnURL(c *gin.Context, raw string) string {
	fallback := "/admin"
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		if strings.HasPrefix(raw, "/admin") {
			return raw
		}
		return fallback
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fallback
	}
	if !strings.EqualFold(u.Host, requestHost(c)) {
		return fallback
	}
	if !strings.HasPrefix(u.Path, "/admin") {
		return fallback
	}
	out := u.Path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}

func setLoginStateCookie(c *gin.Context, val string) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     adminOIDCStateCookie,
		Value:    val,
		Path:     "/",
		MaxAge:   int(adminOIDCStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   adminCookieSecure(c),
		SameSite: http.SameSiteLaxMode,
	})
}

func clearLoginStateCookie(c *gin.Context) {
	for _, path := range []string{"/", "/admin"} {
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     adminOIDCStateCookie,
			Value:    "",
			Path:     path,
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   adminCookieSecure(c),
			SameSite: http.SameSiteLaxMode,
		})
	}
}

func setIDTokenCookie(c *gin.Context, rawToken string) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     idTokenCookieName(),
		Value:    rawToken,
		Path:     "/admin",
		MaxAge:   accessTokenCookieMaxAge(),
		HttpOnly: true,
		Secure:   adminCookieSecure(c),
		SameSite: http.SameSiteLaxMode,
	})
}

func clearIDTokenCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     idTokenCookieName(),
		Value:    "",
		Path:     "/admin",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   adminCookieSecure(c),
		SameSite: http.SameSiteLaxMode,
	})
}

func writeOIDCClientHTML(c *gin.Context, status int, msg string) {
	c.Data(status, "text/html; charset=utf-8", []byte(
		"<!doctype html><html><head><meta charset=\"utf-8\"><title>Admin login</title></head>"+
			"<body><p>"+htmlEscape(msg)+"</p><p><a href=\"/admin\">Back to admin</a></p></body></html>"))
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

// HandleAdminOIDCLogin starts the authorization-code + PKCE flow.
func HandleAdminOIDCLogin(c *gin.Context) {
	if !AdminOIDCClientConfigured() {
		writeOIDCClientHTML(c, http.StatusServiceUnavailable, "In-app OIDC login is not configured (set ADMIN_AUTH_ISSUER and ADMIN_AUTH_CLIENT_ID).")
		return
	}
	if _, err := adminOIDCStateSecret(); err != nil {
		writeOIDCClientHTML(c, http.StatusServiceUnavailable, err.Error())
		return
	}
	issuer := strings.TrimRight(strings.TrimSpace(os.Getenv("ADMIN_AUTH_ISSUER")), "/")
	meta, err := ensureOIDCMetadata(issuer)
	if err != nil {
		log.Printf("[admin-oidc] discovery failed: %v", err)
		writeOIDCClientHTML(c, http.StatusBadGateway, "Could not load identity provider metadata.")
		return
	}
	if meta.AuthorizationEndpoint == "" {
		writeOIDCClientHTML(c, http.StatusBadGateway, "Identity provider has no authorization_endpoint.")
		return
	}

	state, err := randomB64(32)
	if err != nil {
		writeOIDCClientHTML(c, http.StatusInternalServerError, "Could not start login.")
		return
	}
	nonce, err := randomB64(32)
	if err != nil {
		writeOIDCClientHTML(c, http.StatusInternalServerError, "Could not start login.")
		return
	}
	verifier, err := randomB64(32)
	if err != nil {
		writeOIDCClientHTML(c, http.StatusInternalServerError, "Could not start login.")
		return
	}

	redirectURI := adminOIDCRedirectURI(c)
	returnURL := safeAdminReturnURL(c, c.Query("rd"))
	st := oidcLoginState{
		State:       state,
		Nonce:       nonce,
		Verifier:    verifier,
		ReturnURL:   returnURL,
		RedirectURI: redirectURI,
	}
	putPendingOIDC(st)
	if packed, err := encodeLoginState(st); err == nil {
		setLoginStateCookie(c, packed)
	}

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", adminOIDCClientID())
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", adminOIDCScopes())
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", pkceChallenge(verifier))
	q.Set("code_challenge_method", "S256")
	if p := strings.TrimSpace(c.Query("prompt")); p != "" {
		q.Set("prompt", p)
	}
	c.Redirect(http.StatusFound, meta.AuthorizationEndpoint+"?"+q.Encode())
}

type oidcTokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// HandleAdminOIDCCallback finishes the authorization-code flow and sets session cookies.
func HandleAdminOIDCCallback(c *gin.Context) {
	if !AdminOIDCClientConfigured() {
		writeOIDCClientHTML(c, http.StatusServiceUnavailable, "In-app OIDC login is not configured.")
		return
	}
	if errParam := strings.TrimSpace(c.Query("error")); errParam != "" {
		desc := strings.TrimSpace(c.Query("error_description"))
		if desc == "" {
			desc = errParam
		}
		clearLoginStateCookie(c)
		writeOIDCClientHTML(c, http.StatusUnauthorized, "Login was denied: "+desc)
		return
	}

	st, err := loadLoginState(c)
	if err != nil {
		log.Printf("[admin-oidc] login state: %v (state_len=%d)", err, len(c.Query("state")))
		writeOIDCClientHTML(c, http.StatusBadRequest, "Login session is missing or expired. Open /admin and sign in again.")
		return
	}
	clearLoginStateCookie(c)
	code := strings.TrimSpace(c.Query("code"))
	if code == "" {
		writeOIDCClientHTML(c, http.StatusBadRequest, "Missing authorization code.")
		return
	}

	tokens, err := exchangeAdminOIDCCode(st, code)
	if err != nil {
		log.Printf("[admin-oidc] token exchange failed: %v", err)
		writeOIDCClientHTML(c, http.StatusBadGateway, "Could not complete login with the identity provider. "+err.Error())
		return
	}
	if strings.TrimSpace(tokens.IDToken) == "" {
		writeOIDCClientHTML(c, http.StatusBadGateway, "Identity provider did not return an ID token.")
		return
	}
	if err := validateAdminIDToken(tokens.IDToken, st.Nonce); err != nil {
		log.Printf("[admin-oidc] id_token invalid: %v", err)
		writeOIDCClientHTML(c, http.StatusUnauthorized, "Identity token was rejected.")
		return
	}
	if strings.TrimSpace(tokens.AccessToken) == "" {
		writeOIDCClientHTML(c, http.StatusBadGateway, "Identity provider did not return an access token.")
		return
	}

	setAccessTokenCookie(c, tokens.AccessToken)
	setIDTokenCookie(c, tokens.IDToken)
	c.Redirect(http.StatusFound, st.ReturnURL)
}

func loadLoginState(c *gin.Context) (*oidcLoginState, error) {
	q := strings.TrimSpace(c.Query("state"))
	if st, ok := takePendingOIDC(q); ok {
		return st, nil
	}
	if st, err := decodeLoginState(q); err == nil {
		return st, nil
	}
	st, err := decodeLoginState(getCookieValue(c, adminOIDCStateCookie))
	if err != nil {
		return nil, fmt.Errorf("no pending login for this callback")
	}
	if subtleConstantTimeString(st.State, q) != 1 {
		return nil, fmt.Errorf("invalid login state")
	}
	return st, nil
}

func subtleConstantTimeString(a, b string) int {
	if len(a) != len(b) {
		// Still compare to keep timing closer when lengths match; mismatch is a failure.
		return 0
	}
	return hmacEqualString(a, b)
}

func hmacEqualString(a, b string) int {
	if hmac.Equal([]byte(a), []byte(b)) {
		return 1
	}
	return 0
}

func exchangeAdminOIDCCode(st *oidcLoginState, code string) (*oidcTokenResponse, error) {
	issuer := strings.TrimRight(strings.TrimSpace(os.Getenv("ADMIN_AUTH_ISSUER")), "/")
	meta, err := ensureOIDCMetadata(issuer)
	if err != nil {
		return nil, err
	}
	if meta.TokenEndpoint == "" {
		return nil, fmt.Errorf("token_endpoint missing in issuer metadata")
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", st.RedirectURI)
	form.Set("client_id", adminOIDCClientID())
	form.Set("code_verifier", st.Verifier)
	// Pocket ID (and many IdPs) use client_secret_post. Basic-only is ignored when
	// client_id is already in the form ("Client id or secret not provided").
	if secret := adminOIDCClientSecret(); secret != "" {
		form.Set("client_secret", secret)
	}

	req, err := http.NewRequest(http.MethodPost, meta.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := adminOIDCHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var tokens oidcTokenResponse
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, fmt.Errorf("token response is not JSON: %w", err)
	}
	if resp.StatusCode != http.StatusOK || tokens.Error != "" {
		desc := tokens.ErrorDesc
		if desc == "" {
			desc = tokens.Error
		}
		if desc == "" {
			desc = strings.TrimSpace(string(body))
		}
		if desc == "" {
			desc = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		log.Printf("[admin-oidc] token POST %s → HTTP %d: %s", meta.TokenEndpoint, resp.StatusCode, desc)
		return nil, fmt.Errorf("token endpoint: %s", desc)
	}
	return &tokens, nil
}

func validateAdminIDToken(rawToken, nonce string) error {
	issuer := strings.TrimRight(strings.TrimSpace(os.Getenv("ADMIN_AUTH_ISSUER")), "/")
	clientID := adminOIDCClientID()
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
	if err := verifyBearerClaims(mapClaims, issuer, clientID, ""); err != nil {
		return err
	}
	gotNonce, _ := mapClaims["nonce"].(string)
	if nonce == "" || gotNonce != nonce {
		return fmt.Errorf("nonce mismatch")
	}
	return nil
}

// HandleAdminOIDCLogoff clears admin session cookies and, when possible, ends the IdP session.
func HandleAdminOIDCLogoff(homeURL string) gin.HandlerFunc {
	if strings.TrimSpace(homeURL) == "" {
		homeURL = "/"
	}
	return func(c *gin.Context) {
		idTok := getCookieValue(c, idTokenCookieName())
		clearAccessTokenCookie(c)
		clearBearerCookie(c)
		clearIDTokenCookie(c)
		clearLoginStateCookie(c)

		if AdminOIDCClientConfigured() && idTok != "" {
			if end := adminEndSessionURL(c, idTok, homeURL); end != "" {
				c.Redirect(http.StatusFound, end)
				return
			}
		}
		c.Redirect(http.StatusFound, homeURL)
	}
}

func adminEndSessionURL(c *gin.Context, idToken, homeURL string) string {
	issuer := strings.TrimRight(strings.TrimSpace(os.Getenv("ADMIN_AUTH_ISSUER")), "/")
	meta, err := ensureOIDCMetadata(issuer)
	if err != nil || meta.EndSessionEndpoint == "" {
		return ""
	}
	postLogout := strings.TrimSpace(os.Getenv("ADMIN_AUTH_POST_LOGOUT_REDIRECT_URI"))
	if postLogout == "" {
		if strings.HasPrefix(homeURL, "http://") || strings.HasPrefix(homeURL, "https://") {
			postLogout = homeURL
		} else {
			postLogout = adminPublicOrigin(c) + "/admin"
		}
	}
	q := url.Values{}
	q.Set("id_token_hint", idToken)
	q.Set("post_logout_redirect_uri", postLogout)
	if cid := adminOIDCClientID(); cid != "" {
		q.Set("client_id", cid)
	}
	return meta.EndSessionEndpoint + "?" + q.Encode()
}
