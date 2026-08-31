package adminauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func resetAdminAuthCaches() {
	adminJWKSCache.Lock()
	adminJWKSCache.keys = nil
	adminJWKSCache.jwksURI = ""
	adminJWKSCache.expires = time.Time{}
	adminJWKSCache.Unlock()
	oidcMetadataCache.Lock()
	oidcMetadataCache.meta = nil
	oidcMetadataCache.issuer = ""
	oidcMetadataCache.expires = time.Time{}
	oidcMetadataCache.Unlock()
}

func TestSafeAdminReturnURL(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	c.Request.Host = "ta.example.com"

	if got := safeAdminReturnURL(c, ""); got != "/admin" {
		t.Fatalf("empty = %q", got)
	}
	if got := safeAdminReturnURL(c, "/admin"); got != "/admin" {
		t.Fatalf("relative = %q", got)
	}
	if got := safeAdminReturnURL(c, "https://ta.example.com/admin"); got != "/admin" {
		t.Fatalf("same host = %q", got)
	}
	if got := safeAdminReturnURL(c, "https://evil.example/admin"); got != "/admin" {
		t.Fatalf("open redirect = %q", got)
	}
	if got := safeAdminReturnURL(c, "/"); got != "/admin" {
		t.Fatalf("non-admin path = %q", got)
	}
	if got := safeAdminReturnURL(c, "//evil.example"); got != "/admin" {
		t.Fatalf("protocol-relative = %q", got)
	}
}

func TestAdminLoginRedirectURL_oidcClient(t *testing.T) {
	t.Setenv("ADMIN_AUTH_LOGIN_URL", "")
	t.Setenv("ADMIN_AUTH_ISSUER", "https://idp.example.com")
	t.Setenv("ADMIN_AUTH_CLIENT_ID", "admin-ui")
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/admin", nil)
	c.Request.Host = "ta.example.com"
	c.Request.Header.Set("X-Forwarded-Proto", "https")

	got := AdminLoginRedirectURL(c)
	if !strings.HasPrefix(got, "/admin/login?rd=") {
		t.Fatalf("URL = %q, want /admin/login", got)
	}
}

func TestAdminBrowserLoginTemplate(t *testing.T) {
	t.Setenv("ADMIN_AUTH_LOGIN_URL", "")
	t.Setenv("ADMIN_AUTH_ISSUER", "")
	t.Setenv("ADMIN_AUTH_CLIENT_ID", "")
	if got := AdminBrowserLoginTemplate(); !strings.HasPrefix(got, "/oauth2/start") {
		t.Fatalf("proxy default = %q", got)
	}
	t.Setenv("ADMIN_AUTH_ISSUER", "https://idp.example.com")
	t.Setenv("ADMIN_AUTH_CLIENT_ID", "admin-ui")
	if got := AdminBrowserLoginTemplate(); got != "/admin/login?rd={return_url}" {
		t.Fatalf("client template = %q", got)
	}
}

func TestHandleAdminOIDCLogin_notConfigured(t *testing.T) {
	t.Setenv("ADMIN_AUTH_ISSUER", "")
	t.Setenv("ADMIN_AUTH_CLIENT_ID", "")
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/admin/login", HandleAdminOIDCLogin)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/login", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestAdminOIDCLoginAndCallback(t *testing.T) {
	resetAdminAuthCaches()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	var pending struct {
		code    string
		idToken string
	}

	op := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 "http://" + r.Host,
				"jwks_uri":               "http://" + r.Host + "/jwks",
				"authorization_endpoint": "http://" + r.Host + "/authorize",
				"token_endpoint":         "http://" + r.Host + "/token",
				"userinfo_endpoint":      "http://" + r.Host + "/userinfo",
				"end_session_endpoint":   "http://" + r.Host + "/logout",
			})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{testRSAJWK(priv)}})
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			if r.Form.Get("code") != pending.code || r.Form.Get("code_verifier") == "" {
				http.Error(w, "bad code", 400)
				return
			}
			if r.Header.Get("Authorization") != "" {
				http.Error(w, `{"error":"invalid_request","error_description":"do not use Basic"}`, 400)
				return
			}
			if r.Form.Get("client_secret") != "secret" || r.Form.Get("client_id") != "admin-ui" {
				http.Error(w, `{"error":"invalid_client","error_description":"Client id or secret not provided"}`, 400)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token": "opaque-at",
				"id_token":     pending.idToken,
				"token_type":   "Bearer",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer op.Close()

	t.Setenv("ADMIN_AUTH_ISSUER", op.URL)
	t.Setenv("ADMIN_AUTH_CLIENT_ID", "admin-ui")
	t.Setenv("ADMIN_AUTH_CLIENT_SECRET", "secret")
	t.Setenv("ADMIN_AUTH_LOGIN_URL", "")
	t.Setenv("PASSPHRASE", "test-passphrase")
	t.Setenv("ADMIN_AUTH_REDIRECT_URI", "")

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/admin/login", HandleAdminOIDCLogin)
	r.GET("/admin/callback", HandleAdminOIDCCallback)
	r.GET("/admin/logoff", HandleAdminOIDCLogoff("/"))

	loginReq := httptest.NewRequest(http.MethodGet, "/admin/login?rd=/admin", nil)
	loginReq.Host = "ta.example.com"
	loginReq.Header.Set("X-Forwarded-Proto", "https")
	loginW := httptest.NewRecorder()
	r.ServeHTTP(loginW, loginReq)
	if loginW.Code != http.StatusFound {
		t.Fatalf("login status = %d body=%s", loginW.Code, loginW.Body.String())
	}
	loc := loginW.Header().Get("Location")
	authURL, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	if authURL.Path != "/authorize" {
		t.Fatalf("authorize path = %s", authURL.Path)
	}
	q := authURL.Query()
	if q.Get("client_id") != "admin-ui" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("authorize query = %s", loc)
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Fatalf("scope = %q", q.Get("scope"))
	}
	if q.Get("redirect_uri") != "https://ta.example.com/admin/callback" {
		t.Fatalf("redirect_uri = %q", q.Get("redirect_uri"))
	}

	stateKey := q.Get("state")
	if _, err := decodeLoginState(stateKey); err == nil {
		t.Fatal("authorize state should be a short key, not the signed blob")
	}
	stored, ok := peekPendingOIDC(stateKey)
	if !ok {
		t.Fatal("expected pending login stored for authorize state")
	}
	if stored.Nonce != q.Get("nonce") {
		t.Fatal("nonce does not match authorize query")
	}

	pending.code = "authz-code"
	idTok, err := signTestIDToken(priv, op.URL, "admin-ui", stored.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	pending.idToken = idTok

	// No state cookie: IdP bounce often drops it. Server store is enough.
	cbReq := httptest.NewRequest(http.MethodGet, "/admin/callback?code=authz-code&state="+url.QueryEscape(stateKey)+"&iss="+url.QueryEscape(op.URL), nil)
	cbReq.Host = "ta.example.com"
	cbReq.Header.Set("X-Forwarded-Proto", "https")
	cbW := httptest.NewRecorder()
	r.ServeHTTP(cbW, cbReq)
	if cbW.Code != http.StatusFound {
		t.Fatalf("callback status = %d body=%s", cbW.Code, cbW.Body.String())
	}
	if cbW.Header().Get("Location") != "/admin" {
		t.Fatalf("callback Location = %q", cbW.Header().Get("Location"))
	}
	if cookieValue(cbW, accessTokenCookieName()) != "opaque-at" {
		t.Fatal("expected access token cookie")
	}
	if cookieValue(cbW, idTokenCookieName()) == "" {
		t.Fatal("expected id token cookie")
	}

	offReq := httptest.NewRequest(http.MethodGet, "/admin/logoff", nil)
	offReq.Host = "ta.example.com"
	offReq.AddCookie(&http.Cookie{Name: idTokenCookieName(), Value: idTok, Path: "/admin"})
	offW := httptest.NewRecorder()
	r.ServeHTTP(offW, offReq)
	if offW.Code != http.StatusFound {
		t.Fatalf("logoff status = %d", offW.Code)
	}
	end, err := url.Parse(offW.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if end.Path != "/logout" || end.Query().Get("id_token_hint") == "" {
		t.Fatalf("end-session Location = %q", offW.Header().Get("Location"))
	}
}

func TestHandleAdminOIDCCallback_stateMismatch(t *testing.T) {
	t.Setenv("ADMIN_AUTH_ISSUER", "https://idp.example.com")
	t.Setenv("ADMIN_AUTH_CLIENT_ID", "admin-ui")
	t.Setenv("PASSPHRASE", "test-passphrase")
	gin.SetMode(gin.TestMode)

	packed, err := encodeLoginState(oidcLoginState{
		State: "good", Nonce: "n", Verifier: "v", ReturnURL: "/admin",
		RedirectURI: "https://ta.example.com/admin/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.GET("/admin/callback", HandleAdminOIDCCallback)
	req := httptest.NewRequest(http.MethodGet, "/admin/callback?code=x&state=bad", nil)
	req.AddCookie(&http.Cookie{Name: adminOIDCStateCookie, Value: packed})
	// cookie fallback still requires the query CSRF to match the blob
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", w.Code)
	}
}

func cookieValue(w *httptest.ResponseRecorder, name string) string {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func testRSAJWK(priv *rsa.PrivateKey) map[string]any {
	n := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.PublicKey.E)).Bytes())
	return map[string]any{"kty": "RSA", "kid": "test", "alg": "RS256", "n": n, "e": e}
}

func signTestIDToken(priv *rsa.PrivateKey, issuer, aud, nonce string) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   issuer,
		"sub":   "user-1",
		"aud":   aud,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"nonce": nonce,
	})
	tok.Header["kid"] = "test"
	return tok.SignedString(priv)
}
