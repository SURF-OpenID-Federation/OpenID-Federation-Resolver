package adminauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAdminLoginRedirectURL_default(t *testing.T) {
	t.Setenv("ADMIN_AUTH_LOGIN_URL", "")
	t.Setenv("ADMIN_AUTH_CLIENT_ID", "")
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/admin", nil)
	c.Request.Host = "ta.example.com"
	c.Request.Header.Set("X-Forwarded-Proto", "https")

	got := AdminLoginRedirectURL(c)
	wantPrefix := "/oauth2/start?rd="
	if got[:len(wantPrefix)] != wantPrefix {
		t.Fatalf("URL = %q, want prefix %q", got, wantPrefix)
	}
	if !strings.Contains(got, "https%3A%2F%2Fta.example.com%2Fadmin") {
		t.Fatalf("URL = %q, want encoded return URL", got)
	}
}

func TestShouldRedirectAdminUnauthorized_browserAdmin(t *testing.T) {
	t.Setenv("ADMIN_AUTH_ISSUER", "https://idp.example.com")
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/admin", nil)
	c.Request.Header.Set("Accept", "text/html,application/xhtml+xml")

	if !shouldRedirectAdminUnauthorized(c) {
		t.Fatal("expected redirect for GET /admin with text/html accept")
	}
}

func TestShouldRedirectAdminUnauthorized_apiKeyClient(t *testing.T) {
	t.Setenv("ADMIN_AUTH_ISSUER", "https://idp.example.com")
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/enrollment/pending", nil)
	c.Request.Header.Set("X-API-Key", "secret")

	if shouldRedirectAdminUnauthorized(c) {
		t.Fatal("expected JSON 401 for explicit X-API-Key client")
	}
}

func TestWriteAdminUnauthorized_redirectsBrowser(t *testing.T) {
	t.Setenv("ADMIN_AUTH_ISSUER", "https://idp.example.com")
	t.Setenv("ADMIN_AUTH_CLIENT_ID", "")
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/admin", nil)
	c.Request.Host = "ta.example.com"
	c.Request.Header.Set("X-Forwarded-Proto", "https")
	c.Request.Header.Set("Accept", "text/html")

	writeAdminUnauthorized(c, "Re-authentication required")

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc == "" || !strings.HasPrefix(loc, "/oauth2/start") {
		t.Fatalf("Location = %q, want oauth2 start redirect", loc)
	}
}
