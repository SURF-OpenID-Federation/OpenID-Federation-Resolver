package resolver

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestIsBlockedIP(t *testing.T) {
	cases := []struct {
		ip      string
		blocked bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"192.168.1.1", true},
		{"172.16.5.5", true},
		{"169.254.169.254", true},
		{"0.0.0.0", true},
		{"::1", true},
		{"fc00::1", true},
		{"fe80::1", true},
		{"8.8.8.8", false},
		{"145.100.20.27", false}, // publicly routed; blocked via literal-IP policy instead
		{"1.1.1.1", false},
	}
	for _, tc := range cases {
		got := isBlockedIP(net.ParseIP(tc.ip))
		if got != tc.blocked {
			t.Errorf("isBlockedIP(%s)=%v want %v", tc.ip, got, tc.blocked)
		}
	}
}

func TestValidateFetchURLRejectsLiteralAndPrivate(t *testing.T) {
	cases := []struct {
		raw     string
		allow   bool
		wantErr bool
	}{
		{"http://145.100.20.27/?x=", false, true},
		{"http://127.0.0.1/.well-known/openid-federation", false, true},
		{"http://10.0.0.1/ssrf", false, true},
		{"file:///etc/passwd", false, true},
		{"gopher://evil", false, true},
		{"https://rp.example.org/.well-known/openid-federation", false, false},
		{"http://127.0.0.1:8080/ok", true, false},
	}
	for _, tc := range cases {
		err := validateFetchURL(tc.raw, tc.allow)
		if tc.wantErr && err == nil {
			t.Errorf("validateFetchURL(%q) expected error", tc.raw)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("validateFetchURL(%q) unexpected error: %v", tc.raw, err)
		}
		if tc.wantErr && err != nil && !errors.Is(err, ErrBlockedDestination) {
			t.Errorf("validateFetchURL(%q) error should wrap ErrBlockedDestination: %v", tc.raw, err)
		}
	}
}

func TestHTTPGetBlocksLiteralIP(t *testing.T) {
	res, err := NewFederationResolver(&Config{
		RequestTimeout:       2 * time.Second,
		AllowPrivateNetworks: false,
		MaxRetries:           1,
	})
	if err != nil {
		t.Fatalf("NewFederationResolver: %v", err)
	}

	_, _, err = res.httpGet(context.Background(), "http://145.100.20.27/?x=")
	if err == nil {
		t.Fatal("expected SSRF block for literal public IP")
	}
	if !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("expected ErrBlockedDestination, got %v", err)
	}
}

func TestDirectResolveDoesNotReflectHTML(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html class="html-devise-layout"><head><title>Sign in · GitLab</title></head></html>`)
	}))
	defer srv.Close()

	res, err := NewFederationResolver(&Config{
		RequestTimeout:       2 * time.Second,
		AllowPrivateNetworks: true, // httptest listens on loopback
		ValidateSignatures:   false,
		MaxRetries:           1,
	})
	if err != nil {
		t.Fatalf("NewFederationResolver: %v", err)
	}

	stmt, err := res.ResolveEntityAny(context.Background(), srv.URL, true)
	if err == nil {
		t.Fatalf("expected failure for HTML body, got statement=%q", stmt.Statement)
	}
	if strings.Contains(err.Error(), "Sign in") || strings.Contains(err.Error(), "GitLab") {
		t.Fatalf("error must not reflect upstream HTML: %v", err)
	}
	if stmt != nil && strings.Contains(stmt.Statement, "GitLab") {
		t.Fatal("statement must not contain upstream HTML")
	}
	if hits == 0 {
		t.Fatal("expected at least one fetch attempt")
	}
}

func TestDirectResolveBlocksPrivateWithoutAllow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not be reached when SSRF guard is enabled")
	}))
	defer srv.Close()

	res, err := NewFederationResolver(&Config{
		RequestTimeout:       2 * time.Second,
		AllowPrivateNetworks: false,
		MaxRetries:           1,
	})
	if err != nil {
		t.Fatalf("NewFederationResolver: %v", err)
	}

	_, err = res.ResolveEntityAny(context.Background(), srv.URL, true)
	if err == nil {
		t.Fatal("expected SSRF block against httptest loopback")
	}
	if !errors.Is(err, ErrBlockedDestination) && !strings.Contains(err.Error(), "blocked destination") {
		t.Fatalf("expected blocked destination error, got %v", err)
	}
}

func TestSafeResponseSnippetOmitsBody(t *testing.T) {
	html := []byte(`<html><body>Collaborator response secret-token-xyz</body></html>`)
	got := safeResponseSnippet(html)
	if strings.Contains(got, "secret-token") || strings.Contains(got, "Collaborator") {
		t.Fatalf("snippet leaked body content: %q", got)
	}
	if !strings.Contains(got, "HTML") {
		t.Fatalf("expected HTML hint, got %q", got)
	}

	errJSON := []byte(`{"error":"not_found","error_description":"not a member of this federation"}`)
	got = safeResponseSnippet(errJSON)
	if !strings.Contains(got, "not_found") {
		t.Fatalf("expected error code preserved, got %q", got)
	}
	if strings.Contains(got, "member of this federation") && !strings.Contains(got, "desc=") {
		t.Fatalf("unexpected snippet: %q", got)
	}
}

func TestCheckRedirectBlocksPrivateTarget(t *testing.T) {
	res, err := NewFederationResolver(&Config{
		RequestTimeout:       2 * time.Second,
		AllowPrivateNetworks: false,
		MaxRetries:           1,
	})
	if err != nil {
		t.Fatalf("NewFederationResolver: %v", err)
	}

	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:9/internal", http.StatusFound)
	}))
	defer public.Close()

	// Public server itself is loopback — allow private so the first hop can run,
	// then rely on CheckRedirect + validateFetchURL for the redirect target.
	res.config.AllowPrivateNetworks = true
	res.httpClient = newSafeHTTPClient(&Config{AllowPrivateNetworks: false, RequestTimeout: 2 * time.Second})

	// Re-map: first request must reach public (loopback). With AllowPrivateNetworks
	// false the dialer blocks 127.0.0.1 before redirect. Use a custom client that
	// allows dialing but still validates redirects.
	dialer := &ssrfDialer{
		base:         &net.Dialer{Timeout: 2 * time.Second},
		allowPrivate: true,
	}
	res.httpClient = &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return validateFetchURL(req.URL.String(), false)
		},
	}

	_, _, err = res.httpGet(context.Background(), public.URL)
	if err == nil {
		t.Fatal("expected redirect to loopback to be blocked")
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	if !errors.Is(err, ErrBlockedDestination) && !strings.Contains(err.Error(), "blocked destination") {
		t.Fatalf("expected blocked destination on redirect, got %v", err)
	}
}
