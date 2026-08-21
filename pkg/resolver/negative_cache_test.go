package resolver

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestResolveEntityAny_NegativeCachesDeadSubordinate(t *testing.T) {
	var resolveHits int32
	var wellKnownHits int32

	ta1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/resolve" {
			atomic.AddInt32(&resolveHits, 1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not_found","error_description":"Subject is not a member of this federation"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ta1.Close()

	ta2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/resolve" {
			atomic.AddInt32(&resolveHits, 1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not_found","error_description":"Subject is not a member of this federation"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ta2.Close()

	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/openid-federation") {
			atomic.AddInt32(&wellKnownHits, 1)
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<pre>Cannot GET /auth/.well-known/openid-federation</pre>`))
			return
		}
		http.NotFound(w, r)
	}))
	defer dead.Close()

	entityID := dead.URL + "/auth"
	cfg := &Config{
		TrustAnchors:       []string{ta1.URL, ta2.URL},
		RequestTimeout:     2 * time.Second,
		ValidateSignatures: false,
		NegativeCacheTTL:   time.Minute,
	}
	r, err := NewFederationResolver(cfg)
	if err != nil {
		t.Fatalf("NewFederationResolver: %v", err)
	}

	ctx := context.Background()
	_, err = r.ResolveEntityAny(ctx, entityID, false)
	if err == nil {
		t.Fatal("expected resolve failure for dead subordinate")
	}
	firstResolves := atomic.LoadInt32(&resolveHits)
	firstWK := atomic.LoadInt32(&wellKnownHits)
	if firstResolves != 2 {
		t.Fatalf("expected 2 federation /resolve probes (one per TA), got %d", firstResolves)
	}
	if firstWK != 1 {
		t.Fatalf("expected exactly 1 direct well-known probe, got %d", firstWK)
	}

	// Second call should hit negative cache: no more remote probes.
	_, err = r.ResolveEntityAny(ctx, entityID, false)
	if err == nil {
		t.Fatal("expected negative-cached failure")
	}
	if !strings.Contains(err.Error(), "temporarily marked unresolvable") {
		t.Fatalf("expected unresolvable cache error, got: %v", err)
	}
	if atomic.LoadInt32(&resolveHits) != firstResolves {
		t.Fatalf("negative cache should skip /resolve; hits %d → %d", firstResolves, atomic.LoadInt32(&resolveHits))
	}
	if atomic.LoadInt32(&wellKnownHits) != firstWK {
		t.Fatalf("negative cache should skip well-known; hits %d → %d", firstWK, atomic.LoadInt32(&wellKnownHits))
	}

	stats := r.GetCacheStats()
	if n, _ := stats["unresolvable_cache_size"].(int); n < 1 {
		t.Fatalf("expected unresolvable cache size >= 1, got %v", stats["unresolvable_cache_size"])
	}
}

func TestResolveEntityAny_StillTriesOtherTAAfterNotMember(t *testing.T) {
	badTA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/resolve" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not_found","error_description":"Subject is not a member of this federation"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer badTA.Close()

	goodTA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer goodTA.Close()
	goodTA.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/resolve" {
			sub := r.URL.Query().Get("sub")
			header := `{"typ":"entity-statement+jwt","alg":"none"}`
			payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":9999999999}`, goodTA.URL, sub)
			jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
				base64.RawURLEncoding.EncodeToString([]byte(payload)) + "."
			w.Header().Set("Content-Type", "application/entity-statement+jwt")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(jwt))
			return
		}
		http.NotFound(w, r)
	})

	cfg := &Config{
		TrustAnchors:       []string{badTA.URL, goodTA.URL},
		RequestTimeout:     2 * time.Second,
		ValidateSignatures: false,
	}
	r, err := NewFederationResolver(cfg)
	if err != nil {
		t.Fatalf("NewFederationResolver: %v", err)
	}

	entityID := "https://leaf.example/op"
	stmt, err := r.ResolveEntityAny(context.Background(), entityID, false)
	if err != nil {
		t.Fatalf("expected success via second TA, got: %v", err)
	}
	if stmt == nil || stmt.Subject != entityID {
		t.Fatalf("unexpected statement: %+v", stmt)
	}
}

func TestShouldNegativeCache(t *testing.T) {
	direct404 := fmt.Errorf("direct resolve failed with status 404: Cannot GET /auth/.well-known/openid-federation")
	notMember := fmt.Errorf(`federation resolve failed with status 404: {"error":"not_found","error_description":"Subject is not a member of this federation"}`)
	timeout := fmt.Errorf("federation resolve request failed: context deadline exceeded")

	if !shouldNegativeCache([]error{notMember, notMember}, direct404) {
		t.Fatal("expected negative cache for not-member + direct 404")
	}
	if shouldNegativeCache([]error{timeout}, direct404) {
		t.Fatal("should not negative-cache when a TA probe timed out")
	}
	if shouldNegativeCache([]error{notMember}, fmt.Errorf("direct resolve request failed: connection refused")) {
		t.Fatal("should not negative-cache transient direct failures")
	}
}
