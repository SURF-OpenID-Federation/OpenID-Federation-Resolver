package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPGetDoesNotRetryCanceledContext(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		<-r.Context().Done()
	}))
	defer srv.Close()

	res, err := NewFederationResolver(&Config{
		RequestTimeout: 2 * time.Second,
		MaxRetries:     3,
	})
	if err != nil {
		t.Fatalf("NewFederationResolver: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	_, _, err = res.httpGet(ctx, srv.URL)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if n := atomic.LoadInt32(&hits); n > 1 {
		t.Fatalf("retried a canceled request: hits=%d", n)
	}
}

func TestResolveEntityAnyStopsWhenContextCanceled(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer slow.Close()

	res, err := NewFederationResolver(&Config{
		TrustAnchors:   []string{slow.URL},
		RequestTimeout: 2 * time.Second,
		MaxRetries:     3,
	})
	if err != nil {
		t.Fatalf("NewFederationResolver: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = res.ResolveEntityAny(ctx, "https://leaf.example", true)
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context error, got %v", err)
	}
}

func TestResolveEntityAnyFallsBackWhenResolveHangs(t *testing.T) {
	leaf := httptest.NewServer(nil)
	defer leaf.Close()
	ta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/resolve" {
			<-r.Context().Done()
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ta.Close()
	leaf.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(unsignedEntityJWT(leaf.URL, leaf.URL, "")))
	})

	res, err := NewFederationResolver(&Config{
		TrustAnchors:       []string{ta.URL},
		RequestTimeout:     10 * time.Second,
		ValidateSignatures: false,
	})
	if err != nil {
		t.Fatalf("NewFederationResolver: %v", err)
	}

	start := time.Now()
	stmt, err := res.ResolveEntityAny(context.Background(), leaf.URL, true)
	if err != nil {
		t.Fatalf("ResolveEntityAny: %v", err)
	}
	if stmt.Subject != leaf.URL {
		t.Fatalf("expected leaf, got %s", stmt.Subject)
	}
	if elapsed := time.Since(start); elapsed > 6*time.Second {
		t.Fatalf("hung /resolve should be abandoned after the probe timeout, took %s", elapsed)
	}
}

func TestResolveEntityAnyUsesTrustChainLeaf(t *testing.T) {
	// Live PoC: TA /resolve returns resolve-response+jwt with trust_chain
	// and no metadata.statement. Do not fall back to well-known.
	ta := httptest.NewServer(nil)
	defer ta.Close()
	leaf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("leaf well-known should not be fetched: %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer leaf.Close()

	leafEC := unsignedEntityJWT(leaf.URL, leaf.URL, fmt.Sprintf(`,"authority_hints":["%s"]`, ta.URL))
	taToLeaf := unsignedEntityJWT(ta.URL, leaf.URL, "")
	resolveJWT := unsignedResolveJWT(ta.URL, leaf.URL, ta.URL, leafEC, taToLeaf)

	var resolveHits int32
	ta.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/resolve" {
			atomic.AddInt32(&resolveHits, 1)
			w.Header().Set("Content-Type", "application/resolve-response+jwt")
			_, _ = w.Write([]byte(resolveJWT))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	res, err := NewFederationResolver(&Config{
		TrustAnchors:       []string{ta.URL},
		RequestTimeout:     2 * time.Second,
		ValidateSignatures: false,
	})
	if err != nil {
		t.Fatalf("NewFederationResolver: %v", err)
	}

	stmt, err := res.ResolveEntityAny(context.Background(), leaf.URL, true)
	if err != nil {
		t.Fatalf("ResolveEntityAny: %v", err)
	}
	if stmt.Issuer != leaf.URL || stmt.Subject != leaf.URL {
		t.Fatalf("expected leaf EC, got iss=%s sub=%s", stmt.Issuer, stmt.Subject)
	}
	if atomic.LoadInt32(&resolveHits) != 1 {
		t.Fatalf("expected 1 /resolve, got %d", resolveHits)
	}
}

func TestResolveEntityAnyCoalescesInFlight(t *testing.T) {
	var resolveHits int32
	started := make(chan struct{})
	release := make(chan struct{})
	ta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/resolve" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		atomic.AddInt32(&resolveHits, 1)
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		sub := r.URL.Query().Get("sub")
		leafEC := unsignedEntityJWT(sub, sub, "")
		_, _ = w.Write([]byte(unsignedResolveJWT("https://ta.example", sub, "https://ta.example", leafEC)))
	}))
	defer ta.Close()

	res, err := NewFederationResolver(&Config{
		TrustAnchors:       []string{ta.URL},
		RequestTimeout:     2 * time.Second,
		ValidateSignatures: false,
	})
	if err != nil {
		t.Fatalf("NewFederationResolver: %v", err)
	}

	const n = 8
	errCh := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := res.ResolveEntityAny(context.Background(), "https://leaf.example", true)
			errCh <- err
		}()
	}
	<-started
	close(release)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Errorf("ResolveEntityAny: %v", err)
		}
	}
	if hits := atomic.LoadInt32(&resolveHits); hits != 1 {
		t.Fatalf("expected 1 coalesced /resolve, got %d", hits)
	}
}

func TestResolveEntityAnyConfiguredTAUsesWellKnown(t *testing.T) {
	var resolveHits int32
	ta := httptest.NewServer(nil)
	defer ta.Close()
	ta.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/resolve" {
			atomic.AddInt32(&resolveHits, 1)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(unsignedEntityJWT(ta.URL, ta.URL, "")))
	})

	res, err := NewFederationResolver(&Config{
		TrustAnchors:       []string{ta.URL},
		RequestTimeout:     2 * time.Second,
		ValidateSignatures: false,
	})
	if err != nil {
		t.Fatalf("NewFederationResolver: %v", err)
	}

	stmt, err := res.ResolveEntityAny(context.Background(), ta.URL, true)
	if err != nil {
		t.Fatalf("ResolveEntityAny: %v", err)
	}
	if stmt.Issuer != ta.URL || stmt.Subject != ta.URL {
		t.Fatalf("expected TA EC, got iss=%s sub=%s", stmt.Issuer, stmt.Subject)
	}
	if atomic.LoadInt32(&resolveHits) != 0 {
		t.Fatalf("configured TA should not be resolved via /resolve, hits=%d", resolveHits)
	}
}

func TestInflightLeaderCancelDoesNotFailWaiters(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	ta := httptest.NewServer(nil)
	defer ta.Close()
	ta.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/.well-known/openid-federation") {
			select {
			case started <- struct{}{}:
			default:
			}
			<-release
			_, _ = w.Write([]byte(unsignedEntityJWT(ta.URL, ta.URL, "")))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	res, err := NewFederationResolver(&Config{
		TrustAnchors:       []string{ta.URL},
		RequestTimeout:     2 * time.Second,
		ValidateSignatures: false,
	})
	if err != nil {
		t.Fatalf("NewFederationResolver: %v", err)
	}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	errCh := make(chan error, 2)
	go func() {
		_, err := res.ResolveEntityAny(leaderCtx, ta.URL, true)
		errCh <- err
	}()
	<-started
	cancelLeader()
	time.Sleep(20 * time.Millisecond)
	go func() {
		_, err := res.ResolveEntityAny(context.Background(), ta.URL, true)
		errCh <- err
	}()
	close(release)
	e1 := <-errCh
	e2 := <-errCh
	if !errors.Is(e1, context.Canceled) && !errors.Is(e2, context.Canceled) {
		t.Fatalf("expected one waiter to see leader cancel, got %v and %v", e1, e2)
	}
	if e1 != nil && e2 != nil {
		t.Fatalf("waiter should succeed after leader cancel, got %v and %v", e1, e2)
	}
}

func TestResolveTrustChainSelfAnchor(t *testing.T) {
	var resolveHits int32
	ta := httptest.NewServer(nil)
	defer ta.Close()
	ta.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/resolve" {
			atomic.AddInt32(&resolveHits, 1)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(unsignedEntityJWT(ta.URL, ta.URL, "")))
	})

	res, err := NewFederationResolver(&Config{
		TrustAnchors:       []string{ta.URL},
		RequestTimeout:     2 * time.Second,
		ValidateSignatures: false,
	})
	if err != nil {
		t.Fatalf("NewFederationResolver: %v", err)
	}

	chain, err := res.ResolveTrustChainWithAnchor(context.Background(), ta.URL, ta.URL, true)
	if err != nil {
		t.Fatalf("ResolveTrustChainWithAnchor: %v", err)
	}
	if chain.Status != "valid" || len(chain.Chain) != 1 {
		t.Fatalf("expected 1-statement TA chain, got status=%s n=%d", chain.Status, len(chain.Chain))
	}
	if atomic.LoadInt32(&resolveHits) != 0 {
		t.Fatalf("self-anchored TA must not call /resolve, hits=%d", resolveHits)
	}
}
