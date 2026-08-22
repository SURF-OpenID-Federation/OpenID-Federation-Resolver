package resolver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
	var secondHits int32
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer slow.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&secondHits, 1)
		http.NotFound(w, r)
	}))
	defer second.Close()

	res, err := NewFederationResolver(&Config{
		TrustAnchors:   []string{slow.URL, second.URL},
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
	if n := atomic.LoadInt32(&secondHits); n != 0 {
		t.Fatalf("probed next trust anchor after context expired: hits=%d", n)
	}
}
