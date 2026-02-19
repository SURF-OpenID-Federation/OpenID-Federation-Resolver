package resolver

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// httpGet performs a mapped GET request and returns the response body and status code.
// It applies a small retry/backoff for transient network errors.
func (r *FederationResolver) httpGet(ctx context.Context, rawURL string) ([]byte, int, error) {
	mapped := r.mapURL(rawURL)

	// Apply optional per-request timeout from config if set
	var cancel context.CancelFunc
	if r.config != nil && r.config.RequestTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, r.config.RequestTimeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, "GET", mapped, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Determine retries from config with sensible default
	retries := 3
	if r.config != nil && r.config.MaxRetries > 0 {
		retries = r.config.MaxRetries
	}

	// simple retry loop with exponential backoff
	var resp *http.Response
	for attempt := 0; attempt < retries; attempt++ {
		resp, err = r.httpClient.Do(req)
		if err == nil {
			break
		}
		log.Printf("[RESOLVER] httpGet attempt %d/%d failed: %v", attempt+1, retries, err)
		// Exponential backoff: base 100ms * 2^attempt
		backoff := time.Duration(100*(1<<attempt)) * time.Millisecond
		select {
		case <-time.After(backoff):
			// continue
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		}
	}
	if err != nil {
		return nil, 0, fmt.Errorf("request failed after %d retries: %w", retries, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read response body: %w", err)
	}

	return body, resp.StatusCode, nil
}

// FetchWellKnownOpenIDFederation fetches the /.well-known/openid-federation
// document for the provided entity URL and returns the body and the final
// fetched URL (after joining the path). It uses the shared httpGet helper
// which applies URL mapping and retries.
func (r *FederationResolver) FetchWellKnownOpenIDFederation(ctx context.Context, entityID string) (string, string, error) {
	// Construct well-known URL properly to avoid double slashes
	u, err := url.Parse(entityID)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse entity ID URL %s: %w", entityID, err)
	}
	u.Path = path.Join(u.Path, ".well-known", "openid-federation")
	wellKnownURL := u.String()

	body, status, err := r.httpGet(ctx, wellKnownURL)
	if err != nil {
		return "", wellKnownURL, fmt.Errorf("direct resolve request failed: %w", err)
	}

	if status != http.StatusOK {
		return "", wellKnownURL, fmt.Errorf("direct resolve failed with status %d: %s", status, string(body))
	}

	return strings.TrimSpace(string(body)), wellKnownURL, nil
}
