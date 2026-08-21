package resolver

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"strings"
)

// FetchSubordinateStatement fetches a Subordinate Statement (iss=issuer, sub=subject)
// from the issuer's federation_fetch_endpoint (or {issuer}/fetch as fallback).
func (r *FederationResolver) FetchSubordinateStatement(ctx context.Context, issuerID, subjectID string) (*CachedEntityStatement, error) {
	issuerID = normalizeEntityID(issuerID)
	subjectID = normalizeEntityID(subjectID)
	if issuerID == "" || subjectID == "" {
		return nil, fmt.Errorf("issuer and subject are required for subordinate fetch")
	}

	fetchURL, err := r.resolveFetchEndpoint(ctx, issuerID, subjectID)
	if err != nil {
		return nil, err
	}

	log.Printf("[RESOLVER] Fetching subordinate statement: issuer=%s subject=%s url=%s", issuerID, subjectID, fetchURL)

	body, status, err := r.httpGet(ctx, fetchURL)
	if err != nil {
		return nil, fmt.Errorf("fetch subordinate from %s failed: %w", issuerID, err)
	}
	if status != 200 {
		return nil, fmt.Errorf("fetch subordinate from %s returned status %d", issuerID, status)
	}

	stmt := strings.TrimSpace(string(body))
	if strings.Count(stmt, ".") != 2 {
		return nil, fmt.Errorf("fetch subordinate from %s did not return a JWT", issuerID)
	}

	cached, err := r.parseEntityStatementFromJWT(subjectID, stmt, fetchURL, "")
	if err != nil {
		return nil, fmt.Errorf("failed to parse subordinate statement from %s: %w", issuerID, err)
	}

	if normalizeEntityID(cached.Issuer) != issuerID || normalizeEntityID(cached.Subject) != subjectID {
		return nil, fmt.Errorf("subordinate statement iss/sub mismatch: got iss=%s sub=%s, want iss=%s sub=%s",
			cached.Issuer, cached.Subject, issuerID, subjectID)
	}
	if normalizeEntityID(cached.Issuer) == normalizeEntityID(cached.Subject) {
		return nil, fmt.Errorf("expected subordinate statement (iss!=sub), got self-signed from %s", issuerID)
	}

	return cached, nil
}

// resolveFetchEndpoint returns the URL to fetch a subordinate statement for subjectID
// from issuerID, preferring federation_fetch_endpoint from the issuer EC.
func (r *FederationResolver) resolveFetchEndpoint(ctx context.Context, issuerID, subjectID string) (string, error) {
	issuerEC, err := r.tryDirectResolve(ctx, issuerID)
	if err == nil && issuerEC != nil && issuerEC.ParsedClaims != nil {
		if meta, ok := issuerEC.ParsedClaims["metadata"].(map[string]interface{}); ok {
			if fed, ok := meta["federation_entity"].(map[string]interface{}); ok {
				if ep, ok := fed["federation_fetch_endpoint"].(string); ok && ep != "" {
					return appendSubQuery(ep, subjectID), nil
				}
			}
		}
	} else if err != nil {
		log.Printf("[RESOLVER] Could not load issuer EC for fetch endpoint discovery (%s): %v; using /fetch fallback", issuerID, err)
	}

	return appendSubQuery(strings.TrimRight(issuerID, "/")+"/fetch", subjectID), nil
}

func appendSubQuery(endpoint, subjectID string) string {
	if strings.Contains(endpoint, "?") {
		return endpoint + "&sub=" + url.QueryEscape(subjectID)
	}
	return endpoint + "?sub=" + url.QueryEscape(subjectID)
}
