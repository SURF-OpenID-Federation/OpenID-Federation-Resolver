package resolver

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	cache "resolver/pkg/cache"
)

const defaultNegativeCacheTTL = 10 * time.Minute

// unresolvableEntry is stored in the negative cache for entities that cannot be
// resolved through any configured trust anchor or direct well-known fetch.
type unresolvableEntry struct {
	EntityID  string
	Reason    string
	CachedAt  time.Time
	ExpiresAt time.Time
}

func (r *FederationResolver) negativeCacheTTL() time.Duration {
	if r == nil || r.config == nil || r.config.NegativeCacheTTL <= 0 {
		return defaultNegativeCacheTTL
	}
	return r.config.NegativeCacheTTL
}

func (r *FederationResolver) rememberUnresolvable(entityID string, cause error) {
	if r == nil || entityID == "" || r.negativeCache == nil {
		return
	}
	reason := "unresolvable"
	if cause != nil {
		reason = cause.Error()
	}
	ttl := r.negativeCacheTTL()
	entry := &unresolvableEntry{
		EntityID:  entityID,
		Reason:    reason,
		CachedAt:  time.Now(),
		ExpiresAt: time.Now().Add(ttl),
	}
	r.negativeCache.Set(entityID, entry, ttl)
	log.Printf("[RESOLVER] Negative-cached unresolvable entity %s for %s (%s)", entityID, ttl, truncateForLog(reason, 160))
}

func (r *FederationResolver) getUnresolvable(entityID string) error {
	if r == nil || r.negativeCache == nil || entityID == "" {
		return nil
	}
	v, ok := r.negativeCache.Get(entityID)
	if !ok {
		return nil
	}
	entry, ok := v.(*unresolvableEntry)
	if !ok || entry == nil {
		return nil
	}
	reason := entry.Reason
	if reason == "" {
		reason = "previously failed to resolve"
	}
	log.Printf("[RESOLVER] Negative-cache hit for %s (skipping remote probes)", entityID)
	return fmt.Errorf("entity %s is temporarily marked unresolvable: %s", entityID, reason)
}

func (r *FederationResolver) clearNegativeCache() {
	if r == nil {
		return
	}
	r.negativeCache = cache.NewLimitedCache("unresolvable_entities", cacheLimit(r.config))
}

func truncateForLog(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func isHTTPStatusError(err error, status int) bool {
	if err == nil {
		return false
	}
	needle := fmt.Sprintf("status %d", status)
	return strings.Contains(err.Error(), needle)
}

// isPermanentDirectFailure reports well-known fetches that will not succeed by
// retrying other trust anchors (missing entity configuration).
func isPermanentDirectFailure(err error) bool {
	if err == nil {
		return false
	}
	if isHTTPStatusError(err, http.StatusNotFound) || isHTTPStatusError(err, http.StatusGone) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "cannot get") && strings.Contains(msg, "openid-federation")
}

// isNotFederationMember reports TA /resolve responses that reject the subject
// as outside that federation. Trying another TA may still succeed.
func isNotFederationMember(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not a member of this federation") ||
		strings.Contains(msg, `"error":"not_found"`) ||
		(isHTTPStatusError(err, http.StatusNotFound) && strings.Contains(msg, "federation resolve"))
}

// shouldNegativeCache reports whether a full resolve failure looks stable enough
// to suppress repeated probes for a while.
func shouldNegativeCache(fedErrs []error, directErr error) bool {
	if !isPermanentDirectFailure(directErr) {
		return false
	}
	if len(fedErrs) == 0 {
		return true
	}
	for _, err := range fedErrs {
		if err == nil {
			return false
		}
		msg := strings.ToLower(err.Error())
		// Transient network/5xx should not poison the negative cache.
		if isHTTPStatusError(err, http.StatusBadGateway) ||
			isHTTPStatusError(err, http.StatusServiceUnavailable) ||
			isHTTPStatusError(err, http.StatusGatewayTimeout) ||
			strings.Contains(msg, "timeout") ||
			strings.Contains(msg, "deadline exceeded") ||
			strings.Contains(msg, "connection refused") {
			return false
		}
	}
	return true
}

func combineResolveErrors(fedErrs []error, directErr error) error {
	parts := make([]string, 0, len(fedErrs)+1)
	for _, err := range fedErrs {
		if err != nil {
			parts = append(parts, err.Error())
		}
	}
	if directErr != nil {
		parts = append(parts, "direct: "+directErr.Error())
	}
	if len(parts) == 0 {
		return errors.New("resolve failed")
	}
	return fmt.Errorf("%s", strings.Join(parts, "; "))
}
