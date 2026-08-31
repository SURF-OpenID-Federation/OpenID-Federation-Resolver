// Package admin implements draft-kodden-oidfed-admin-00 document types
// and helpers used by GET/PUT /admin/v1 on this resolver node.
package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

const (
	// SpecID is stored by control-plane discovery when this API is present.
	SpecID = "oidfed-admin-00"
	// Spec is the Node document spec string the control plane classifies on.
	Spec = "draft-kodden-oidfed-admin-00"
	// SpecPrefix matches NodeDocument.spec for discovery.
	SpecPrefix = "draft-kodden-oidfed-admin"
	// DefaultBase is the Administration API mount.
	DefaultBase = "/admin/v1"
	// DefaultPageSize matches the control-plane Admin client.
	DefaultPageSize = 25
	// DefaultLifetime is used when the operator has not set configuration.lifetime.
	DefaultLifetime = int64(86400)
	// ImplementationName is NodeDocument.implementation.name.
	ImplementationName = "openid-federation-resolver"
)

// ResolverRole is the draft role for a node that publishes federation_resolve_endpoint.
const ResolverRole = "resolver"

// NodeDocument is GET /admin/v1 (node.read).
type NodeDocument struct {
	EntityID       string              `json:"entity_id,omitempty"`
	Roles          []string            `json:"roles"`
	Base           string              `json:"base"`
	Spec           string              `json:"spec,omitempty"`
	SigningKid     string              `json:"signing_kid,omitempty"`
	Implementation map[string]any      `json:"implementation,omitempty"`
	Capabilities   map[string][]string `json:"capabilities"`
}

// KeyDocument is one Federation Entity Key.
type KeyDocument struct {
	Kid       string         `json:"kid"`
	Status    string         `json:"status"`
	Signing   bool           `json:"signing,omitempty"`
	Alg       string         `json:"alg,omitempty"`
	Kty       string         `json:"kty,omitempty"`
	PublicJWK map[string]any `json:"public_jwk"`
	CreatedAt int64          `json:"created_at,omitempty"`
	NotAfter  int64          `json:"not_after,omitempty"`
}

// KeyCreateRequest is POST /keys or the rotate body.
type KeyCreateRequest struct {
	Generate    map[string]any `json:"generate,omitempty"`
	Import      map[string]any `json:"import,omitempty"`
	SwitchAfter *int64         `json:"switch_after,omitempty"`
}

// CapabilitiesForResolver is the Node document capabilities map for a resolver-only node.
func CapabilitiesForResolver() map[string][]string {
	return map[string][]string{
		"configuration": {"read", "replace", "patch", "statement"},
		"keys":          {"list", "create", "read", "delete", "rotate"},
		"audit":         {"list"},
	}
}

// ClassifyResponse maps GET /admin/v1 to the control-plane discovery kind.
func ClassifyResponse(status int, body []byte) (kind string, doc *NodeDocument) {
	if status < 200 || status >= 300 {
		return "legacy", nil
	}
	var n NodeDocument
	if err := json.Unmarshal(body, &n); err != nil {
		return "legacy", nil
	}
	if strings.Contains(strings.ToLower(n.Spec), SpecPrefix) || n.Capabilities != nil || (len(n.Roles) > 0 && strings.TrimSpace(n.Base) != "") {
		return SpecID, &n
	}
	return "legacy", &n
}

// ValidSegment is true for a single RFC 3986 path segment (kid).
func ValidSegment(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, "/\\") || strings.Contains(s, "..") {
		return false
	}
	return true
}

// EncodeSegment percent-encodes one path parameter.
func EncodeSegment(s string) string {
	return url.PathEscape(strings.TrimSpace(s))
}

// QuoteETag wraps a hex digest in DQUOTE.
func QuoteETag(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.Trim(raw, `"`)
	if raw == "" {
		return ""
	}
	return `"` + raw + `"`
}

// MatchETag reports whether If-Match matches the current ETag.
func MatchETag(ifMatch, etag string) bool {
	ifMatch = strings.TrimSpace(ifMatch)
	if ifMatch == "" || ifMatch == "*" {
		return true
	}
	return QuoteETag(ifMatch) == QuoteETag(etag)
}

// HashETag is a stable ETag for a JSON-serializable value.
func HashETag(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return QuoteETag("0")
	}
	sum := sha256.Sum256(b)
	return QuoteETag(hex.EncodeToString(sum[:8]))
}

// PageSlice applies limit/cursor to a sorted slice. cursor is a 0-based index.
func PageSlice[T any](items []T, limit int, cursor string) (page []T, next string) {
	if limit <= 0 {
		limit = DefaultPageSize
	}
	start := 0
	if cursor != "" {
		if n, err := strconv.Atoi(cursor); err == nil && n >= 0 {
			start = n
		}
	}
	if start > len(items) {
		start = len(items)
	}
	end := start + limit
	if end > len(items) {
		end = len(items)
	}
	page = items[start:end]
	if end < len(items) {
		next = strconv.Itoa(end)
	}
	return page, next
}

// MergePatch applies RFC 7396 merge-patch of patch onto target (both objects).
func MergePatch(target map[string]any, patch map[string]any) map[string]any {
	if target == nil {
		target = map[string]any{}
	}
	for k, v := range patch {
		if v == nil {
			delete(target, k)
			continue
		}
		if pm, ok := v.(map[string]any); ok {
			if tm, ok := target[k].(map[string]any); ok {
				target[k] = MergePatch(tm, pm)
				continue
			}
		}
		target[k] = v
	}
	return target
}

// EntityIDsEqual compares Entity Identifiers ignoring a trailing slash.
func EntityIDsEqual(a, b string) bool {
	return strings.TrimRight(strings.TrimSpace(a), "/") == strings.TrimRight(strings.TrimSpace(b), "/")
}
