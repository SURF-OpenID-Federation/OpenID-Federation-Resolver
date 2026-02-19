package resolver

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strings"
)

// padBase64 adds '=' padding to a base64url string if required for decoding
func padBase64(s string) string {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return s
}

// claimsMapFromJWT decodes a JWT payload without verifying signature, returning claims map.
// Use only for inspection / fallback logic; real verification should be done separately.
func claimsMapFromJWT(jwtStr string) (map[string]interface{}, error) {
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("JWT: unexpected parts count")
	}
	payload := parts[1]
	// base64-url decode with padding fix
	if m := len(payload) % 4; m != 0 {
		payload += strings.Repeat("=", 4-m)
	}
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode payload: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWT payload: %w", err)
	}
	return claims, nil
}

// extractMetadataStatement decodes a resolve-response+jwt payload and returns
// the value of metadata.statement if it exists and looks like a compact JWT.
func extractMetadataStatement(jwtStr string) string {
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		return ""
	}
	pl, err := base64.RawURLEncoding.DecodeString(padBase64(parts[1]))
	if err != nil {
		return ""
	}
	// Attempt normal JSON decode first
	var claims map[string]interface{}
	if err := json.Unmarshal(pl, &claims); err == nil {
		if md, ok := claims["metadata"].(map[string]interface{}); ok {
			if s, ok2 := md["statement"].(string); ok2 && strings.Count(s, ".") == 2 {
				return s
			}
		}
	}

	// Fallback: do a tolerant raw search for a JSON string value named "statement"
	var re = regexp.MustCompile(`"statement"\s*:\s*"([A-Za-z0-9_\-\.=]+)"`)
	if m := re.FindSubmatch(pl); len(m) == 2 {
		s := string(m[1])
		if strings.Count(s, ".") == 2 {
			return s
		}
	}

	return ""
}

// getMapKeys returns the keys of a map[string]interface{} as a slice of strings
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// DeduplicateCachedChain collapses duplicate CachedEntityStatement entries keyed
// by normalized issuer+subject pair (fallback to subject+entity). It preserves
// first-seen order and prefers entries that are validated or that contain
// parsed claims (more authoritative). This avoids dropping subordinate vs leaf
// entries that share the same subject but come from different issuers.
func DeduplicateCachedChain(chain []CachedEntityStatement) []CachedEntityStatement {
	best := make(map[string]CachedEntityStatement)
	order := make([]string, 0, len(chain))
	for _, c := range chain {
		iss := normalizeEntityID(c.Issuer)
		sub := normalizeEntityID(c.Subject)
		if sub == "" {
			sub = normalizeEntityID(c.EntityID)
		}
		if sub == "" {
			// skip entries we cannot key
			continue
		}
		key := iss + "|" + sub
		// If issuer absent, fall back to subject-only key to maintain compatibility
		if iss == "" {
			key = sub
		}

		prev, ok := best[key]
		if !ok {
			best[key] = c
			order = append(order, key)
			continue
		}

		// Prefer validated entries
		if !prev.Validated && c.Validated {
			best[key] = c
			continue
		}

		// Prefer entries that contain parsed claims (likely authoritative)
		if prev.ParsedClaims == nil && c.ParsedClaims != nil {
			best[key] = c
			continue
		}
	}

	deduped := make([]CachedEntityStatement, 0, len(order))
	for _, k := range order {
		deduped = append(deduped, best[k])
	}
	return deduped
}

// normalizeEntityID converts an entity ID into a canonical string for comparisons.
// It parses the URL, lowercases scheme/host, removes default ports (80/443),
// and trims trailing slashes on the path.
func normalizeEntityID(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		// fallback: trim whitespace
		return strings.TrimSpace(raw)
	}

	// Normalize scheme/host
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())

	// Remove default ports from Host:80 or Host:443
	if (u.Scheme == "http" && u.Port() == "80") || (u.Scheme == "https" && u.Port() == "443") {
		u.Host = host
	} else if u.Port() != "" {
		u.Host = host + ":" + u.Port()
	} else {
		u.Host = host
	}

	// Normalize path: drop trailing slash (consistent)
	u.Path = strings.TrimRight(u.Path, "/")

	return fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
}

// mapURL maps external domain URLs to internal service URLs for Docker networking
func (r *FederationResolver) mapURL(inputURL string) string {
	// If no URL mappings are configured, return the URL unchanged
	if r.config.URLMappings == nil {
		log.Printf("[RESOLVER] mapURL: no mappings configured")
		return inputURL
	}

	log.Printf("[RESOLVER] mapURL: input=%s, available mappings: %v", inputURL, r.config.URLMappings)

	// First, check if the full URL matches any mapping key
	if mappedURL, exists := r.config.URLMappings[inputURL]; exists {
		log.Printf("[RESOLVER] Mapped URL %s -> %s", inputURL, mappedURL)
		return mappedURL
	}

	// Check if the input URL starts with any mapping key (prefix matching for base URLs)
	for mappingKey, mappedValue := range r.config.URLMappings {
		if strings.HasPrefix(inputURL, mappingKey) {
			// Replace the prefix with the mapped value
			result := strings.Replace(inputURL, mappingKey, mappedValue, 1)
			log.Printf("[RESOLVER] Mapped URL (prefix match) %s -> %s", inputURL, result)
			return result
		}
	}

	// Fallback: Parse the input URL and check if the host matches any mapping
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		log.Printf("[RESOLVER] Failed to parse URL for mapping: %s, error: %v", inputURL, err)
		return inputURL
	}

	// Check if the host matches any mapping key (either full URL or host-only)
	if mappedHost, exists := r.config.URLMappings[parsedURL.Host]; exists {
		mappedURL := *parsedURL
		mappedURL.Host = mappedHost
		mappedURL.Scheme = "http"
		result := mappedURL.String()

		log.Printf("[RESOLVER] Mapped URL (host fallback) %s -> %s", inputURL, result)
		return result
	}

	for mappingKey, mappedValue := range r.config.URLMappings {
		if parsedKey, err := url.Parse(mappingKey); err == nil {
			if parsedKey.Host == parsedURL.Host {
				mappedURL := *parsedURL
				if parsedValue, err := url.Parse(mappedValue); err == nil {
					mappedURL.Host = parsedValue.Host
					mappedURL.Scheme = parsedValue.Scheme
					result := mappedURL.String()

					log.Printf("[RESOLVER] Mapped URL (full URL host match) %s -> %s", inputURL, result)
					return result
				}
			}
		}
	}

	log.Printf("[RESOLVER] No mapping found for URL: %s, available mappings: %v", inputURL, r.config.URLMappings)
	return inputURL
}
