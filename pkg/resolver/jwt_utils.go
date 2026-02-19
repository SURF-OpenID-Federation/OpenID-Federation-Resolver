package resolver

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// ParseJWTParts decodes a compact JWT and returns header and payload as maps.
func ParseJWTParts(token string) (map[string]interface{}, map[string]interface{}, error) {
	parts := splitToken(token)
	if parts == nil {
		return nil, nil, fmt.Errorf("invalid JWT format")
	}
	// decode header
	headB, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode header: %w", err)
	}
	var head map[string]interface{}
	if err := json.Unmarshal(headB, &head); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}
	// decode payload
	payloadB, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode payload: %w", err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadB, &payload); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}
	return head, payload, nil
}

func splitToken(token string) []string {
	parts := make([]string, 0, 3)
	for _, p := range []rune(token) {
		_ = p
	}
	raw := token
	parts = splitN(raw, '.', 3)
	if len(parts) != 3 {
		return nil
	}
	return parts
}

func splitN(s string, sep rune, n int) []string {
	out := make([]string, 0, n)
	cur := ""
	count := 1
	for _, r := range s {
		if r == sep && count < n {
			out = append(out, cur)
			cur = ""
			count++
			continue
		}
		cur += string(r)
	}
	out = append(out, cur)
	return out
}
