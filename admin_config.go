package main

import (
	"net/http"
	"strings"

	"resolver/pkg/admin"

	"github.com/gin-gonic/gin"
)

var reservedConfigKeys = map[string]bool{
	"entity_id": true, "lifetime": true, "updated_at": true, "etag": true,
	"authority_hints": true, "trust_anchor_hints": true, "metadata": true,
	"trust_marks": true, "trust_mark_issuers": true, "trust_mark_owners": true, "crit": true,
}

func adminConfigRead(c *gin.Context) {
	writeJSONETag(c, http.StatusOK, buildConfigurationDocument())
}

func adminConfigStatement(c *gin.Context) {
	if fedResolver == nil {
		admin.Conflict(c, "not_initialized", "resolver is not initialized")
		return
	}
	stmt, err := fedResolver.GetResolverEntityStatementWithContext(c.Request.Context())
	if err != nil {
		admin.ServerError(c, err.Error())
		return
	}
	c.Header("Content-Type", "application/entity-statement+jwt")
	c.Header("Cache-Control", "no-store")
	c.String(http.StatusOK, stmt)
}

func adminConfigReplace(c *gin.Context) {
	current := buildConfigurationDocument()
	if !requireIfMatch(c, configETag(current)) {
		return
	}
	body, ok := decodeJSONObject(c)
	if !ok {
		return
	}
	if err := persistConfiguration(body, true); err != nil {
		writeConfigPersistError(c, err)
		return
	}
	writeJSONETag(c, http.StatusOK, buildConfigurationDocument())
}

func adminConfigPatch(c *gin.Context) {
	current := buildConfigurationDocument()
	if !requireIfMatch(c, configETag(current)) {
		return
	}
	patch, ok := decodeJSONObject(c)
	if !ok {
		return
	}
	merged := admin.MergePatch(cloneMap(current), patch)
	delete(merged, "etag")
	delete(merged, "updated_at")
	if err := persistConfiguration(merged, false); err != nil {
		writeConfigPersistError(c, err)
		return
	}
	writeJSONETag(c, http.StatusOK, buildConfigurationDocument())
}

func writeConfigPersistError(c *gin.Context, err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "entity_id"):
		admin.BadRequest(c, msg, "/entity_id")
	case strings.Contains(msg, "trust_mark_issuers") || strings.Contains(msg, "trust_mark_owners"):
		admin.InvalidFederationClaim(c, msg, "")
	case strings.Contains(msg, "federation_fetch_endpoint") || strings.Contains(msg, "federation_list_endpoint"):
		admin.InvalidFederationClaim(c, msg, "/metadata")
	default:
		admin.BadRequest(c, msg, "")
	}
}

func buildConfigurationDocument() map[string]any {
	doc := map[string]any{}
	entityID := ""
	if fedResolver != nil {
		entityID = fedResolver.EntityID()
		snap := fedResolver.SnapshotConfig()
		if snap != nil {
			if len(snap.AuthorityHints) > 0 {
				doc["authority_hints"] = append([]string(nil), snap.AuthorityHints...)
			}
			if len(snap.TrustAnchors) > 0 {
				doc["trust_anchor_hints"] = append([]string(nil), snap.TrustAnchors...)
			}
			if len(snap.Crit) > 0 {
				doc["crit"] = append([]string(nil), snap.Crit...)
			}
			if len(snap.TrustMarks) > 0 {
				doc["trust_marks"] = snap.TrustMarks
			}
			if snap.MetadataOverlay != nil {
				doc["metadata"] = snap.MetadataOverlay
			}
		}
	} else if config != nil {
		if len(config.TrustAnchors) > 0 {
			doc["trust_anchor_hints"] = append([]string(nil), config.TrustAnchors...)
		}
	}
	if entityID == "" {
		entityID = getEnvWithDefault("RESOLVER_ENTITY_ID", "https://resolver.example.org")
	}
	doc["entity_id"] = strings.TrimRight(entityID, "/")
	doc["lifetime"] = admin.DefaultLifetime
	if adminStore != nil {
		if ov := adminStore.Configuration(); ov != nil {
			if ov.Lifetime >= 1 {
				doc["lifetime"] = ov.Lifetime
			}
			if ov.UpdatedAt > 0 {
				doc["updated_at"] = ov.UpdatedAt
			}
			if len(ov.Crit) > 0 {
				doc["crit"] = ov.Crit
			}
			if ov.Metadata != nil {
				doc["metadata"] = ov.Metadata
			}
			if ov.TrustMarks != nil {
				doc["trust_marks"] = ov.TrustMarks
			}
			if ov.AuthorityHints != nil {
				doc["authority_hints"] = ov.AuthorityHints
			}
			if ov.TrustAnchorHints != nil {
				doc["trust_anchor_hints"] = ov.TrustAnchorHints
			}
			for k, v := range ov.Extra {
				if reservedConfigKeys[k] {
					continue
				}
				doc[k] = v
			}
		}
	}
	if _, ok := doc["metadata"]; !ok && fedResolver != nil {
		entityID := strings.TrimRight(fedResolver.EntityID(), "/")
		doc["metadata"] = map[string]any{
			"federation_entity":   liveFederationEntityMetadata(entityID),
			"federation_resolver": liveFederationResolverMetadata(entityID),
		}
	}
	return doc
}

func liveFederationEntityMetadata(entityID string) map[string]any {
	md := map[string]any{
		"federation_resolve_endpoint":    entityID + "/api/v1/resolve",
		"federation_collection_endpoint": entityID + "/api/v1/collection",
	}
	name := "Federation Resolver"
	if fedResolver != nil {
		if snap := fedResolver.SnapshotConfig(); snap != nil {
			if n := strings.TrimSpace(snap.OrganizationName); n != "" {
				name = n
			}
			if u := strings.TrimSpace(snap.OrganizationURI); u != "" {
				md["organization_uri"] = u
			}
			if u := strings.TrimSpace(snap.LogoURI); u != "" {
				md["logo_uri"] = u
			}
			if len(snap.Contacts) > 0 {
				md["contacts"] = append([]string(nil), snap.Contacts...)
			}
		}
	}
	md["organization_name"] = name
	return md
}

func liveFederationResolverMetadata(entityID string) map[string]any {
	return map[string]any{
		"federation_resolve_endpoint":    entityID + "/api/v1/resolve",
		"federation_collection_endpoint": entityID + "/api/v1/collection",
	}
}

func persistConfiguration(body map[string]any, replace bool) error {
	env := envRuntimeConfig()
	lockedID := strings.TrimRight(env.EntityID, "/")
	if raw, ok := body["entity_id"].(string); ok && strings.TrimSpace(raw) != "" && !admin.EntityIDsEqual(raw, lockedID) {
		return errString("entity_id cannot be changed after initialization")
	}
	if _, ok := body["trust_mark_issuers"]; ok {
		return errString("trust_mark_issuers is only valid on a trust_anchor")
	}
	if _, ok := body["trust_mark_owners"]; ok {
		return errString("trust_mark_owners is only valid on a trust_anchor")
	}
	if err := rejectSuperiorEndpoints(body["metadata"]); err != nil {
		return err
	}

	ov := &admin.ConfigurationOverlay{}
	if !replace && adminStore != nil {
		if cur := adminStore.Configuration(); cur != nil {
			cp := *cur
			ov = &cp
		}
	}
	if v, ok := int64Val(body["lifetime"]); ok {
		if v < 1 {
			return errString("lifetime must be a positive number of seconds")
		}
		ov.Lifetime = v
	} else if replace {
		ov.Lifetime = admin.DefaultLifetime
	}
	if v, exists := body["authority_hints"]; exists {
		ov.AuthorityHints, _ = stringSlice(v)
	} else if replace {
		ov.AuthorityHints = []string{}
	}
	if v, exists := body["trust_anchor_hints"]; exists {
		ov.TrustAnchorHints, _ = stringSlice(v)
	} else if replace {
		ov.TrustAnchorHints = []string{}
	}
	if v, exists := body["crit"]; exists {
		ov.Crit, _ = stringSlice(v)
	} else if replace {
		ov.Crit = nil
	}
	if v, exists := body["metadata"]; exists {
		ov.Metadata = asTypeMetadata(v)
	} else if replace {
		ov.Metadata = nil
	}
	if v, exists := body["trust_marks"]; exists {
		ov.TrustMarks = asObjectSlice(v)
	} else if replace {
		ov.TrustMarks = nil
	}
	extra := map[string]any{}
	for k, v := range body {
		if reservedConfigKeys[k] {
			continue
		}
		extra[k] = v
	}
	ov.Extra = extra

	if err := applyAdminOverlayToResolver(ov); err != nil {
		return err
	}
	if adminStore == nil {
		openAdminStore()
	}
	if adminStore != nil {
		return adminStore.SetConfiguration(ov)
	}
	return nil
}

func rejectSuperiorEndpoints(v any) error {
	raw, ok := v.(map[string]any)
	if !ok || raw == nil {
		return nil
	}
	for _, typ := range []string{"federation_entity", "federation_resolver"} {
		inner, _ := raw[typ].(map[string]any)
		if inner == nil {
			continue
		}
		if _, ok := inner["federation_fetch_endpoint"]; ok {
			return errString("federation_fetch_endpoint is not valid on a resolver")
		}
		if _, ok := inner["federation_list_endpoint"]; ok {
			return errString("federation_list_endpoint is not valid on a resolver")
		}
	}
	return nil
}

type errString string

func (e errString) Error() string { return string(e) }

func int64Val(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	default:
		return 0, false
	}
}

func asTypeMetadata(v any) map[string]map[string]any {
	raw, ok := v.(map[string]any)
	if !ok || raw == nil {
		return nil
	}
	out := make(map[string]map[string]any, len(raw))
	for k, inner := range raw {
		im, ok := inner.(map[string]any)
		if !ok {
			continue
		}
		out[k] = im
	}
	return out
}

func asObjectSlice(v any) []map[string]any {
	switch t := v.(type) {
	case []map[string]any:
		return t
	case []any:
		out := make([]map[string]any, 0, len(t))
		for _, x := range t {
			if m, ok := x.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	default:
		return nil
	}
}
