package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"resolver/pkg/admin"
	"resolver/pkg/resolver"

	"github.com/gin-gonic/gin"
)

var adminStore *admin.Store

func registerAdmin(router *gin.Engine) {
	if router == nil {
		return
	}
	openAdminStore()

	g := router.Group("/admin/v1", adminAuthMiddleware())
	g.GET("", adminNode)
	g.GET("/", adminNode)

	g.GET("/configuration", adminConfigRead)
	g.PUT("/configuration", adminConfigReplace)
	g.PATCH("/configuration", adminConfigPatch)
	g.GET("/configuration/statement", adminConfigStatement)

	g.GET("/keys", adminKeysList)
	g.POST("/keys", adminKeysCreate)
	g.GET("/keys/:kid", adminKeysRead)
	g.DELETE("/keys/:kid", adminKeysDelete)
	g.POST("/keys/:kid/rotate", adminKeysRotate)

	g.GET("/subordinates", adminUnsupportedSubordinates)
	g.POST("/subordinates", adminUnsupportedSubordinates)
	g.Any("/subordinates/*rest", adminUnsupportedSubordinates)

	g.GET("/trust-marks", adminUnsupportedTrustMarks)
	g.POST("/trust-marks", adminUnsupportedTrustMarks)
	g.Any("/trust-marks/*rest", adminUnsupportedTrustMarks)
}

func openAdminStore() {
	if adminStore != nil {
		return
	}
	dataPath := "./data"
	if config != nil && strings.TrimSpace(config.DataPath) != "" {
		dataPath = config.DataPath
	}
	s, err := admin.Open(dataPath)
	if err != nil {
		log.Printf("[WARN] admin-v1 store: %v", err)
		return
	}
	adminStore = s
	if ov := s.Configuration(); ov != nil {
		if err := applyAdminOverlayToResolver(ov); err != nil {
			log.Printf("[WARN] admin-v1 overlay: %v", err)
		}
	}
}

func adminNode(c *gin.Context) {
	entityID := ""
	kid := ""
	if fedResolver != nil {
		entityID = fedResolver.EntityID()
		kid, _ = fedResolver.SigningKeySummary()
	} else if config != nil {
		entityID = strings.TrimRight(getEnvWithDefault("RESOLVER_ENTITY_ID", "https://resolver.example.org"), "/")
	}
	c.JSON(http.StatusOK, admin.NodeDocument{
		EntityID:   strings.TrimRight(entityID, "/"),
		Roles:      []string{admin.ResolverRole},
		Base:       admin.DefaultBase,
		Spec:       admin.Spec,
		SigningKid: kid,
		Implementation: map[string]any{
			"name": admin.ImplementationName,
		},
		Capabilities: admin.CapabilitiesForResolver(),
	})
}

func adminUnsupportedSubordinates(c *gin.Context) {
	admin.UnsupportedResource(c, "this node is a resolver and does not implement Immediate Subordinates")
}

func adminUnsupportedTrustMarks(c *gin.Context) {
	admin.UnsupportedResource(c, "this node is a resolver and does not issue Trust Marks")
}

func requireIfMatch(c *gin.Context, etag string) bool {
	ifMatch := c.GetHeader("If-Match")
	if strings.TrimSpace(ifMatch) == "" {
		return true
	}
	if !admin.MatchETag(ifMatch, etag) {
		admin.PreconditionFailed(c, "If-Match did not match the current ETag")
		return false
	}
	return true
}

func decodeJSONObject(c *gin.Context) (map[string]any, bool) {
	var body map[string]any
	if err := c.ShouldBindJSON(&body); err != nil {
		admin.BadRequest(c, "request body must be a JSON object", "")
		return nil, false
	}
	if body == nil {
		body = map[string]any{}
	}
	return body, true
}

func writeJSONETag(c *gin.Context, status int, doc map[string]any) {
	etag := configETag(doc)
	doc["etag"] = strings.Trim(etag, `"`)
	c.Header("ETag", etag)
	c.JSON(status, doc)
}

func configETag(doc map[string]any) string {
	cp := cloneMap(doc)
	delete(cp, "etag")
	return admin.HashETag(cp)
}

func cloneMap(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	b, err := json.Marshal(in)
	if err != nil {
		out := map[string]any{}
		for k, v := range in {
			out[k] = v
		}
		return out
	}
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	if out == nil {
		return map[string]any{}
	}
	return out
}

func syncMainTrustAnchors() {
	if config == nil || fedResolver == nil {
		return
	}
	if snap := fedResolver.SnapshotConfig(); snap != nil {
		config.TrustAnchors = append([]string(nil), snap.TrustAnchors...)
	}
}

func overlayLifetime(ov *admin.ConfigurationOverlay) time.Duration {
	if ov != nil && ov.Lifetime >= 1 {
		return time.Duration(ov.Lifetime) * time.Second
	}
	return time.Duration(admin.DefaultLifetime) * time.Second
}

func applyAdminOverlayToResolver(ov *admin.ConfigurationOverlay) error {
	if fedResolver == nil || ov == nil {
		return nil
	}
	env := envRuntimeConfig()
	org := env.OrganizationName
	orgURI := env.OrganizationURI
	logo := env.LogoURI
	contacts := append([]string(nil), env.Contacts...)
	if fed := ov.Metadata["federation_entity"]; fed != nil {
		if s, _ := fed["organization_name"].(string); strings.TrimSpace(s) != "" {
			org = s
		}
		if s, _ := fed["organization_uri"].(string); strings.TrimSpace(s) != "" {
			orgURI = s
		}
		if s, _ := fed["logo_uri"].(string); strings.TrimSpace(s) != "" {
			logo = s
		}
		if c, ok := stringSlice(fed["contacts"]); ok {
			contacts = c
		}
	}
	hints := ov.AuthorityHints
	if hints == nil {
		hints = []string{}
	}
	tas := ov.TrustAnchorHints
	if tas == nil {
		tas = append([]string(nil), env.TrustAnchors...)
	}
	fedResolver.ApplyMutableOverlay(resolver.MutableOverlay{
		OrganizationName:        org,
		OrganizationURI:         orgURI,
		LogoURI:                 logo,
		Contacts:                contacts,
		AuthorityHints:          hints,
		TrustAnchors:            tas,
		EntityStatementLifetime: overlayLifetime(ov),
		Crit:                    append([]string(nil), ov.Crit...),
		TrustMarks:              ov.TrustMarks,
		MetadataOverlay:         ov.Metadata,
	})
	syncMainTrustAnchors()
	return nil
}

func stringSlice(v any) ([]string, bool) {
	switch t := v.(type) {
	case []string:
		return append([]string(nil), t...), true
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			s, ok := x.(string)
			if !ok {
				continue
			}
			out = append(out, s)
		}
		return out, true
	default:
		return nil, false
	}
}
