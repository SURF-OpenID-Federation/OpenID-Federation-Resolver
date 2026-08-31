package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"resolver/pkg/adminv1"
	"resolver/pkg/resolver"

	"github.com/gin-gonic/gin"
)

var adminStore *adminv1.Store

func registerAdminV1(router *gin.Engine) {
	if router == nil {
		return
	}
	openAdminStore()

	g := router.Group("/admin/v1", adminV1AuthMiddleware())
	g.GET("", adminV1Node)
	g.GET("/", adminV1Node)

	g.GET("/configuration", adminV1ConfigRead)
	g.PUT("/configuration", adminV1ConfigReplace)
	g.PATCH("/configuration", adminV1ConfigPatch)
	g.GET("/configuration/statement", adminV1ConfigStatement)

	g.GET("/keys", adminV1KeysList)
	g.POST("/keys", adminV1KeysCreate)
	g.GET("/keys/:kid", adminV1KeysRead)
	g.DELETE("/keys/:kid", adminV1KeysDelete)
	g.POST("/keys/:kid/rotate", adminV1KeysRotate)

	g.GET("/subordinates", adminV1UnsupportedSubordinates)
	g.POST("/subordinates", adminV1UnsupportedSubordinates)
	g.Any("/subordinates/*rest", adminV1UnsupportedSubordinates)

	g.GET("/trust-marks", adminV1UnsupportedTrustMarks)
	g.POST("/trust-marks", adminV1UnsupportedTrustMarks)
	g.Any("/trust-marks/*rest", adminV1UnsupportedTrustMarks)
}

func openAdminStore() {
	if adminStore != nil {
		return
	}
	dataPath := "./data"
	if config != nil && strings.TrimSpace(config.DataPath) != "" {
		dataPath = config.DataPath
	}
	s, err := adminv1.Open(dataPath)
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

func adminV1Node(c *gin.Context) {
	entityID := ""
	kid := ""
	if fedResolver != nil {
		entityID = fedResolver.EntityID()
		kid, _ = fedResolver.SigningKeySummary()
	} else if config != nil {
		entityID = strings.TrimRight(getEnvWithDefault("RESOLVER_ENTITY_ID", "https://resolver.example.org"), "/")
	}
	c.JSON(http.StatusOK, adminv1.NodeDocument{
		EntityID:   strings.TrimRight(entityID, "/"),
		Roles:      []string{adminv1.ResolverRole},
		Base:       adminv1.DefaultBase,
		Spec:       adminv1.Spec,
		SigningKid: kid,
		Implementation: map[string]any{
			"name": adminv1.ImplementationName,
		},
		Capabilities: adminv1.CapabilitiesForResolver(),
	})
}

func adminV1UnsupportedSubordinates(c *gin.Context) {
	adminv1.UnsupportedResource(c, "this node is a resolver and does not implement Immediate Subordinates")
}

func adminV1UnsupportedTrustMarks(c *gin.Context) {
	adminv1.UnsupportedResource(c, "this node is a resolver and does not issue Trust Marks")
}

func requireIfMatch(c *gin.Context, etag string) bool {
	ifMatch := c.GetHeader("If-Match")
	if strings.TrimSpace(ifMatch) == "" {
		return true
	}
	if !adminv1.MatchETag(ifMatch, etag) {
		adminv1.PreconditionFailed(c, "If-Match did not match the current ETag")
		return false
	}
	return true
}

func decodeJSONObject(c *gin.Context) (map[string]any, bool) {
	var body map[string]any
	if err := c.ShouldBindJSON(&body); err != nil {
		adminv1.BadRequest(c, "request body must be a JSON object", "")
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
	return adminv1.HashETag(cp)
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

func overlayLifetime(ov *adminv1.ConfigurationOverlay) time.Duration {
	if ov != nil && ov.Lifetime >= 1 {
		return time.Duration(ov.Lifetime) * time.Second
	}
	return time.Duration(adminv1.DefaultLifetime) * time.Second
}

func applyAdminOverlayToResolver(ov *adminv1.ConfigurationOverlay) error {
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
