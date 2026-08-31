package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"resolver/pkg/admin"
	"resolver/pkg/adminauth"

	"github.com/gin-gonic/gin"
)

func handleConfigStatus(c *gin.Context) {
	status, messages := configStatusSnapshot()
	c.JSON(http.StatusOK, gin.H{
		"status":   status,
		"messages": messages,
	})
}

func handleAuthCapabilities(c *gin.Context) {
	configAuth := []string{"api_key", "pat"}
	adminAuth := []string{"api_key", "pat"}
	oidcOut := gin.H{}
	issuer := strings.TrimRight(strings.TrimSpace(os.Getenv("ADMIN_AUTH_ISSUER")), "/")
	if issuer != "" {
		configAuth = append(configAuth, "oidc")
		adminAuth = append(adminAuth, "oidc")
		oidcOut["issuer"] = issuer
		if meta, err := adminauth.DiscoverOIDCMetadata(issuer); err == nil && meta != nil {
			if meta.AuthorizationEndpoint != "" {
				oidcOut["authorization_endpoint"] = meta.AuthorizationEndpoint
			}
			if meta.TokenEndpoint != "" {
				oidcOut["token_endpoint"] = meta.TokenEndpoint
			}
			if meta.UserinfoEndpoint != "" {
				oidcOut["userinfo_endpoint"] = meta.UserinfoEndpoint
			}
			if meta.JWKSURI != "" {
				oidcOut["jwks_uri"] = meta.JWKSURI
			}
		}
		loginHint := strings.TrimSpace(os.Getenv("ADMIN_AUTH_LOGIN_URL"))
		if loginHint == "" {
			if adminauth.AdminOIDCClientConfigured() {
				loginHint = "/admin/login"
			} else {
				loginHint = "/oauth2/start"
			}
		}
		oidcOut["login_hint"] = loginHint
		oidcOut["login_url_template"] = adminauth.AdminBrowserLoginTemplate()
		if adminauth.AdminOIDCClientConfigured() {
			oidcOut["client"] = true
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"config_auth": configAuth,
		"admin_auth":  adminAuth,
		"oidc":        oidcOut,
	})
}

func configStatusSnapshot() (string, []string) {
	cfg := currentRuntimeConfig()
	if err := validateRuntimeConfig(cfg); err != nil {
		return "pending", []string{err.Error()}
	}
	return "ready", []string{}
}

func currentRuntimeConfig() *RuntimeConfig {
	env := envRuntimeConfig()
	if fedResolver == nil {
		return env
	}
	return effectiveFromResolver(env, fedResolver.SnapshotConfig())
}

// bootstrapDay2Config applies the Administration API overlay, importing a legacy
// $DATA_PATH/runtime-config.json once if the admin store has no overlay yet.
func bootstrapDay2Config() {
	openAdminStore()
	if adminStore != nil && adminStore.Configuration() != nil {
		return
	}
	migrateLegacyRuntimeConfig()
}

func migrateLegacyRuntimeConfig() {
	env := envRuntimeConfig()
	path := runtimeConfigPath(env.DataPath)
	stored, err := loadRuntimeConfigFile(path)
	if err != nil {
		log.Printf("[WARN] runtime config load failed (%s): %v", path, err)
		return
	}
	if stored == nil {
		return
	}
	if err := checkIdentityConflict(env, stored.EntityID, stored.ServiceType); err != nil {
		log.Printf("[WARN] ignoring %s: %v", path, err)
		return
	}
	raw, err := json.Marshal(stored)
	if err != nil {
		log.Printf("[WARN] runtime config marshal failed: %v", err)
		return
	}
	merged, err := mergeRuntimeOverlay(env, raw)
	if err != nil {
		log.Printf("[WARN] runtime config merge failed: %v", err)
		return
	}
	if err := validateRuntimeConfig(merged); err != nil {
		log.Printf("[WARN] runtime config invalid (%s): %v — using ENV only", path, err)
		return
	}
	ov := overlayFromRuntime(merged)
	if err := applyAdminOverlayToResolver(ov); err != nil {
		log.Printf("[WARN] runtime config apply failed: %v", err)
		return
	}
	if adminStore == nil {
		openAdminStore()
	}
	if adminStore != nil {
		if err := adminStore.SetConfiguration(ov); err != nil {
			log.Printf("[WARN] failed to import %s into admin store: %v", path, err)
			return
		}
	}
	log.Printf("Imported legacy runtime config from %s into admin-v1 store", path)
}

func overlayFromRuntime(cfg *RuntimeConfig) *admin.ConfigurationOverlay {
	if cfg == nil {
		return &admin.ConfigurationOverlay{}
	}
	fed := map[string]any{}
	if s := strings.TrimSpace(cfg.OrganizationName); s != "" {
		fed["organization_name"] = s
	}
	if s := strings.TrimSpace(cfg.OrganizationURI); s != "" {
		fed["organization_uri"] = s
	}
	if s := strings.TrimSpace(cfg.LogoURI); s != "" {
		fed["logo_uri"] = s
	}
	if len(cfg.Contacts) > 0 {
		fed["contacts"] = append([]string(nil), cfg.Contacts...)
	}
	ov := &admin.ConfigurationOverlay{
		AuthorityHints:   append([]string(nil), cfg.AuthorityHints...),
		TrustAnchorHints: append([]string(nil), cfg.TrustAnchors...),
	}
	if len(fed) > 0 {
		ov.Metadata = map[string]map[string]any{"federation_entity": fed}
	}
	return ov
}
