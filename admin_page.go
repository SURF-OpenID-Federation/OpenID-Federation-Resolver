package main

import (
	"html/template"
	"net/http"
	"strings"
	"sync"

	"resolver/pkg/adminauth"

	"github.com/gin-gonic/gin"
)

var (
	adminPageOnce sync.Once
	adminPageTmpl *template.Template
	adminPageErr  error
)

type adminPageData struct {
	EntityName     string
	EntityID       string
	BannerVisible  bool
	BannerIdentity string
	ShowAPIKeyBar  bool
	ServerOIDC     bool
	LoginURL       string
}

func adminPageHandler(c *gin.Context) {
	adminPageOnce.Do(func() {
		adminPageTmpl, adminPageErr = template.ParseFS(staticFS, "static/admin.html")
	})
	if adminPageErr != nil || adminPageTmpl == nil {
		c.String(http.StatusInternalServerError, "admin UI unavailable")
		return
	}
	name := "Federation Resolver"
	entityID := ""
	if config != nil && strings.TrimSpace(config.Service.Name) != "" {
		name = config.Service.Name
	}
	if fedResolver != nil {
		entityID = fedResolver.EntityID()
		if snap := fedResolver.SnapshotConfig(); snap != nil {
			if n := strings.TrimSpace(snap.OrganizationName); n != "" {
				name = n
			}
		}
	} else if config != nil {
		entityID = getEnvWithDefault("RESOLVER_ENTITY_ID", "https://resolver.example.org")
	}
	oidc := adminauth.HasOIDCAdminSession(c)
	banner := adminauth.BannerDisplayNameFromContext(c)
	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := adminPageTmpl.Execute(c.Writer, adminPageData{
		EntityName:     name,
		EntityID:       strings.TrimRight(entityID, "/"),
		BannerVisible:  banner != "",
		BannerIdentity: banner,
		ShowAPIKeyBar:  !oidc,
		ServerOIDC:     oidc,
		LoginURL:       adminauth.AdminBrowserLoginTemplate(),
	}); err != nil {
		c.Status(http.StatusInternalServerError)
	}
}
