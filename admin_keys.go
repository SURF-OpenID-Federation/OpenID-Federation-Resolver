package main

import (
	"errors"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"resolver/pkg/admin"
	"resolver/pkg/resolver"

	"github.com/gin-gonic/gin"
)

func adminKeysList(c *gin.Context) {
	items := listKeyDocuments(c)
	status := strings.TrimSpace(c.Query("status"))
	if status != "" {
		filtered := items[:0]
		for _, k := range items {
			if k.Status == status {
				filtered = append(filtered, k)
			}
		}
		items = filtered
	}
	limit := 0
	if n, err := strconv.Atoi(c.Query("limit")); err == nil {
		limit = n
	}
	page, next := admin.PageSlice(items, limit, c.Query("cursor"))
	out := gin.H{"items": page}
	if next != "" {
		out["next"] = next
	}
	c.JSON(http.StatusOK, out)
}

func adminKeysRead(c *gin.Context) {
	kid := strings.TrimSpace(c.Param("kid"))
	if !admin.ValidSegment(kid) {
		admin.BadRequest(c, "kid must be a single path segment", "/kid")
		return
	}
	doc, ok := findKeyDocument(c, kid)
	if !ok {
		admin.NotFound(c, "unknown key")
		return
	}
	c.Header("ETag", admin.HashETag(doc))
	c.JSON(http.StatusOK, doc)
}

func adminKeysCreate(c *gin.Context) {
	var req admin.KeyCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil && c.Request.ContentLength > 0 {
		admin.BadRequest(c, "request body must be JSON", "")
		return
	}
	if req.Import != nil && req.Generate == nil {
		admin.BadRequest(c, "import is not supported; use generate to roll a new ES256 signing key", "/import")
		return
	}
	doc, err := rotateSigningKeyDoc(c)
	if err != nil {
		admin.ServerError(c, err.Error())
		return
	}
	c.Header("Location", admin.DefaultBase+"/keys/"+admin.EncodeSegment(doc.Kid))
	c.Header("ETag", admin.HashETag(doc))
	c.JSON(http.StatusCreated, doc)
}

func adminKeysRotate(c *gin.Context) {
	kid := strings.TrimSpace(c.Param("kid"))
	if !admin.ValidSegment(kid) {
		admin.BadRequest(c, "kid must be a single path segment", "/kid")
		return
	}
	if _, ok := findKeyDocument(c, kid); !ok {
		admin.NotFound(c, "unknown key")
		return
	}
	var req admin.KeyCreateRequest
	_ = c.ShouldBindJSON(&req)
	if req.Import != nil && req.Generate == nil {
		admin.BadRequest(c, "import is not supported on rotate; a new ES256 key is generated", "/import")
		return
	}
	doc, err := rotateSigningKeyDoc(c)
	if err != nil {
		admin.ServerError(c, err.Error())
		return
	}
	c.Header("Location", admin.DefaultBase+"/keys/"+admin.EncodeSegment(doc.Kid))
	c.JSON(http.StatusCreated, doc)
}

func adminKeysDelete(c *gin.Context) {
	kid := strings.TrimSpace(c.Param("kid"))
	if !admin.ValidSegment(kid) {
		admin.BadRequest(c, "kid must be a single path segment", "/kid")
		return
	}
	doc, ok := findKeyDocument(c, kid)
	if !ok {
		admin.NotFound(c, "unknown key")
		return
	}
	if !requireIfMatch(c, admin.HashETag(doc)) {
		return
	}
	if fedResolver == nil {
		admin.Conflict(c, "not_initialized", "resolver is not initialized")
		return
	}
	if err := fedResolver.RevokeSigningKey(c.Request.Context(), kid); err != nil {
		if errors.Is(err, resolver.ErrLastSigningKey) {
			admin.Conflict(c, "last_signing_key", "cannot delete the last signing key; rotate first")
			return
		}
		if errors.Is(err, resolver.ErrUnknownSigningKey) {
			admin.NotFound(c, "unknown key")
			return
		}
		admin.ServerError(c, err.Error())
		return
	}
	c.Status(http.StatusNoContent)
}

func rotateSigningKeyDoc(c *gin.Context) (admin.KeyDocument, error) {
	if fedResolver == nil {
		return admin.KeyDocument{}, errors.New("resolver is not initialized")
	}
	previous, newKid, err := fedResolver.RotateSigningKey(c.Request.Context())
	if err != nil {
		return admin.KeyDocument{}, err
	}
	log.Printf("[RESOLVER] admin-v1 key rotation: previous=%s new=%s", previous, newKid)
	doc, ok := findKeyDocument(c, newKid)
	if !ok {
		doc = admin.KeyDocument{Kid: newKid, Status: "active", Signing: true, PublicJWK: map[string]any{"kid": newKid}}
	}
	return doc, nil
}

func listKeyDocuments(c *gin.Context) []admin.KeyDocument {
	if fedResolver == nil {
		return nil
	}
	info := fedResolver.SigningKeyPublicInfo(c.Request.Context())
	items := make([]admin.KeyDocument, 0, len(info.JWKS))
	for _, jwk := range info.JWKS {
		kid, _ := jwk["kid"].(string)
		if kid == "" {
			continue
		}
		signing := kid == info.ActiveKid
		status := "retiring"
		if signing {
			status = "active"
		}
		items = append(items, keyDocFromJWK(jwk, status, signing))
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Signing != items[j].Signing {
			return items[i].Signing
		}
		return items[i].Kid < items[j].Kid
	})
	return items
}

func findKeyDocument(c *gin.Context, kid string) (admin.KeyDocument, bool) {
	for _, d := range listKeyDocuments(c) {
		if d.Kid == kid {
			return d, true
		}
	}
	return admin.KeyDocument{}, false
}

func keyDocFromJWK(jwk map[string]any, status string, signing bool) admin.KeyDocument {
	doc := admin.KeyDocument{
		Status:    status,
		Signing:   signing,
		PublicJWK: jwk,
	}
	if jwk != nil {
		doc.Kid, _ = jwk["kid"].(string)
		doc.Alg, _ = jwk["alg"].(string)
		doc.Kty, _ = jwk["kty"].(string)
	}
	return doc
}
