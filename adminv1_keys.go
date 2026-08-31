package main

import (
	"errors"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"resolver/pkg/adminv1"
	"resolver/pkg/resolver"

	"github.com/gin-gonic/gin"
)

func adminV1KeysList(c *gin.Context) {
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
	page, next := adminv1.PageSlice(items, limit, c.Query("cursor"))
	out := gin.H{"items": page}
	if next != "" {
		out["next"] = next
	}
	c.JSON(http.StatusOK, out)
}

func adminV1KeysRead(c *gin.Context) {
	kid := strings.TrimSpace(c.Param("kid"))
	if !adminv1.ValidSegment(kid) {
		adminv1.BadRequest(c, "kid must be a single path segment", "/kid")
		return
	}
	doc, ok := findKeyDocument(c, kid)
	if !ok {
		adminv1.NotFound(c, "unknown key")
		return
	}
	c.Header("ETag", adminv1.HashETag(doc))
	c.JSON(http.StatusOK, doc)
}

func adminV1KeysCreate(c *gin.Context) {
	var req adminv1.KeyCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil && c.Request.ContentLength > 0 {
		adminv1.BadRequest(c, "request body must be JSON", "")
		return
	}
	if req.Import != nil && req.Generate == nil {
		adminv1.BadRequest(c, "import is not supported; use generate to roll a new ES256 signing key", "/import")
		return
	}
	doc, err := rotateSigningKeyDoc(c)
	if err != nil {
		adminv1.ServerError(c, err.Error())
		return
	}
	c.Header("Location", adminv1.DefaultBase+"/keys/"+adminv1.EncodeSegment(doc.Kid))
	c.Header("ETag", adminv1.HashETag(doc))
	c.JSON(http.StatusCreated, doc)
}

func adminV1KeysRotate(c *gin.Context) {
	kid := strings.TrimSpace(c.Param("kid"))
	if !adminv1.ValidSegment(kid) {
		adminv1.BadRequest(c, "kid must be a single path segment", "/kid")
		return
	}
	if _, ok := findKeyDocument(c, kid); !ok {
		adminv1.NotFound(c, "unknown key")
		return
	}
	var req adminv1.KeyCreateRequest
	_ = c.ShouldBindJSON(&req)
	if req.Import != nil && req.Generate == nil {
		adminv1.BadRequest(c, "import is not supported on rotate; a new ES256 key is generated", "/import")
		return
	}
	doc, err := rotateSigningKeyDoc(c)
	if err != nil {
		adminv1.ServerError(c, err.Error())
		return
	}
	c.Header("Location", adminv1.DefaultBase+"/keys/"+adminv1.EncodeSegment(doc.Kid))
	c.JSON(http.StatusCreated, doc)
}

func adminV1KeysDelete(c *gin.Context) {
	kid := strings.TrimSpace(c.Param("kid"))
	if !adminv1.ValidSegment(kid) {
		adminv1.BadRequest(c, "kid must be a single path segment", "/kid")
		return
	}
	doc, ok := findKeyDocument(c, kid)
	if !ok {
		adminv1.NotFound(c, "unknown key")
		return
	}
	if !requireIfMatch(c, adminv1.HashETag(doc)) {
		return
	}
	if fedResolver == nil {
		adminv1.Conflict(c, "not_initialized", "resolver is not initialized")
		return
	}
	if err := fedResolver.RevokeSigningKey(c.Request.Context(), kid); err != nil {
		if errors.Is(err, resolver.ErrLastSigningKey) {
			adminv1.Conflict(c, "last_signing_key", "cannot delete the last signing key; rotate first")
			return
		}
		if errors.Is(err, resolver.ErrUnknownSigningKey) {
			adminv1.NotFound(c, "unknown key")
			return
		}
		adminv1.ServerError(c, err.Error())
		return
	}
	c.Status(http.StatusNoContent)
}

func rotateSigningKeyDoc(c *gin.Context) (adminv1.KeyDocument, error) {
	if fedResolver == nil {
		return adminv1.KeyDocument{}, errors.New("resolver is not initialized")
	}
	previous, newKid, err := fedResolver.RotateSigningKey(c.Request.Context())
	if err != nil {
		return adminv1.KeyDocument{}, err
	}
	log.Printf("[RESOLVER] admin-v1 key rotation: previous=%s new=%s", previous, newKid)
	doc, ok := findKeyDocument(c, newKid)
	if !ok {
		doc = adminv1.KeyDocument{Kid: newKid, Status: "active", Signing: true, PublicJWK: map[string]any{"kid": newKid}}
	}
	return doc, nil
}

func listKeyDocuments(c *gin.Context) []adminv1.KeyDocument {
	if fedResolver == nil {
		return nil
	}
	info := fedResolver.SigningKeyPublicInfo(c.Request.Context())
	items := make([]adminv1.KeyDocument, 0, len(info.JWKS))
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

func findKeyDocument(c *gin.Context, kid string) (adminv1.KeyDocument, bool) {
	for _, d := range listKeyDocuments(c) {
		if d.Kid == kid {
			return d, true
		}
	}
	return adminv1.KeyDocument{}, false
}

func keyDocFromJWK(jwk map[string]any, status string, signing bool) adminv1.KeyDocument {
	doc := adminv1.KeyDocument{
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
