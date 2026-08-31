package main

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"resolver/pkg/adminauth"
	"resolver/pkg/apitokens"

	"github.com/gin-gonic/gin"
)

type createPATRequest struct {
	Name    string `json:"name"`
	TTLDays *int   `json:"ttl_days"`
}

func registerTokenAPI(router *gin.Engine) {
	if router == nil {
		return
	}
	g := router.Group("/api/v1/tokens", operatorAuthMiddleware(), adminauth.RequireTokenManage())
	g.GET("", handleListTokens)
	g.POST("", handleCreateToken)
	g.GET("/:id", handleGetToken)
	g.DELETE("/:id", handleRevokeToken)
}

func handleListTokens(c *gin.Context) {
	store := apitokens.Get()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "tokens_unavailable",
			"error_description": "API token store is not initialized",
		})
		return
	}
	now := time.Now()
	c.JSON(http.StatusOK, gin.H{
		"tokens":           store.ListPATs(now),
		"env_api_key_set":  strings.TrimSpace(apiKey) != "",
		"default_ttl_days": apitokens.DefaultTTLDays(),
		"max_ttl_days":     apitokens.MaxTTLDays(),
		"unused_warn_days": apitokens.UnusedWarnDays(),
	})
}

func handleCreateToken(c *gin.Context) {
	store := apitokens.Get()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "tokens_unavailable",
			"error_description": "API token store is not initialized",
		})
		return
	}
	var req createPATRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "JSON body with name is required",
		})
		return
	}
	ttl, err := apitokens.ParseTTLDays(req.TTLDays)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_ttl",
			"error_description": err.Error(),
		})
		return
	}
	plaintext, pub, err := store.CreatePAT(req.Name, ttl, time.Now())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "create_failed",
			"error_description": err.Error(),
		})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"token": plaintext,
		"pat":   pub,
	})
}

func handleGetToken(c *gin.Context) {
	store := apitokens.Get()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "tokens_unavailable",
			"error_description": "API token store is not initialized",
		})
		return
	}
	pub, err := store.GetPAT(c.Param("id"), time.Now())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":             "not_found",
			"error_description": "token not found",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{"pat": pub})
}

func handleRevokeToken(c *gin.Context) {
	store := apitokens.Get()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":             "tokens_unavailable",
			"error_description": "API token store is not initialized",
		})
		return
	}
	pub, err := store.RevokePAT(c.Param("id"), time.Now())
	if err != nil {
		status := http.StatusNotFound
		code := "not_found"
		if !errors.Is(err, apitokens.ErrTokenNotFound) {
			status = http.StatusBadRequest
			code = "revoke_failed"
		}
		c.JSON(status, gin.H{
			"error":             code,
			"error_description": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{"pat": pub})
}
