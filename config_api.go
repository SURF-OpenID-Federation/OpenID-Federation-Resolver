package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func registerConfigAPI(router *gin.Engine) {
	auth := router.Group("/api/v1/config")
	auth.Use(operatorAuthMiddleware())
	{
		auth.POST("", handleConfigPost)
	}
}

func handleConfigStatus(c *gin.Context) {
	status, messages := configStatusSnapshot()
	c.JSON(http.StatusOK, gin.H{
		"status":   status,
		"messages": messages,
	})
}

func handleAuthCapabilities(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"config_auth": []string{"api_key"},
		"admin_auth":  []string{"api_key"},
		"oidc":        gin.H{},
	})
}

func handleConfigGet(c *gin.Context) {
	cfg := currentRuntimeConfig()
	status, messages := configStatusSnapshot()
	c.JSON(http.StatusOK, gin.H{
		"status":   status,
		"messages": messages,
		"config":   cfg,
	})
}

func handleConfigPost(c *gin.Context) {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 1<<20))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed_to_read_body", "error_description": err.Error()})
		return
	}
	if err := applyRuntimeConfig(body); err != nil {
		code := http.StatusBadRequest
		errCode := "invalid_config"
		if errors.Is(err, errConfigConflict) {
			errCode = "config_violation"
		}
		c.JSON(code, gin.H{"error": errCode, "error_description": err.Error()})
		return
	}
	cfg := currentRuntimeConfig()
	status, messages := configStatusSnapshot()
	c.JSON(http.StatusOK, gin.H{
		"status":   status,
		"messages": messages,
		"config":   cfg,
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

func applyRuntimeConfig(body []byte) error {
	env := envRuntimeConfig()
	merged, err := mergeRuntimeOverlay(env, body)
	if err != nil {
		return err
	}
	if err := validateRuntimeConfig(merged); err != nil {
		return err
	}
	if fedResolver == nil {
		return fmt.Errorf("resolver not initialized")
	}
	fedResolver.ApplyMutableOverlay(runtimeToMutable(merged))
	path := runtimeConfigPath(env.DataPath)
	if err := saveRuntimeConfigFile(path, merged); err != nil {
		log.Printf("[WARN] failed to persist runtime config to %s: %v", path, err)
	} else {
		log.Printf("Configuration applied; status=ready entity_id=%s", merged.EntityID)
	}
	return nil
}

// bootstrapRuntimeConfig loads $DATA_PATH/runtime-config.json onto the live resolver.
func bootstrapRuntimeConfig() {
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
	if fedResolver != nil {
		fedResolver.ApplyMutableOverlay(runtimeToMutable(merged))
		log.Printf("Loaded runtime config from %s", path)
	}
}
