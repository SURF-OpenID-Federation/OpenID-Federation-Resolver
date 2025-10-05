package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"resolver/pkg/metrics"
	"resolver/pkg/resolver"
)

type Config struct {
	Service struct {
		Name     string
		Port     int
		Host     string
		LogLevel string
	}

	Resolver struct {
		MaxRetries         int
		RequestTimeout     time.Duration
		ValidateSignatures bool
		AllowSelfSigned    bool
		ConcurrentFetches  int
	}

	TrustAnchors []string

}

var (
	config      *Config
	fedResolver *resolver.FederationResolver
	startTime   time.Time
	metricsEnabled  bool
	checkTrustAnchors bool

)

func main() {
	startTime = time.Now()

	// Load configuration
	if err := loadConfig(); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize resolver
	resolverConfig, err := buildResolverConfig()
	if err != nil {
		log.Fatalf("Failed to build resolver config: %v", err)
	}

	fedResolver, err = resolver.NewFederationResolver(resolverConfig)
	if err != nil {
		log.Fatalf("Failed to create federation resolver: %v", err)
	}

	// Set up router
	router := gin.Default()

	// Add metrics middleware
	router.Use(func(c *gin.Context) {
		metrics.IncrementActiveConnections()
		defer metrics.DecrementActiveConnections()
		c.Next()
	})

	// Set up routes
	setupRoutes(router)

	// Create HTTP server
	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", config.Service.Host, config.Service.Port),
		Handler: router,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Federation resolver with metrics running on %s:%d", config.Service.Host, config.Service.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Start background metric updater
	go updatePeriodicMetrics()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Give outstanding requests 30 seconds to complete
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exiting")
}

// updatePeriodicMetrics updates metrics that need periodic updates
func updatePeriodicMetrics() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		metrics.UpdateUptime()
	}
}

// setupRoutes configures all the routes
func setupRoutes(router *gin.Engine) {
	// Main page
	router.GET("/", mainPageHandler)

	// Health and metrics
	router.GET("/health", healthHandler)
	router.GET("/metrics", metricsHandler)

	// API v1 routes
	v1 := router.Group("/api/v1")
	{
		// Entity resolution - use query parameter for trust anchor
		v1.GET("/entity/*entityId", resolveEntityHandler)

		// Trust chain resolution
		v1.GET("/trust-chain/*entityId", resolveTrustChainHandler)

		// Testing
		v1.GET("/test/resolve/*entityId", testResolveHandler)

		// Federation list endpoint
		v1.GET("/federation_list", federationListHandler)

		// Configuration
		v1.GET("/trust-anchors", listTrustAnchorsHandler)

		// Cache management
		v1.GET("/cache/stats", cacheStatsHandler)
		v1.GET("/cache/entities", listCachedEntitiesHandler)
		v1.GET("/cache/chains", listCachedChainsHandler)
		v1.GET("/cache/entity/*entityId", getCachedEntityHandler)
		v1.GET("/cache/chain/*entityId", getCachedChainHandler)
		v1.POST("/cache/clear-entities", clearEntityCacheHandler)
		v1.POST("/cache/clear-chains", clearChainCacheHandler)
		v1.POST("/cache/clear-all", clearAllCachesHandler)
		v1.DELETE("/cache/entity/*entityId", removeCachedEntityHandler)
		v1.DELETE("/cache/chain/*entityId", removeCachedChainHandler)
	}

	// Log all registered routes
	for _, route := range router.Routes() {
		log.Printf("[RESOLVER] Registered route: %s %s", route.Method, route.Path)
	}

	// Add catch-all for debugging 404s
	router.NoRoute(func(c *gin.Context) {
		log.Printf("[RESOLVER] 404 - Route not found: %s %s", c.Request.Method, c.Request.URL.Path)
		c.JSON(404, gin.H{
			"error":  "Route not found",
			"method": c.Request.Method,
			"path":   c.Request.URL.Path,
			"query":  c.Request.URL.RawQuery,
		})
	})
}

func loadConfig() error {
	config = &Config{}

	// Service configuration
	config.Service.Name = getEnvWithDefault("SERVICE_NAME", "Federation Resolver")
	config.Service.Port = getEnvIntWithDefault("PORT", 8080)
	config.Service.Host = getEnvWithDefault("HOST", "0.0.0.0")
	config.Service.LogLevel = getEnvWithDefault("LOG_LEVEL", "info")

	// Resolver configuration
	config.Resolver.MaxRetries = getEnvIntWithDefault("MAX_RETRIES", 3)
	requestTimeoutStr := getEnvWithDefault("REQUEST_TIMEOUT", "30s")
	requestTimeout, err := time.ParseDuration(requestTimeoutStr)
	if err != nil {
		return fmt.Errorf("invalid REQUEST_TIMEOUT: %w", err)
	}
	config.Resolver.RequestTimeout = requestTimeout
	config.Resolver.ValidateSignatures = getEnvBoolWithDefault("VALIDATE_SIGNATURES", true)
	config.Resolver.AllowSelfSigned = getEnvBoolWithDefault("ALLOW_SELF_SIGNED", true)
	config.Resolver.ConcurrentFetches = getEnvIntWithDefault("CONCURRENT_FETCHES", 10)

	// Trust anchors
	trustAnchorsStr := os.Getenv("TRUST_ANCHORS")
	if trustAnchorsStr != "" {
		trustAnchors := strings.Split(trustAnchorsStr, ",")
		for i, ta := range trustAnchors {
			trustAnchors[i] = strings.TrimSpace(ta)
		}
		config.TrustAnchors = trustAnchors
		log.Printf("Loaded %d trust anchors from environment", len(config.TrustAnchors))
	} else {
		log.Printf("No TRUST_ANCHORS environment variable set, using empty trust anchors list")
		config.TrustAnchors = []string{}
	}

	// Metrics configuration
	metricsEnabled = getEnvBoolWithDefault("METRICS_ENABLED", true)

	// Health configuration
	checkTrustAnchors = getEnvBoolWithDefault("HEALTH_CHECK_TRUST_ANCHORS", true)

	return nil
}

// Helper functions for environment variable parsing
func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntWithDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBoolWithDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func buildResolverConfig() (*resolver.Config, error) {
	return &resolver.Config{
		MaxRetries:         config.Resolver.MaxRetries,
		RequestTimeout:     config.Resolver.RequestTimeout,
		TrustAnchors:       config.TrustAnchors,
		ValidateSignatures: config.Resolver.ValidateSignatures,
		AllowSelfSigned:    config.Resolver.AllowSelfSigned,
		ConcurrentFetches:  config.Resolver.ConcurrentFetches,
	}, nil
}
