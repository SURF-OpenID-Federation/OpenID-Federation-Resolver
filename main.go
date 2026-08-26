package main

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/harrykodden/keymanager"
	"resolver/pkg/metrics"
	"resolver/pkg/resolver"
)

type Config struct {
	Service struct {
		Name     string
		Host     string
		LogLevel string
	}

	Resolver struct {
		MaxRetries         int
		RequestTimeout     time.Duration
		ValidateSignatures bool
		AllowSelfSigned    bool
		ConcurrentFetches  int
		SkipTLSVerify      bool
	}

	TrustAnchors []string
	URLMappings  map[string]string
}

var (
	config            *Config
	fedResolver       *resolver.FederationResolver
	startTime         time.Time
	metricsEnabled    bool
	metricsToken      string
	apiKey            string
	taAPIToken        string
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

	// Create KeyManager (backend chosen by env vars)
	km, err := keymanager.NewDefaultKeyManager()
	if err != nil {
		log.Fatalf("Failed to initialize KeyManager: %v", err)
	}

	fedResolver, err = resolver.NewFederationResolverWithKeyManager(resolverConfig, km)
	if err != nil {
		log.Fatalf("Failed to create federation resolver: %v", err)
	}

	// Set up router
	router := gin.Default()

	// Configure CORS middleware
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOriginFunc = func(string) bool { return true }
	corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"}
	corsConfig.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type", "Authorization", "X-API-Key"}
	corsConfig.AllowCredentials = false
	router.Use(cors.New(corsConfig))

	// HTTP caches (browsers, OpenResty, CDNs) must not store API responses.
	// Static console assets may be cached briefly; the in-memory resolver caches stay authoritative.
	router.Use(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/static/") {
			c.Header("Cache-Control", "public, max-age=300")
			c.Next()
			return
		}
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")
		c.Next()
	})

	router.Use(func(c *gin.Context) {
		metrics.IncrementActiveConnections()
		defer metrics.DecrementActiveConnections()
		c.Next()
	})
	router.Use(httpMetricsMiddleware())

	// Set up routes
	setupRoutes(router)

	// Create HTTP server
	port := getEnvWithDefault("PORT", "8080")
	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%s", config.Service.Host, port),
		Handler: router,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Federation resolver with metrics running on %s:%s", config.Service.Host, port)
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
	staticRoot, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("Failed to load embedded UI: %v", err)
	}
	router.GET("/static/*filepath", gin.WrapH(http.StripPrefix("/static/", http.FileServer(http.FS(staticRoot)))))

	router.GET("/", mainPageHandler)

	// Resolver's own entity statement (required for signature verification)
	router.GET("/.well-known/openid-federation", resolverEntityStatementHandler)

	// Health and metrics
	router.GET("/health", healthHandler)
	if strings.TrimSpace(metricsToken) != "" {
		log.Printf("GET /metrics requires Authorization: Bearer (METRICS_TOKEN is set)")
	}
	router.GET("/metrics", metricsAuthMiddleware(metricsToken), metricsHandler)

	v1 := router.Group("/api/v1")
	{
		v1.GET("/auth/status", authStatusHandler)
		v1.GET("/openapi.json", openAPISpecHandler)
		v1.GET("/docs", swaggerUIHandler)
		v1.GET("/resolve", federationResolveHandler)
		v1.GET("/federation_list", federationListHandler)
		v1.GET("/collection", federationCollectionHandler)
	}

	operator := v1.Group("")
	operator.Use(operatorAuthMiddleware())
	{
		operator.GET("/ops", opsSnapshotHandler)
		operator.GET("/entity/*entityId", resolveEntityHandler)
		operator.GET("/entity-statement/*entityId", resolveEntityRawHandler)
		operator.GET("/trust-chain/*entityId", resolveTrustChainHandler)
		operator.GET("/test/resolve/*entityId", testResolveHandler)
		operator.GET("/trust-anchors", listTrustAnchorsHandler)

		operator.GET("/cache/stats", cacheStatsHandler)
		operator.GET("/cache/entities", listCachedEntitiesHandler)
		operator.GET("/cache/chains", listCachedChainsHandler)
		operator.GET("/cache/entity/*entityId", getCachedEntityHandler)
		operator.GET("/cache/chain/*entityId", getCachedChainHandler)
		operator.GET("/debug/cache/chain/*entityId", debugCachedChainHandler)
		operator.POST("/cache/clear-entities", clearEntityCacheHandler)
		operator.POST("/cache/clear-chains", clearChainCacheHandler)
		operator.POST("/cache/clear-all", clearAllCachesHandler)
		operator.DELETE("/cache/entity/*entityId", removeCachedEntityHandler)
		operator.DELETE("/cache/chain/*entityId", removeCachedChainHandler)
	}

	taAdmin := v1.Group("")
	taAdmin.Use(taAdminAuthMiddleware())
	{
		taAdmin.POST("/register-trust-anchor", registerTrustAnchorHandler)
		taAdmin.GET("/registered-trust-anchors", listRegisteredTrustAnchorsHandler)
		taAdmin.DELETE("/registered-trust-anchors/*entityId", unregisterTrustAnchorHandler)
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
	config.Resolver.SkipTLSVerify = getEnvBoolWithDefault("SKIP_TLS_VERIFY", true)

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

	// URL mappings for Docker networking
	urlMappingsStr := os.Getenv("URL_MAPPINGS")
	if urlMappingsStr != "" {
		config.URLMappings = make(map[string]string)
		mappings := strings.Split(urlMappingsStr, ",")
		for _, mapping := range mappings {
			parts := strings.Split(strings.TrimSpace(mapping), "=")
			if len(parts) == 2 {
				externalURL := strings.TrimSpace(parts[0])
				internalURL := strings.TrimSpace(parts[1])
				config.URLMappings[externalURL] = internalURL
				log.Printf("Added URL mapping: %s -> %s", externalURL, internalURL)
			}
		}
		log.Printf("Loaded %d URL mappings from environment", len(config.URLMappings))
	} else {
		log.Printf("No URL_MAPPINGS environment variable set")
		config.URLMappings = nil
	}

	// Metrics configuration
	metricsEnabled = getEnvBoolWithDefault("METRICS_ENABLED", true)
	metricsToken = strings.TrimSpace(os.Getenv("METRICS_TOKEN"))
	apiKey = strings.TrimSpace(os.Getenv("API_KEY"))
	taAPIToken = strings.TrimSpace(os.Getenv("TA_API_TOKEN"))
	if apiKey != "" {
		log.Printf("Operator APIs require Authorization: Bearer or X-API-Key (API_KEY is set)")
	}
	if taAPIToken != "" {
		log.Printf("Trust-anchor admin APIs require TA_API_TOKEN or API_KEY")
	}

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
	negTTL := 10 * time.Minute
	if v := os.Getenv("NEGATIVE_CACHE_TTL_SECONDS"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			negTTL = time.Duration(secs) * time.Second
		}
	}
	return &resolver.Config{
		MaxRetries:         config.Resolver.MaxRetries,
		RequestTimeout:     config.Resolver.RequestTimeout,
		TrustAnchors:       config.TrustAnchors,
		ValidateSignatures: config.Resolver.ValidateSignatures,
		AllowSelfSigned:    config.Resolver.AllowSelfSigned,
		ConcurrentFetches:  config.Resolver.ConcurrentFetches,
		ResolverEntityID:   getEnvWithDefault("RESOLVER_ENTITY_ID", "https://resolver.example.org"),
		EnableSigning:      getEnvBoolWithDefault("ENABLE_SIGNING", true),
		SkipTLSVerify:      config.Resolver.SkipTLSVerify,
		URLMappings:        config.URLMappings,
		NegativeCacheTTL:   negTTL,
	}, nil
}
