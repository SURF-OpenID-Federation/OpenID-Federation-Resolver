package main

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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

	DataPath           string
	KeyPath            string
	AdminPort          string
	PublicOnly         bool
	MaxConcurrent      int
	HTTPReadTimeout    time.Duration
	HTTPWriteTimeout   time.Duration
	HTTPIdleTimeout    time.Duration
	CacheMaxEntries    int
	CacheSweepInterval time.Duration
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

	// Create KeyManager (Vault if configured, otherwise file store under KEYS_PATH)
	km, err := newKeyManager()
	if err != nil {
		log.Fatalf("Failed to initialize KeyManager: %v", err)
	}

	fedResolver, err = resolver.NewFederationResolverWithKeyManager(resolverConfig, km)
	if err != nil {
		log.Fatalf("Failed to create federation resolver: %v", err)
	}

	stopJanitor := make(chan struct{})
	fedResolver.StartCacheJanitor(stopJanitor, config.CacheSweepInterval)
	defer close(stopJanitor)

	if config.Service.LogLevel == "debug" || os.Getenv("DEBUG") == "true" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	port := getEnvWithDefault("PORT", "8080")
	publicAddr := fmt.Sprintf("%s:%s", config.Service.Host, port)
	publicRouter := newHTTPEngine()
	if config.PublicOnly {
		setupPublicRoutes(publicRouter)
		setupNoRoute(publicRouter)
		log.Printf("PUBLIC_ONLY: protocol routes only on %s", publicAddr)
	} else if config.AdminPort != "" {
		setupPublicRoutes(publicRouter)
		setupNoRoute(publicRouter)
		log.Printf("Public (federation) listener on %s", publicAddr)
	} else {
		setupRoutes(publicRouter)
	}

	srv := newHTTPServer(publicAddr, publicRouter)
	go func() {
		log.Printf("Federation resolver listening on %s", publicAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	var adminSrv *http.Server
	if config.AdminPort != "" && !config.PublicOnly {
		adminAddr := fmt.Sprintf("%s:%s", config.Service.Host, config.AdminPort)
		adminRouter := newHTTPEngine()
		setupPublicRoutes(adminRouter)
		setupAdminRoutes(adminRouter)
		setupNoRoute(adminRouter)
		adminSrv = newHTTPServer(adminAddr, adminRouter)
		go func() {
			log.Printf("Admin listener (console, ops, TA register, metrics) on %s", adminAddr)
			if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start admin server: %v", err)
			}
		}()
	}

	// Start background metric updater
	go updatePeriodicMetrics()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}
	if adminSrv != nil {
		if err := adminSrv.Shutdown(ctx); err != nil {
			log.Fatal("Admin server forced to shutdown:", err)
		}
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
func newHTTPEngine() *gin.Engine {
	router := gin.New()
	router.Use(gin.Recovery())
	if gin.Mode() == gin.DebugMode {
		router.Use(gin.Logger())
	}

	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOriginFunc = func(string) bool { return true }
	corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"}
	corsConfig.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type", "Authorization", "X-API-Key"}
	corsConfig.AllowCredentials = false
	router.Use(cors.New(corsConfig))

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
	if config != nil && config.MaxConcurrent > 0 {
		router.Use(maxConcurrencyMiddleware(config.MaxConcurrent))
	}
	return router
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	read := 15 * time.Second
	write := 60 * time.Second
	idle := 90 * time.Second
	if config != nil {
		if config.HTTPReadTimeout > 0 {
			read = config.HTTPReadTimeout
		}
		if config.HTTPWriteTimeout > 0 {
			write = config.HTTPWriteTimeout
		}
		if config.HTTPIdleTimeout > 0 {
			idle = config.HTTPIdleTimeout
		}
	}
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       read,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      write,
		IdleTimeout:       idle,
		MaxHeaderBytes:    1 << 20,
	}
}

func setupRoutes(router *gin.Engine) {
	setupPublicRoutes(router)
	setupAdminRoutes(router)
	setupNoRoute(router)
}

func setupPublicRoutes(router *gin.Engine) {
	router.GET("/.well-known/openid-federation", resolverEntityStatementHandler)
	router.GET("/health", healthHandler)

	v1 := router.Group("/api/v1")
	{
		v1.GET("/resolve", federationResolveHandler)
		v1.GET("/federation_list", federationListHandler)
		v1.GET("/collection", federationCollectionHandler)
	}
}

func setupAdminRoutes(router *gin.Engine) {
	staticRoot, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("Failed to load embedded UI: %v", err)
	}
	router.GET("/static/*filepath", gin.WrapH(http.StripPrefix("/static/", http.FileServer(http.FS(staticRoot)))))
	router.GET("/", mainPageHandler)

	if strings.TrimSpace(metricsToken) != "" {
		log.Printf("GET /metrics requires Authorization: Bearer (METRICS_TOKEN is set)")
	}
	router.GET("/metrics", metricsAuthMiddleware(metricsToken), metricsHandler)

	v1 := router.Group("/api/v1")
	{
		v1.GET("/auth/status", authStatusHandler)
		v1.GET("/openapi.json", openAPISpecHandler)
		v1.GET("/docs", swaggerUIHandler)

		v1.GET("/ops", opsSnapshotHandler)
		v1.GET("/test/resolve/*entityId", testResolveHandler)
		v1.GET("/trust-anchors", listTrustAnchorsHandler)
		v1.GET("/registered-trust-anchors", listRegisteredTrustAnchorsHandler)
		v1.GET("/entity/*entityId", resolveEntityHandler)
		v1.GET("/entity-statement/*entityId", resolveEntityRawHandler)
		v1.GET("/trust-chain/*entityId", resolveTrustChainHandler)

		v1.GET("/cache/stats", cacheStatsHandler)
		v1.GET("/cache/entities", listCachedEntitiesHandler)
		v1.GET("/cache/chains", listCachedChainsHandler)
		v1.GET("/cache/entity/*entityId", getCachedEntityHandler)
		v1.GET("/cache/chain/*entityId", getCachedChainHandler)
		v1.GET("/debug/cache/chain/*entityId", debugCachedChainHandler)
		v1.GET("/keys", listSigningKeysHandler)
	}

	operator := v1.Group("")
	operator.Use(operatorAuthMiddleware())
	{
		operator.POST("/cache/clear-entities", clearEntityCacheHandler)
		operator.POST("/cache/clear-chains", clearChainCacheHandler)
		operator.POST("/cache/clear-all", clearAllCachesHandler)
		operator.DELETE("/cache/entity/*entityId", removeCachedEntityHandler)
		operator.DELETE("/cache/chain/*entityId", removeCachedChainHandler)
		operator.POST("/keys/rotate", rotateSigningKeyHandler)
	}

	taAdmin := v1.Group("")
	taAdmin.Use(taAdminAuthMiddleware())
	{
		taAdmin.POST("/register-trust-anchor", registerTrustAnchorHandler)
		taAdmin.DELETE("/registered-trust-anchors/*entityId", unregisterTrustAnchorHandler)
	}

	for _, route := range router.Routes() {
		log.Printf("[RESOLVER] Registered route: %s %s", route.Method, route.Path)
	}
}

func setupNoRoute(router *gin.Engine) {
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
	config.Resolver.AllowSelfSigned = getEnvBoolWithDefault("ALLOW_SELF_SIGNED", false)
	config.Resolver.ConcurrentFetches = getEnvIntWithDefault("CONCURRENT_FETCHES", 10)
	config.Resolver.SkipTLSVerify = getEnvBoolWithDefault("SKIP_TLS_VERIFY", false)
	if config.Resolver.SkipTLSVerify {
		log.Printf("WARNING: SKIP_TLS_VERIFY=true — outbound TLS certificates are not verified")
	}
	if config.Resolver.AllowSelfSigned {
		log.Printf("WARNING: ALLOW_SELF_SIGNED=true")
	}

	config.DataPath = getEnvWithDefault("DATA_PATH", "./data")
	config.KeyPath = resolveKeyPath()
	config.AdminPort = strings.TrimSpace(os.Getenv("ADMIN_PORT"))
	config.PublicOnly = getEnvBoolWithDefault("PUBLIC_ONLY", false)
	config.MaxConcurrent = getEnvIntWithDefault("MAX_CONCURRENT_REQUESTS", 0)
	config.HTTPReadTimeout = getEnvDurationWithDefault("HTTP_READ_TIMEOUT", 15*time.Second)
	config.HTTPWriteTimeout = getEnvDurationWithDefault("HTTP_WRITE_TIMEOUT", 60*time.Second)
	config.HTTPIdleTimeout = getEnvDurationWithDefault("HTTP_IDLE_TIMEOUT", 90*time.Second)
	config.CacheMaxEntries = getEnvIntWithDefault("CACHE_MAX_ENTRIES", 10000)
	config.CacheSweepInterval = getEnvDurationWithDefault("CACHE_SWEEP_INTERVAL", 30*time.Second)

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
	taAPIToken = strings.TrimSpace(os.Getenv("TA_API_KEY"))
	if taAPIToken == "" {
		taAPIToken = strings.TrimSpace(os.Getenv("TA_API_TOKEN"))
	}
	if apiKey != "" {
		log.Printf("Operator APIs (cache mutations, key rotate) require Authorization: Bearer or X-API-Key (API_KEY is set)")
	}
	if taAPIToken != "" {
		log.Printf("Trust-anchor register/unregister require TA_API_KEY")
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

func getEnvDurationWithDefault(key string, defaultValue time.Duration) time.Duration {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		if d, err := time.ParseDuration(value); err == nil && d >= 0 {
			return d
		}
	}
	return defaultValue
}

func parseCommaSeparatedEnv(key string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func firstNonEmptyEnv(keys ...string) string {
	for _, key := range keys {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
	}
	return ""
}

// resolveKeyPath is KEYS_PATH, then KEYS_DIR (KeyManager), default ./keys.
func resolveKeyPath() string {
	if p := firstNonEmptyEnv("KEYS_PATH", "KEYS_DIR"); p != "" {
		return p
	}
	return "./keys"
}

func newKeyManager() (keymanager.AdvancedKeyManager, error) {
	if strings.TrimSpace(os.Getenv("VAULT_ADDR")) != "" && strings.TrimSpace(os.Getenv("VAULT_TOKEN")) != "" {
		return keymanager.NewDefaultKeyManager()
	}
	dir := "./keys"
	if config != nil && strings.TrimSpace(config.KeyPath) != "" {
		dir = config.KeyPath
	} else {
		dir = resolveKeyPath()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create KEYS_PATH %s: %w", dir, err)
	}
	pass := os.Getenv("PASSPHRASE")
	if strings.TrimSpace(pass) == "" {
		log.Printf("WARNING: PASSPHRASE is unset; private keys in %s are encrypted with an empty passphrase. Set PASSPHRASE in production.", dir)
	}
	log.Printf("Resolver signing keys: file store %s", dir)
	return keymanager.NewFileKeyManager(dir, pass), nil
}

func buildResolverConfig() (*resolver.Config, error) {
	negTTL := 10 * time.Minute
	if v := os.Getenv("NEGATIVE_CACHE_TTL_SECONDS"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			negTTL = time.Duration(secs) * time.Second
		}
	}
	entityID := getEnvWithDefault("RESOLVER_ENTITY_ID", "https://resolver.example.org")
	if !strings.HasPrefix(strings.ToLower(entityID), "https://") {
		log.Printf("WARNING: RESOLVER_ENTITY_ID %q does not use the https scheme required by OpenID Federation", entityID)
	}
	return &resolver.Config{
		MaxRetries:         config.Resolver.MaxRetries,
		RequestTimeout:     config.Resolver.RequestTimeout,
		TrustAnchors:       config.TrustAnchors,
		ValidateSignatures: config.Resolver.ValidateSignatures,
		AllowSelfSigned:    config.Resolver.AllowSelfSigned,
		ConcurrentFetches:  config.Resolver.ConcurrentFetches,
		ResolverEntityID:   entityID,
		EnableSigning:      getEnvBoolWithDefault("ENABLE_SIGNING", true),
		OrganizationName:   config.Service.Name,
		AuthorityHints:     parseCommaSeparatedEnv("AUTHORITY_HINTS"),
		SkipTLSVerify:      config.Resolver.SkipTLSVerify,
		URLMappings:        config.URLMappings,
		NegativeCacheTTL:   negTTL,
		RegistryPath:       filepath.Join(config.DataPath, "registered-trust-anchors.json"),
		CacheMaxEntries:    config.CacheMaxEntries,
		CacheSweepInterval: config.CacheSweepInterval,
	}, nil
}
