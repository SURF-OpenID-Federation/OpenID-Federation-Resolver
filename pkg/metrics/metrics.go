package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	startTime = time.Now()

	// Request metrics
	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "federation_resolver_requests_total",
			Help: "Total HTTP requests",
		},
		[]string{"method", "endpoint", "status"},
	)

	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "federation_resolver_request_duration_seconds",
			Help: "HTTP request duration",
		},
		[]string{"method", "endpoint"},
	)

	// Entity resolution metrics
	EntityResolutions = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "federation_resolver_entity_resolutions_total",
			Help: "Entity resolution attempts",
		},
		[]string{"entity_id", "trust_anchor", "status"},
	)

	EntityResolutionDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "federation_resolver_entity_resolution_duration_seconds",
			Help: "Entity resolution duration",
		},
		[]string{"entity_id", "trust_anchor"},
	)

	// Trust chain metrics
	TrustChainResolutions = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "federation_resolver_trust_chain_resolutions_total",
			Help: "Trust chain resolution attempts",
		},
		[]string{"entity_id", "trust_anchor", "status"},
	)

	// System metrics
	ActiveConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "federation_resolver_active_connections",
			Help: "Active connections",
		},
	)

	UptimeSeconds = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "federation_resolver_uptime_seconds",
			Help: "Uptime in seconds",
		},
	)

	ErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "federation_resolver_errors_total",
			Help: "Total errors",
		},
		[]string{"error_type", "operation"},
	)

	// Cache metrics
	CacheSize = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "federation_resolver_cache_size",
			Help: "Cache size by cache name",
		},
		[]string{"cache_name"},
	)
)

// Helper functions
func RecordHTTPRequest(method, endpoint string, statusCode int, duration time.Duration) {
	HTTPRequestsTotal.WithLabelValues(method, endpoint, string(rune(statusCode))).Inc()
	HTTPRequestDuration.WithLabelValues(method, endpoint).Observe(duration.Seconds())
}

func RecordEntityResolution(entityID, trustAnchor, status string, duration time.Duration) {
	EntityResolutions.WithLabelValues(entityID, trustAnchor, status).Inc()
	EntityResolutionDuration.WithLabelValues(entityID, trustAnchor).Observe(duration.Seconds())
}

func RecordTrustChainDiscovery(entityID, trustAnchor, status string, duration time.Duration) {
	TrustChainResolutions.WithLabelValues(entityID, trustAnchor, status).Inc()
}

func RecordError(errorType, operation string) {
	ErrorsTotal.WithLabelValues(errorType, operation).Inc()
}

func IncrementActiveConnections() {
	ActiveConnections.Inc()
}

func DecrementActiveConnections() {
	ActiveConnections.Dec()
}

func UpdateUptime() {
	UptimeSeconds.Set(time.Since(startTime).Seconds())
}

func UpdateCacheSize(cacheName string, size int) {
	CacheSize.WithLabelValues(cacheName).Set(float64(size))
}

func RecordCacheHit(cacheName, key string) {
	// Could add cache hit metrics here if needed
}

func RecordCacheMiss(cacheName, key string) {
	// Could add cache miss metrics here if needed
}
