package metrics

import (
	"testing"
	"time"
)

func TestGatherSnapshotIncludesCounters(t *testing.T) {
	RecordHTTPRequest("GET", "/api/v1/entity/*entityId", 200, 12*time.Millisecond)
	RecordHTTPRequest("GET", "/api/v1/entity/*entityId", 404, 8*time.Millisecond)
	RecordEntityResolution("https://example.com", "any", "success", 20*time.Millisecond)
	RecordEntityResolution("https://example.com", "any", "error", 5*time.Millisecond)
	RecordTrustChainDiscovery("https://example.com", "ta", "success", 30*time.Millisecond)
	RecordError("entity_resolution_failed", "resolve_entity")
	RecordCacheHit("entity_statements", "k")
	RecordCacheMiss("entity_statements", "k2")
	UpdateCacheSize("entity_statements", 3)
	IncrementActiveConnections()
	t.Cleanup(DecrementActiveConnections)

	snap := GatherSnapshot()
	if snap.HTTP.RequestsTotal < 2 {
		t.Fatalf("requests_total = %v", snap.HTTP.RequestsTotal)
	}
	if snap.HTTP.Requests2xx < 1 {
		t.Fatalf("requests_2xx = %v", snap.HTTP.Requests2xx)
	}
	if snap.HTTP.Requests4xx < 1 {
		t.Fatalf("requests_4xx = %v", snap.HTTP.Requests4xx)
	}
	if snap.Resolutions.EntitySuccess < 1 || snap.Resolutions.EntityError < 1 {
		t.Fatalf("entity resolutions: %+v", snap.Resolutions)
	}
	if snap.Resolutions.ChainSuccess < 1 {
		t.Fatalf("chain success = %v", snap.Resolutions.ChainSuccess)
	}
	if snap.Errors.Total < 1 {
		t.Fatalf("errors.total = %v", snap.Errors.Total)
	}
	if snap.Cache.Hits < 1 || snap.Cache.Misses < 1 {
		t.Fatalf("cache hits/misses = %+v", snap.Cache)
	}
	if snap.Cache.HitRatio <= 0 || snap.Cache.HitRatio > 1 {
		t.Fatalf("hit_ratio = %v", snap.Cache.HitRatio)
	}
	if snap.ActiveConnections < 1 {
		t.Fatalf("active_connections = %v", snap.ActiveConnections)
	}
}

func TestRecordHTTPRequestUsesNumericStatus(t *testing.T) {
	before := GatherSnapshot()
	RecordHTTPRequest("POST", "/api/v1/cache/clear-all", 200, time.Millisecond)
	after := GatherSnapshot()
	if after.HTTP.Requests2xx < before.HTTP.Requests2xx+1 {
		t.Fatalf("expected 2xx to increase, before=%v after=%v", before.HTTP.Requests2xx, after.HTTP.Requests2xx)
	}
}
