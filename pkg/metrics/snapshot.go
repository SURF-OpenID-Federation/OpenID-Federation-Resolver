package metrics

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// Snapshot is a JSON-friendly view of resolver metrics for the operations console.
type Snapshot struct {
	UptimeSeconds     float64        `json:"uptime_seconds"`
	ActiveConnections float64        `json:"active_connections"`
	HTTP              HTTPSnapshot   `json:"http"`
	Resolutions       ResolutionSnap `json:"resolutions"`
	Errors            ErrorSnapshot  `json:"errors"`
	Cache             CacheSnapshot  `json:"cache"`
}

type HTTPSnapshot struct {
	RequestsTotal float64        `json:"requests_total"`
	Requests2xx   float64        `json:"requests_2xx"`
	Requests4xx   float64        `json:"requests_4xx"`
	Requests5xx   float64        `json:"requests_5xx"`
	DurationCount float64        `json:"duration_count"`
	DurationSum   float64        `json:"duration_sum"`
	ByEndpoint    []LabeledCount `json:"by_endpoint"`
}

type ResolutionSnap struct {
	EntityTotal   float64 `json:"entity_total"`
	EntitySuccess float64 `json:"entity_success"`
	EntityError   float64 `json:"entity_error"`
	ChainTotal    float64 `json:"chain_total"`
	ChainSuccess  float64 `json:"chain_success"`
	ChainError    float64 `json:"chain_error"`
}

type ErrorSnapshot struct {
	Total  float64        `json:"total"`
	ByType []LabeledCount `json:"by_type"`
}

type CacheSnapshot struct {
	Hits     float64       `json:"hits"`
	Misses   float64       `json:"misses"`
	HitRatio float64       `json:"hit_ratio"`
	ByName   []CacheByName `json:"by_name"`
}

type CacheByName struct {
	Name   string  `json:"name"`
	Size   float64 `json:"size"`
	Hits   float64 `json:"hits"`
	Misses float64 `json:"misses"`
}

type LabeledCount struct {
	Label string  `json:"label"`
	Count float64 `json:"count"`
}

// GatherSnapshot reads the current Prometheus registry into a dashboard snapshot.
func GatherSnapshot() Snapshot {
	UpdateUptime()
	snap := Snapshot{
		HTTP: HTTPSnapshot{
			ByEndpoint: []LabeledCount{},
		},
		Errors: ErrorSnapshot{
			ByType: []LabeledCount{},
		},
		Cache: CacheSnapshot{
			ByName: []CacheByName{},
		},
	}
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return snap
	}

	cacheHits := map[string]float64{}
	cacheMisses := map[string]float64{}
	cacheSize := map[string]float64{}
	endpointCounts := map[string]float64{}

	for _, mf := range mfs {
		switch mf.GetName() {
		case "federation_resolver_uptime_seconds":
			snap.UptimeSeconds = gaugeValue(mf)
		case "federation_resolver_active_connections":
			snap.ActiveConnections = gaugeValue(mf)
		case "federation_resolver_requests_total":
			for _, m := range mf.GetMetric() {
				n := counterValue(m)
				snap.HTTP.RequestsTotal += n
				labels := labelMap(m)
				endpointCounts[labels["method"]+" "+labels["endpoint"]] += n
				switch statusClass(labels["status"]) {
				case 2:
					snap.HTTP.Requests2xx += n
				case 4:
					snap.HTTP.Requests4xx += n
				case 5:
					snap.HTTP.Requests5xx += n
				}
			}
		case "federation_resolver_request_duration_seconds":
			for _, m := range mf.GetMetric() {
				h := m.GetHistogram()
				if h == nil {
					continue
				}
				snap.HTTP.DurationCount += float64(h.GetSampleCount())
				snap.HTTP.DurationSum += h.GetSampleSum()
			}
		case "federation_resolver_entity_resolutions_total":
			for _, m := range mf.GetMetric() {
				n := counterValue(m)
				snap.Resolutions.EntityTotal += n
				if labelMap(m)["status"] == "success" {
					snap.Resolutions.EntitySuccess += n
				} else {
					snap.Resolutions.EntityError += n
				}
			}
		case "federation_resolver_trust_chain_resolutions_total":
			for _, m := range mf.GetMetric() {
				n := counterValue(m)
				snap.Resolutions.ChainTotal += n
				if labelMap(m)["status"] == "success" {
					snap.Resolutions.ChainSuccess += n
				} else {
					snap.Resolutions.ChainError += n
				}
			}
		case "federation_resolver_errors_total":
			for _, m := range mf.GetMetric() {
				n := counterValue(m)
				snap.Errors.Total += n
				labels := labelMap(m)
				snap.Errors.ByType = append(snap.Errors.ByType, LabeledCount{
					Label: labels["error_type"] + " / " + labels["operation"],
					Count: n,
				})
			}
		case "federation_resolver_cache_hits_total":
			for _, m := range mf.GetMetric() {
				n := counterValue(m)
				snap.Cache.Hits += n
				cacheHits[labelMap(m)["cache_name"]] += n
			}
		case "federation_resolver_cache_misses_total":
			for _, m := range mf.GetMetric() {
				n := counterValue(m)
				snap.Cache.Misses += n
				cacheMisses[labelMap(m)["cache_name"]] += n
			}
		case "federation_resolver_cache_size":
			for _, m := range mf.GetMetric() {
				cacheSize[labelMap(m)["cache_name"]] = gaugeMetricValue(m)
			}
		}
	}

	for name, n := range endpointCounts {
		snap.HTTP.ByEndpoint = append(snap.HTTP.ByEndpoint, LabeledCount{Label: name, Count: n})
	}

	names := map[string]struct{}{}
	for k := range cacheHits {
		names[k] = struct{}{}
	}
	for k := range cacheMisses {
		names[k] = struct{}{}
	}
	for k := range cacheSize {
		names[k] = struct{}{}
	}
	for name := range names {
		if name == "" {
			continue
		}
		snap.Cache.ByName = append(snap.Cache.ByName, CacheByName{
			Name:   name,
			Size:   cacheSize[name],
			Hits:   cacheHits[name],
			Misses: cacheMisses[name],
		})
	}

	lookups := snap.Cache.Hits + snap.Cache.Misses
	if lookups > 0 {
		snap.Cache.HitRatio = snap.Cache.Hits / lookups
	}
	return snap
}

func gaugeValue(mf *dto.MetricFamily) float64 {
	if mf == nil || len(mf.GetMetric()) == 0 {
		return 0
	}
	return gaugeMetricValue(mf.GetMetric()[0])
}

func gaugeMetricValue(m *dto.Metric) float64 {
	if m == nil || m.GetGauge() == nil {
		return 0
	}
	return m.GetGauge().GetValue()
}

func counterValue(m *dto.Metric) float64 {
	if m == nil || m.GetCounter() == nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

func labelMap(m *dto.Metric) map[string]string {
	out := map[string]string{}
	if m == nil {
		return out
	}
	for _, lp := range m.GetLabel() {
		out[lp.GetName()] = lp.GetValue()
	}
	return out
}

func statusClass(status string) int {
	n, err := strconv.Atoi(status)
	if err != nil {
		return 0
	}
	return n / 100
}
