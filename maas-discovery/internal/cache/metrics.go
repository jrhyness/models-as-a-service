package cache

import (
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	cacheMetadataRebuildDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "maas",
		Subsystem: "discovery",
		Name:      "cache_metadata_rebuild_duration_seconds",
		Help:      "Duration of tenant metadata rebuilds from informer state.",
		Buckets:   prometheus.DefBuckets,
	})

	cacheEntitlementRebuildDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "maas",
		Subsystem: "discovery",
		Name:      "cache_entitlement_rebuild_duration_seconds",
		Help:      "Duration of entitlement rebuilds over dirty tenants.",
		Buckets:   prometheus.DefBuckets,
	})

	cacheMetadataRebuildErrors = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "maas",
		Subsystem: "discovery",
		Name:      "cache_metadata_rebuild_errors_total",
		Help:      "Count of metadata rebuild failures due to recovered panics.",
	})

	cacheEntitlementRebuildErrors = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "maas",
		Subsystem: "discovery",
		Name:      "cache_entitlement_rebuild_errors_total",
		Help:      "Count of entitlement rebuild failures due to recovered panics.",
	})

	cacheMetadataLastSuccess = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "maas",
		Subsystem: "discovery",
		Name:      "cache_metadata_last_successful_rebuild_timestamp_seconds",
		Help:      "Unix timestamp of the most recent successful metadata rebuild.",
	})

	cacheEntitlementLastSuccess = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "maas",
		Subsystem: "discovery",
		Name:      "cache_entitlement_last_successful_rebuild_timestamp_seconds",
		Help:      "Unix timestamp of the most recent successful entitlement rebuild.",
	})

	metadataLastSuccessUnix    atomic.Int64
	entitlementLastSuccessUnix atomic.Int64

	cacheMetadataFreshness = promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: "maas",
		Subsystem: "discovery",
		Name:      "cache_metadata_freshness_seconds",
		Help:      "Seconds since the most recent successful metadata rebuild.",
	}, func() float64 {
		return freshnessSeconds(metadataLastSuccessUnix.Load())
	})

	cacheEntitlementFreshness = promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: "maas",
		Subsystem: "discovery",
		Name:      "cache_entitlement_freshness_seconds",
		Help:      "Seconds since the most recent successful entitlement rebuild.",
	}, func() float64 {
		return freshnessSeconds(entitlementLastSuccessUnix.Load())
	})
)

func recordMetadataRebuildSuccess() {
	now := time.Now().Unix()
	metadataLastSuccessUnix.Store(now)
	cacheMetadataLastSuccess.Set(float64(now))
}

func recordEntitlementRebuildSuccess() {
	now := time.Now().Unix()
	entitlementLastSuccessUnix.Store(now)
	cacheEntitlementLastSuccess.Set(float64(now))
}

func freshnessSeconds(lastSuccess int64) float64 {
	if lastSuccess <= 0 {
		return 0
	}
	age := time.Since(time.Unix(lastSuccess, 0)).Seconds()
	if age < 0 {
		return 0
	}
	return age
}

// Keep GaugeFuncs linked and registered.
var _ = cacheMetadataFreshness
var _ = cacheEntitlementFreshness
