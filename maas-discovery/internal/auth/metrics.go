package auth

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	sarCacheHitTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "maas",
		Subsystem: "discovery",
		Name:      "sar_cache_hits_total",
		Help:      "Number of cached SAR decisions reused by discovery auth middleware.",
	}, []string{"check"})

	sarCacheMissTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "maas",
		Subsystem: "discovery",
		Name:      "sar_cache_misses_total",
		Help:      "Number of SAR cache misses in discovery auth middleware.",
	}, []string{"check"})
)
