package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

var (
	reg     *prometheus.Registry
	regOnce sync.Once
)

// Registry returns the shared Prometheus registry.
func Registry() *prometheus.Registry {
	regOnce.Do(func() {
		reg = prometheus.NewRegistry()
		reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	})
	return reg
}

// DNSQueriesTotal counts DNS queries by query type and result.
// result: "blocked", "authoritative", "cached", "forwarded", "error"
var DNSQueriesTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "dns_queries_total",
		Help: "Total number of DNS queries",
	},
	[]string{"qtype", "result"},
)

// DNSQueryDuration records DNS query latency by result.
// result: "blocked", "authoritative", "cached", "forwarded", "error"
var DNSQueryDuration = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "dns_query_duration_seconds",
		Help:    "DNS query duration in seconds",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5},
	},
	[]string{"result"},
)

// APIRequestsTotal counts HTTP API requests.
var APIRequestsTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "api_requests_total",
		Help: "Total number of API requests",
	},
	[]string{"method", "path", "status"},
)

func init() {
	Registry().MustRegister(DNSQueriesTotal, DNSQueryDuration, APIRequestsTotal)
}
