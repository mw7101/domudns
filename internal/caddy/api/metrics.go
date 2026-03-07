package api

import (
	"net/http"

	"github.com/mw7101/domudns/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsHandler serves Prometheus metrics.
type MetricsHandler struct {
	handler http.Handler
}

// NewMetricsHandler creates a handler that serves Prometheus metrics.
func NewMetricsHandler() *MetricsHandler {
	handler := promhttp.HandlerFor(metrics.Registry(), promhttp.HandlerOpts{})
	return &MetricsHandler{handler: handler}
}

// ServeHTTP implements http.Handler.
func (h *MetricsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/metrics/history" {
		h.serveHistory(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	h.handler.ServeHTTP(w, r)
}

// serveHistory returns metrics snapshots as JSON.
// Supported query parameters:
//   - range=1h: fine buffer, last 360 entries (10s interval → 1 hour)
//   - range=24h (default): fine buffer (10s interval, up to 8640 points)
//   - range=7d: coarse buffer, last 2016 entries, downsampled to ~288 points
//   - range=30d: coarse buffer, all entries, downsampled to ~288 points
func (h *MetricsHandler) serveHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	rangeParam := r.URL.Query().Get("range")
	if rangeParam == "" {
		rangeParam = "24h"
	}

	var snaps []metrics.Snapshot
	switch rangeParam {
	case "1h":
		all := metrics.GetFineHistory()
		// 1 hour = 360 snapshots at 10s interval
		const fine1h = 360
		if len(all) > fine1h {
			all = all[len(all)-fine1h:]
		}
		snaps = all
	case "7d":
		all := metrics.GetCoarseHistory()
		// 7 days = 2016 snapshots at 5-minute interval
		const coarse7d = 2016
		if len(all) > coarse7d {
			all = all[len(all)-coarse7d:]
		}
		snaps = downsample(all, 288)
	case "30d":
		all := metrics.GetCoarseHistory()
		snaps = downsample(all, 288)
	default: // "24h"
		snaps = metrics.GetFineHistory()
	}

	if snaps == nil {
		snaps = []metrics.Snapshot{}
	}
	writeSuccess(w, map[string]interface{}{"samples": snaps}, http.StatusOK)
}

// downsample reduces snaps to at most n evenly distributed points.
// If len(snaps) <= n, snaps is returned unchanged.
func downsample(snaps []metrics.Snapshot, n int) []metrics.Snapshot {
	if len(snaps) <= n {
		return snaps
	}
	result := make([]metrics.Snapshot, n)
	for i := 0; i < n; i++ {
		idx := i * (len(snaps) - 1) / (n - 1)
		result[i] = snaps[idx]
	}
	return result
}
