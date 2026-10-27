package api

import (
	"context"
	"net/http"

	"github.com/rs/zerolog/log"
)

// HealthHandler handles GET /api/health.
type HealthHandler struct {
	dbCheck      func(ctx context.Context) error
	clusterCheck func() bool // optional; returns false when cluster is misconfigured
}

// NewHealthHandler creates a health check handler.
func NewHealthHandler(dbCheck func(ctx context.Context) error) *HealthHandler {
	return &HealthHandler{dbCheck: dbCheck}
}

// SetClusterCheck registers an optional cluster-readiness check.
// When fn returns false, the health status is reported as "degraded".
func (h *HealthHandler) SetClusterCheck(fn func() bool) {
	h.clusterCheck = fn
}

// ServeHTTP implements http.Handler.
// Returns only "status" (ok/degraded) to avoid information disclosure.
func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	status := "ok"
	if h.dbCheck != nil {
		if err := h.dbCheck(r.Context()); err != nil {
			log.Debug().Err(err).Msg("health check: database unreachable")
			status = "degraded"
		}
	}
	if h.clusterCheck != nil && !h.clusterCheck() {
		log.Debug().Msg("health check: cluster misconfigured")
		status = "degraded"
	}
	writeSuccess(w, map[string]string{"status": status}, http.StatusOK)
}
