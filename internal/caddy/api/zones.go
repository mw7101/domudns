package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/mw7101/domudns/internal/dns"
	"github.com/mw7101/domudns/internal/store"
	"github.com/rs/zerolog/log"
)

// ZoneReloader is called after zone/record changes to reload in-memory zones in the DNS server.
type ZoneReloader func() error

// ZonesHandler handles zone CRUD operations.
type ZonesHandler struct {
	store      store.ZoneStore
	zoneReload ZoneReloader
}

// NewZonesHandler creates a zones handler.
// zoneReload is optional - if provided, it will be called after mutating operations.
func NewZonesHandler(store store.ZoneStore, zoneReload ZoneReloader) *ZonesHandler {
	return &ZonesHandler{store: store, zoneReload: zoneReload}
}

// isValidViewName checks if a view name is valid: only [a-z0-9_-], max 64 chars.
func isValidViewName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// ServeHTTP routes zone requests.
func (h *ZonesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/zones")
	path = strings.Trim(path, "/")
	parts := strings.SplitN(path, "/", 2)

	if path == "" {
		switch r.Method {
		case http.MethodGet:
			h.list(r.Context(), w)
			return
		case http.MethodPost:
			h.create(r.Context(), w, r)
			return
		}
	}

	domain := parts[0]
	if domain == "" {
		writeError(w, http.StatusBadRequest, "INVALID_ZONE", "Domain required")
		return
	}
	if !dns.IsValidDomain(domain) {
		writeError(w, http.StatusBadRequest, "INVALID_ZONE", "Invalid domain name")
		return
	}

	// ?view= query parameter for split-horizon
	view := r.URL.Query().Get("view")
	if view != "" && !isValidViewName(view) {
		writeError(w, http.StatusBadRequest, "INVALID_VIEW", "Invalid view name (only [a-z0-9_-] allowed)")
		return
	}

	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			if view != "" {
				h.getView(r.Context(), w, domain, view)
			} else {
				h.get(r.Context(), w, domain)
			}
			return
		case http.MethodPut:
			h.update(r.Context(), w, r, domain, view)
			return
		case http.MethodDelete:
			if view != "" {
				h.deleteView(r.Context(), w, domain, view)
			} else {
				h.delete(r.Context(), w, domain)
			}
			return
		}
	}

	writeError(w, http.StatusNotFound, "NOT_FOUND", "Unknown endpoint")
}

func (h *ZonesHandler) list(ctx context.Context, w http.ResponseWriter) {
	zones, err := h.store.ListZones(ctx)
	if err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	writeSuccess(w, zones, http.StatusOK)
}

func (h *ZonesHandler) get(ctx context.Context, w http.ResponseWriter, domain string) {
	zone, err := h.store.GetZone(ctx, domain)
	if err != nil {
		if err == dns.ErrZoneNotFound {
			writeError(w, http.StatusNotFound, "ZONE_NOT_FOUND", "Zone not found")
			return
		}
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	writeSuccess(w, zone, http.StatusOK)
}

func (h *ZonesHandler) getView(ctx context.Context, w http.ResponseWriter, domain, view string) {
	zone, err := h.store.GetZoneView(ctx, domain, view)
	if err != nil {
		if err == dns.ErrZoneNotFound {
			writeError(w, http.StatusNotFound, "ZONE_NOT_FOUND", "Zone not found")
			return
		}
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	writeSuccess(w, zone, http.StatusOK)
}

func (h *ZonesHandler) create(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var zone dns.Zone
	if err := DecodeJSON(r, &zone, 0); err != nil {
		if errors.Is(err, ErrJSONDepthExceeded) {
			writeError(w, http.StatusBadRequest, "INVALID_JSON", "JSON nesting depth exceeded")
			return
		}
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}
	if zone.View != "" && !isValidViewName(zone.View) {
		writeError(w, http.StatusBadRequest, "INVALID_VIEW", "Invalid view name (only [a-z0-9_-] allowed)")
		return
	}
	if err := dns.ValidateZone(&zone); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_ZONE", err.Error())
		return
	}
	if zone.TTL == 0 {
		zone.TTL = 3600
	}
	zone.EnsureSOA() // SOA is required for authoritative zones
	if err := h.store.PutZone(ctx, &zone); err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	h.triggerZoneReload()
	writeSuccess(w, zone, http.StatusCreated)
}

func (h *ZonesHandler) update(ctx context.Context, w http.ResponseWriter, r *http.Request, domain, view string) {
	var existing *dns.Zone
	var err error
	if view != "" {
		existing, err = h.store.GetZoneView(ctx, domain, view)
	} else {
		existing, err = h.store.GetZone(ctx, domain)
	}
	if err == dns.ErrZoneNotFound {
		writeError(w, http.StatusNotFound, "ZONE_NOT_FOUND", "Zone not found")
		return
	}
	if err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	var zone dns.Zone
	if err := DecodeJSON(r, &zone, 0); err != nil {
		if errors.Is(err, ErrJSONDepthExceeded) {
			writeError(w, http.StatusBadRequest, "INVALID_JSON", "JSON nesting depth exceeded")
			return
		}
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}
	zone.Domain = domain
	// View from URL parameter overrides body (consistency)
	if view != "" {
		zone.View = view
	}
	// Preserve existing SOA when update doesn't provide one
	if zone.SOA == nil && existing.SOA != nil {
		zone.SOA = existing.SOA
	}
	zone.EnsureSOA()
	if err := dns.ValidateZone(&zone); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_ZONE", err.Error())
		return
	}
	if err := h.store.PutZone(ctx, &zone); err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	h.triggerZoneReload()
	writeSuccess(w, zone, http.StatusOK)
}

func (h *ZonesHandler) delete(ctx context.Context, w http.ResponseWriter, domain string) {
	if err := h.store.DeleteZone(ctx, domain); err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	h.triggerZoneReload()
	w.WriteHeader(http.StatusNoContent)
}

func (h *ZonesHandler) deleteView(ctx context.Context, w http.ResponseWriter, domain, view string) {
	if err := h.store.DeleteZoneView(ctx, domain, view); err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	h.triggerZoneReload()
	w.WriteHeader(http.StatusNoContent)
}

// triggerZoneReload calls the zone reloader in a goroutine (fire-and-forget).
func (h *ZonesHandler) triggerZoneReload() {
	if h.zoneReload == nil {
		return
	}
	go func() {
		if err := h.zoneReload(); err != nil {
			log.Warn().Err(err).Msg("zone reload after API change failed")
		}
	}()
}
