package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/mw7101/domudns/internal/dns"
	"github.com/rs/zerolog/log"
)

// RecordStore abstracts record persistence.
type RecordStore interface {
	GetZone(ctx context.Context, domain string) (*dns.Zone, error)
	GetRecords(ctx context.Context, zoneDomain string) ([]dns.Record, error)
	PutRecord(ctx context.Context, zoneDomain string, record *dns.Record) error
	DeleteRecord(ctx context.Context, zoneDomain string, recordID int) error
}

// RecordsHandler handles record CRUD operations.
type RecordsHandler struct {
	store      RecordStore
	zoneReload ZoneReloader
}

// NewRecordsHandler creates a records handler.
// zoneReload is optional - if provided, it will be called after mutating operations.
func NewRecordsHandler(store RecordStore, zoneReload ZoneReloader) *RecordsHandler {
	return &RecordsHandler{store: store, zoneReload: zoneReload}
}

func (h *RecordsHandler) triggerZoneReload() {
	if h.zoneReload == nil {
		return
	}
	go func() {
		if err := h.zoneReload(); err != nil {
			log.Warn().Err(err).Msg("zone reload after record API change failed")
		}
	}()
}

// ServeHTTP routes record requests. Path: /api/zones/{zone}/records[/{id}]
func (h *RecordsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/zones")
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "records" {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Unknown endpoint")
		return
	}
	zoneDomain := parts[0]
	if zoneDomain == "" {
		writeError(w, http.StatusBadRequest, "INVALID_ZONE", "Domain required")
		return
	}
	if !dns.IsValidDomain(zoneDomain) {
		writeError(w, http.StatusBadRequest, "INVALID_ZONE", "Invalid domain name")
		return
	}

	// ?view= query parameter for split-horizon view zones.
	// Internally "domain@view" is used as a composite key,
	// which the FileStore processes transparently.
	view := r.URL.Query().Get("view")
	if view != "" {
		if !isValidViewName(view) {
			writeError(w, http.StatusBadRequest, "INVALID_VIEW", "Invalid view name (only [a-z0-9_-] allowed)")
			return
		}
		zoneDomain = zoneDomain + "@" + view
	}

	if len(parts) == 2 {
		// /api/zones/example.com/records
		switch r.Method {
		case http.MethodGet:
			h.list(r.Context(), w, zoneDomain)
			return
		case http.MethodPost:
			h.create(r.Context(), w, r, zoneDomain)
			return
		}
	}

	if len(parts) == 3 {
		// /api/zones/example.com/records/123
		id, err := strconv.Atoi(parts[2])
		if err != nil || id < 1 {
			writeError(w, http.StatusBadRequest, "INVALID_RECORD", "Invalid record ID (must be positive integer)")
			return
		}
		switch r.Method {
		case http.MethodGet:
			h.get(r.Context(), w, zoneDomain, id)
			return
		case http.MethodPut:
			h.update(r.Context(), w, r, zoneDomain, id)
			return
		case http.MethodDelete:
			h.delete(r.Context(), w, zoneDomain, id)
			return
		}
	}

	writeError(w, http.StatusNotFound, "NOT_FOUND", "Unknown endpoint")
}

func (h *RecordsHandler) list(ctx context.Context, w http.ResponseWriter, zoneDomain string) {
	zone, err := h.store.GetZone(ctx, zoneDomain)
	if err != nil {
		if err == dns.ErrZoneNotFound {
			writeError(w, http.StatusNotFound, "ZONE_NOT_FOUND", "Zone not found")
			return
		}
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	writeSuccess(w, zone.Records, http.StatusOK)
}

func (h *RecordsHandler) get(ctx context.Context, w http.ResponseWriter, zoneDomain string, id int) {
	zone, err := h.store.GetZone(ctx, zoneDomain)
	if err != nil {
		if err == dns.ErrZoneNotFound {
			writeError(w, http.StatusNotFound, "ZONE_NOT_FOUND", "Zone not found")
			return
		}
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	record := zone.RecordByID(id)
	if record == nil {
		writeError(w, http.StatusNotFound, "RECORD_NOT_FOUND", "Record not found")
		return
	}
	writeSuccess(w, record, http.StatusOK)
}

func (h *RecordsHandler) create(ctx context.Context, w http.ResponseWriter, r *http.Request, zoneDomain string) {
	var record dns.Record
	if err := DecodeJSON(r, &record, 0); err != nil {
		if errors.Is(err, ErrJSONDepthExceeded) {
			writeError(w, http.StatusBadRequest, "INVALID_JSON", "JSON nesting depth exceeded")
			return
		}
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}
	// Validate using the actual domain part (without @view)
	domainPart := zoneDomain
	if idx := strings.LastIndex(zoneDomain, "@"); idx >= 0 {
		domainPart = zoneDomain[:idx]
	}
	if err := dns.ValidateRecord(record, domainPart); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_RECORD", err.Error())
		return
	}
	if record.TTL == 0 {
		record.TTL = 3600
	}
	// API3: Ignore client-supplied ID on create; server assigns (mass assignment prevention)
	record.ID = 0
	if err := h.store.PutRecord(ctx, zoneDomain, &record); err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	h.triggerZoneReload()
	writeSuccess(w, record, http.StatusCreated)
}

func (h *RecordsHandler) update(ctx context.Context, w http.ResponseWriter, r *http.Request, zoneDomain string, id int) {
	zone, err := h.store.GetZone(ctx, zoneDomain)
	if err != nil {
		if err == dns.ErrZoneNotFound {
			writeError(w, http.StatusNotFound, "ZONE_NOT_FOUND", "Zone not found")
			return
		}
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	if zone.RecordByID(id) == nil {
		writeError(w, http.StatusNotFound, "RECORD_NOT_FOUND", "Record not found")
		return
	}
	var record dns.Record
	if err := DecodeJSON(r, &record, 0); err != nil {
		if errors.Is(err, ErrJSONDepthExceeded) {
			writeError(w, http.StatusBadRequest, "INVALID_JSON", "JSON nesting depth exceeded")
			return
		}
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}
	record.ID = id
	domainPart := zoneDomain
	if idx := strings.LastIndex(zoneDomain, "@"); idx >= 0 {
		domainPart = zoneDomain[:idx]
	}
	if err := dns.ValidateRecord(record, domainPart); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_RECORD", err.Error())
		return
	}
	if err := h.store.PutRecord(ctx, zoneDomain, &record); err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	h.triggerZoneReload()
	writeSuccess(w, record, http.StatusOK)
}

func (h *RecordsHandler) delete(ctx context.Context, w http.ResponseWriter, zoneDomain string, id int) {
	if err := h.store.DeleteRecord(ctx, zoneDomain, id); err != nil {
		if err == dns.ErrRecordNotFound {
			writeError(w, http.StatusNotFound, "RECORD_NOT_FOUND", "Record not found")
			return
		}
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	h.triggerZoneReload()
	w.WriteHeader(http.StatusNoContent)
}
