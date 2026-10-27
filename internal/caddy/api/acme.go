package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/mw7101/domudns/internal/dns"
)

// ACMEStore abstracts ACME challenge storage.
type ACMEStore interface {
	PutACMEChallenge(ctx context.Context, fqdn, value string, ttl time.Duration) error
	DeleteACMEChallenge(ctx context.Context, fqdn string) error
}

// ACMEHandler handles ACME DNS-01 present/cleanup.
type ACMEHandler struct {
	store   ACMEStore
	ttlSecs int
}

// NewACMEHandler creates an ACME handler.
func NewACMEHandler(store ACMEStore, ttlSecs int) *ACMEHandler {
	if ttlSecs <= 0 {
		ttlSecs = 60
	}
	return &ACMEHandler{store: store, ttlSecs: ttlSecs}
}

// PresentRequest is the body for POST /api/acme/dns-01/present.
type PresentRequest struct {
	Domain   string `json:"domain"`
	TXTValue string `json:"txt_value"`
}

// CleanupRequest is the body for POST /api/acme/dns-01/cleanup.
type CleanupRequest struct {
	Domain string `json:"domain"`
}

// ServeHTTP routes ACME requests.
func (h *ACMEHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := r.URL.Path

	// Traefik httpreq provider: /api/acme/httpreq/present and /api/acme/httpreq/cleanup
	if strings.HasPrefix(path, "/api/acme/httpreq/") {
		sub := "/" + strings.Trim(strings.TrimPrefix(path, "/api/acme/httpreq/"), "/")
		switch sub {
		case "/present":
			if r.Method != http.MethodPost {
				writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
				return
			}
			h.httpreqPresent(ctx, w, r)
		case "/cleanup":
			if r.Method != http.MethodPost {
				writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
				return
			}
			h.httpreqCleanup(ctx, w, r)
		default:
			writeError(w, http.StatusNotFound, "NOT_FOUND", "Unknown httpreq endpoint")
		}
		return
	}

	// Standard DomU DNS ACME endpoints: /api/acme/dns-01/present and /api/acme/dns-01/cleanup
	sub := "/" + strings.Trim(strings.TrimPrefix(path, "/api/acme/dns-01/"), "/")
	switch sub {
	case "/present":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
			return
		}
		h.present(ctx, w, r)
	case "/cleanup":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
			return
		}
		h.cleanup(ctx, w, r)
	default:
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Unknown endpoint")
	}
}

func (h *ACMEHandler) present(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req PresentRequest
	if err := DecodeJSON(r, &req, 0); err != nil {
		if errors.Is(err, ErrJSONDepthExceeded) {
			writeError(w, http.StatusBadRequest, "INVALID_JSON", "JSON nesting depth exceeded")
			return
		}
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}
	if req.Domain == "" || req.TXTValue == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "domain and txt_value required")
		return
	}
	if len(req.TXTValue) > 255 {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "txt_value exceeds 255 bytes (RFC 1035)")
		return
	}
	domain := strings.TrimSuffix(req.Domain, ".")
	if !dns.IsValidDomain(domain) {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid domain name")
		return
	}
	fqdn := "_acme-challenge." + domain
	if err := h.store.PutACMEChallenge(ctx, fqdn, req.TXTValue, time.Duration(h.ttlSecs)*time.Second); err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	writeSuccess(w, map[string]string{"status": "ok"}, http.StatusOK)
}

func (h *ACMEHandler) cleanup(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req CleanupRequest
	if err := DecodeJSON(r, &req, 0); err != nil {
		if errors.Is(err, ErrJSONDepthExceeded) {
			writeError(w, http.StatusBadRequest, "INVALID_JSON", "JSON nesting depth exceeded")
			return
		}
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}
	if req.Domain == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "domain required")
		return
	}
	domain := strings.TrimSuffix(req.Domain, ".")
	if !dns.IsValidDomain(domain) {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid domain name")
		return
	}
	fqdn := "_acme-challenge." + domain
	if err := h.store.DeleteACMEChallenge(ctx, fqdn); err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	writeSuccess(w, map[string]string{"status": "ok"}, http.StatusOK)
}

// httpreqPresentRequest is the body for POST /api/acme/httpreq/present (Traefik format).
type httpreqPresentRequest struct {
	FQDN  string `json:"fqdn"`  // with trailing dot, e.g. "_acme-challenge.example.com."
	Value string `json:"value"` // TXT token
}

// httpreqCleanupRequest is the body for POST /api/acme/httpreq/cleanup (Traefik format).
type httpreqCleanupRequest struct {
	FQDN string `json:"fqdn"` // with trailing dot
}

// httpreqPresent handles POST /api/acme/httpreq/present (Traefik httpreq provider).
func (h *ACMEHandler) httpreqPresent(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req httpreqPresentRequest
	if err := DecodeJSON(r, &req, 0); err != nil {
		if errors.Is(err, ErrJSONDepthExceeded) {
			writeError(w, http.StatusBadRequest, "INVALID_JSON", "JSON nesting depth exceeded")
			return
		}
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}
	if req.FQDN == "" || req.Value == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "fqdn and value required")
		return
	}
	if len(req.Value) > 255 {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "value exceeds 255 bytes (RFC 1035)")
		return
	}
	// Traefik sends FQDN with trailing dot, e.g. "_acme-challenge.example.com."
	fqdn := strings.TrimSuffix(req.FQDN, ".")
	if !strings.HasPrefix(fqdn, "_acme-challenge.") {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "fqdn must start with _acme-challenge.")
		return
	}
	if err := h.store.PutACMEChallenge(ctx, fqdn, req.Value, time.Duration(h.ttlSecs)*time.Second); err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	writeSuccess(w, map[string]string{"status": "ok"}, http.StatusOK)
}

// httpreqCleanup handles POST /api/acme/httpreq/cleanup (Traefik httpreq provider).
func (h *ACMEHandler) httpreqCleanup(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req httpreqCleanupRequest
	if err := DecodeJSON(r, &req, 0); err != nil {
		if errors.Is(err, ErrJSONDepthExceeded) {
			writeError(w, http.StatusBadRequest, "INVALID_JSON", "JSON nesting depth exceeded")
			return
		}
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}
	if req.FQDN == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "fqdn required")
		return
	}
	// Strip trailing dot (Traefik format)
	fqdn := strings.TrimSuffix(req.FQDN, ".")
	if !strings.HasPrefix(fqdn, "_acme-challenge.") {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "fqdn must start with _acme-challenge.")
		return
	}
	if err := h.store.DeleteACMEChallenge(ctx, fqdn); err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	writeSuccess(w, map[string]string{"status": "ok"}, http.StatusOK)
}
