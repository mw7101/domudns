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
	path := strings.TrimPrefix(r.URL.Path, "/api/acme/dns-01/")
	path = "/" + strings.Trim(path, "/")
	switch path {
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
	if len(req.TXTValue) > 512 {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "txt_value exceeds 512 bytes")
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
