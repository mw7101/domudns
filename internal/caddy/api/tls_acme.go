package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/mw7101/domudns/internal/store"
)

// CertStatusProvider is implemented by certmanager.CertManager.
// Uses store.TLSCertStatus (defined in internal/store/types.go) to avoid import cycles.
type CertStatusProvider interface {
	Status() store.TLSCertStatus
	TriggerRenewal(ctx context.Context)
}

// TLSACMEHandlerStore is the minimal store interface used by this handler.
type TLSACMEHandlerStore interface {
	GetTLSACMEConfig(ctx context.Context) (*store.TLSACMEConfig, error)
	SetTLSACMEConfig(ctx context.Context, cfg *store.TLSACMEConfig) error
}

// TLSACMEHandler handles /api/tls/acme endpoints.
type TLSACMEHandler struct {
	store    TLSACMEHandlerStore
	provider CertStatusProvider
	slave    bool
}

// NewTLSACMEHandler creates a new handler.
func NewTLSACMEHandler(s TLSACMEHandlerStore, provider CertStatusProvider) *TLSACMEHandler {
	return &TLSACMEHandler{store: s, provider: provider}
}

// SetSlaveMode marks this handler as running on a slave (PUT/POST return 403).
func (h *TLSACMEHandler) SetSlaveMode(slave bool) {
	h.slave = slave
}

// ServeHTTP routes /api/tls/acme, /api/tls/acme/status, /api/tls/acme/renew.
func (h *TLSACMEHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case path == "/api/tls/acme" || path == "/api/tls/acme/":
		switch r.Method {
		case http.MethodGet:
			h.handleGet(w, r)
		case http.MethodPut:
			h.handlePut(w, r)
		default:
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET or PUT required")
		}
	case strings.HasSuffix(path, "/status"):
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
			return
		}
		h.handleStatus(w, r)
	case strings.HasSuffix(path, "/renew"):
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
			return
		}
		h.handleRenew(w, r)
	default:
		writeError(w, http.StatusNotFound, "NOT_FOUND", "unknown path")
	}
}

func (h *TLSACMEHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.store.GetTLSACMEConfig(r.Context())
	if err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	if cfg == nil {
		cfg = &store.TLSACMEConfig{}
	}
	writeSuccess(w, cfg, http.StatusOK)
}

func (h *TLSACMEHandler) handlePut(w http.ResponseWriter, r *http.Request) {
	if h.slave {
		writeError(w, http.StatusForbidden, "SLAVE_NODE", "certificate management only on master")
		return
	}
	var cfg store.TLSACMEConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
		return
	}
	if cfg.Enabled {
		if err := validateTLSACMEConfig(&cfg); err != nil {
			writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
			return
		}
	}
	if err := h.store.SetTLSACMEConfig(r.Context(), &cfg); err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	// Trigger renewal check asynchronously if enabled.
	if cfg.Enabled && h.provider != nil {
		h.provider.TriggerRenewal(r.Context())
	}
	writeSuccess(w, cfg, http.StatusOK)
}

func (h *TLSACMEHandler) handleStatus(w http.ResponseWriter, r *http.Request) {
	if h.provider == nil {
		writeSuccess(w, store.TLSCertStatus{}, http.StatusOK)
		return
	}
	writeSuccess(w, h.provider.Status(), http.StatusOK)
}

func (h *TLSACMEHandler) handleRenew(w http.ResponseWriter, r *http.Request) {
	if h.slave {
		writeError(w, http.StatusForbidden, "SLAVE_NODE", "certificate renewal only on master")
		return
	}
	if h.provider != nil {
		h.provider.TriggerRenewal(r.Context())
	}
	w.WriteHeader(http.StatusAccepted) // 202 — async
}

var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

func validateTLSACMEConfig(cfg *store.TLSACMEConfig) error {
	if cfg.Domain == "" {
		return fmt.Errorf("domain is required")
	}
	if strings.HasPrefix(cfg.Domain, "*") {
		return fmt.Errorf("wildcard domains not supported")
	}
	if cfg.Email == "" {
		return fmt.Errorf("email is required")
	}
	if !emailRe.MatchString(cfg.Email) {
		return fmt.Errorf("invalid email address")
	}
	return nil
}
