package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/mw7101/domudns/internal/store"
	"github.com/rs/zerolog/log"
)

// DDNSKeyUpdater is called after key changes (e.g. DNS server live-reload).
type DDNSKeyUpdater interface {
	UpdateTSIGKeys(keys []store.TSIGKey)
}

// DDNSRuntimeStats enthält die für die API relevanten Laufzeitdaten des DDNS-Handlers.
type DDNSRuntimeStats struct {
	TotalUpdates       int64
	LastUpdateAt       time.Time
	TotalFailed        int64
	LastError          string
	LastErrorAt        time.Time
	LastRejectedReason string
	LastRejectedAt     time.Time
}

// DDNSStatsProvider liefert aktuelle DDNS-Laufzeitdaten.
// Implementiert von *dnsserver.DDNSHandler via Adapter in main.go.
type DDNSStatsProvider interface {
	GetDDNSStats() DDNSRuntimeStats
}

// DDNSAPIHandler manages TSIG keys for RFC 2136 DDNS via the REST API.
type DDNSAPIHandler struct {
	store         TSIGKeyStore
	keyUpdater    DDNSKeyUpdater
	statsProvider DDNSStatsProvider
}

// NewDDNSAPIHandler creates a new DDNSAPIHandler.
func NewDDNSAPIHandler(store TSIGKeyStore, keyUpdater DDNSKeyUpdater) *DDNSAPIHandler {
	return &DDNSAPIHandler{
		store:      store,
		keyUpdater: keyUpdater,
	}
}

// SetStatsProvider setzt den DDNS-Stats-Provider (kann nach Initialisierung gesetzt werden).
func (h *DDNSAPIHandler) SetStatsProvider(p DDNSStatsProvider) {
	h.statsProvider = p
}

// tsigKeyResponse is the publicly visible key without the secret.
type tsigKeyResponse struct {
	Name      string    `json:"name"`
	Algorithm string    `json:"algorithm"`
	CreatedAt time.Time `json:"created_at"`
}

// tsigKeyCreateResponse contains the key including secret (only returned once on creation).
type tsigKeyCreateResponse struct {
	Name      string    `json:"name"`
	Algorithm string    `json:"algorithm"`
	Secret    string    `json:"secret"` // returned only once
	CreatedAt time.Time `json:"created_at"`
}

// createKeyRequest is the request body for POST /api/ddns/keys.
type createKeyRequest struct {
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
}

// ServeHTTP routes DDNS requests.
func (h *DDNSAPIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	urlPath := r.URL.Path

	// Status endpoint
	if urlPath == "/api/ddns/status" {
		if r.Method == http.MethodGet {
			h.getStatus(w, r)
		} else {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
		}
		return
	}

	// Keys endpoint
	path := strings.TrimPrefix(urlPath, "/api/ddns/keys")
	path = strings.Trim(path, "/")

	switch r.Method {
	case http.MethodGet:
		if path == "" {
			h.listKeys(w, r)
		} else {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "Unknown endpoint")
		}

	case http.MethodPost:
		if path == "" {
			h.createKey(w, r)
		} else {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "Unknown endpoint")
		}

	case http.MethodDelete:
		if path != "" {
			h.deleteKey(w, r, path)
		} else {
			writeError(w, http.StatusBadRequest, "KEY_NAME_REQUIRED", "Key name required in path")
		}

	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

func (h *DDNSAPIHandler) getStatus(w http.ResponseWriter, r *http.Request) {
	type ddnsStatusResponse struct {
		KeyCount           int    `json:"key_count"`
		TotalUpdates       int64  `json:"total_updates"`
		LastUpdateAt       string `json:"last_update_at"`
		TotalFailed        int64  `json:"total_failed"`
		LastError          string `json:"last_error"`
		LastErrorAt        string `json:"last_error_at"`
		LastRejectedReason string `json:"last_rejected_reason"`
		LastRejectedAt     string `json:"last_rejected_at"`
	}

	keys, _ := h.store.GetTSIGKeys(r.Context())
	resp := ddnsStatusResponse{
		KeyCount: len(keys),
	}

	if h.statsProvider != nil {
		s := h.statsProvider.GetDDNSStats()
		resp.TotalUpdates = s.TotalUpdates
		resp.TotalFailed = s.TotalFailed
		resp.LastRejectedReason = s.LastRejectedReason
		if !s.LastUpdateAt.IsZero() {
			resp.LastUpdateAt = s.LastUpdateAt.Format(time.RFC3339)
		}
		resp.LastError = s.LastError
		if !s.LastErrorAt.IsZero() {
			resp.LastErrorAt = s.LastErrorAt.Format(time.RFC3339)
		}
		if !s.LastRejectedAt.IsZero() {
			resp.LastRejectedAt = s.LastRejectedAt.Format(time.RFC3339)
		}
	}

	writeSuccess(w, resp, http.StatusOK)
}

func (h *DDNSAPIHandler) listKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := h.store.GetTSIGKeys(r.Context())
	if err != nil {
		writeInternalError(w, "DDNS_LIST_FAILED", err)
		return
	}

	resp := make([]tsigKeyResponse, 0, len(keys))
	for _, k := range keys {
		resp = append(resp, tsigKeyResponse{
			Name:      k.Name,
			Algorithm: k.Algorithm,
			CreatedAt: k.CreatedAt,
		})
	}
	writeSuccess(w, resp, http.StatusOK)
}

func (h *DDNSAPIHandler) createKey(w http.ResponseWriter, r *http.Request) {
	var req createKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "NAME_REQUIRED", "Key name is required")
		return
	}
	if strings.ContainsAny(req.Name, " \t\n/\\") {
		writeError(w, http.StatusBadRequest, "INVALID_NAME", "Key name must not contain whitespace or slashes")
		return
	}

	if req.Algorithm == "" {
		req.Algorithm = "hmac-sha256"
	}
	req.Algorithm = strings.ToLower(req.Algorithm)
	switch req.Algorithm {
	case "hmac-sha256", "hmac-sha512", "hmac-sha1":
		// valid
	default:
		writeError(w, http.StatusBadRequest, "INVALID_ALGORITHM", "Algorithm must be hmac-sha256, hmac-sha512 or hmac-sha1")
		return
	}

	// Generate random secret (32 bytes = 256 bits)
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		writeInternalError(w, "SECRET_GENERATION_FAILED", err)
		return
	}
	secret := base64.StdEncoding.EncodeToString(secretBytes)

	key := store.TSIGKey{
		Name:      req.Name,
		Algorithm: req.Algorithm,
		Secret:    secret,
		CreatedAt: time.Now().UTC(),
	}

	if err := h.store.PutTSIGKey(r.Context(), key); err != nil {
		writeInternalError(w, "DDNS_CREATE_FAILED", err)
		return
	}

	log.Info().Str("key", key.Name).Str("algorithm", key.Algorithm).Msg("ddns: TSIG key erstellt")
	h.reloadKeys(r)

	writeSuccess(w, tsigKeyCreateResponse{
		Name:      key.Name,
		Algorithm: key.Algorithm,
		Secret:    secret,
		CreatedAt: key.CreatedAt,
	}, http.StatusCreated)
}

func (h *DDNSAPIHandler) deleteKey(w http.ResponseWriter, r *http.Request, name string) {
	if err := h.store.DeleteTSIGKey(r.Context(), name); err != nil {
		writeInternalError(w, "DDNS_DELETE_FAILED", err)
		return
	}

	log.Info().Str("key", name).Msg("ddns: TSIG key gelöscht")
	h.reloadKeys(r)

	w.WriteHeader(http.StatusNoContent)
}

// reloadKeys reloads all keys and notifies the DNS server.
func (h *DDNSAPIHandler) reloadKeys(r *http.Request) {
	if h.keyUpdater == nil {
		return
	}
	keys, err := h.store.GetTSIGKeys(r.Context())
	if err != nil {
		log.Warn().Err(err).Msg("ddns: keys not loaded after change")
		return
	}
	h.keyUpdater.UpdateTSIGKeys(keys)
}
