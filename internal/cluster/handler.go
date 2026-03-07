package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/mw7101/domudns/internal/filestore"
	"github.com/rs/zerolog/log"
)

// Handler is the HTTP handler for /api/internal/*.
// Registers /api/internal/sync (POST) and /api/internal/state (GET).
type Handler struct {
	receiver     *ReceiverHandler
	store        *filestore.FileStore
	queryLogSync http.Handler // optional: POST /api/internal/query-log-sync
}

// SetQueryLogSyncHandler registers the handler for Query-Log-Sync (Slave → Master).
func (h *Handler) SetQueryLogSyncHandler(handler http.Handler) {
	h.queryLogSync = handler
}

// UpdateCallbacks updates the reload callbacks of the receiver after initialization.
// Called from main.go after the DNS server and AuthManager have been initialized.
func (h *Handler) UpdateCallbacks(callbacks ReloadCallbacks) {
	h.receiver.callbacks = callbacks
}

// NewHandler creates a new cluster HTTP handler.
func NewHandler(receiver *ReceiverHandler, store *filestore.FileStore) *Handler {
	return &Handler{receiver: receiver, store: store}
}

// ServeHTTP routes /api/internal/* requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/internal")
	switch path {
	case "/sync":
		h.receiver.ServeHTTP(w, r)
	case "/state":
		if r.Method != http.MethodGet {
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		h.serveState(w, r)
	case "/query-log-sync":
		if h.queryLogSync != nil {
			h.queryLogSync.ServeHTTP(w, r)
		} else {
			http.Error(w, "query log sync not enabled", http.StatusNotFound)
		}
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// serveState returns the complete master state (for slave poll).
func (h *Handler) serveState(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	state, err := h.buildState(ctx)
	if err != nil {
		log.Error().Err(err).Msg("cluster: build state failed")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(state); err != nil {
		log.Warn().Err(err).Msg("cluster: encode state failed")
	}
}

// buildState collects the complete state from the FileStore.
func (h *Handler) buildState(ctx context.Context) (*MasterStateResponse, error) {
	state := &MasterStateResponse{}

	// Zones
	zones, err := h.store.ListZones(ctx)
	if err == nil {
		state.Zones, _ = json.Marshal(zones)
	}

	// Blocklist URLs
	urls, err := h.store.ListBlocklistURLs(ctx)
	if err == nil {
		state.BlocklistURLs, _ = json.Marshal(urls)
	}

	// Manual Domains
	manualDomains, err := h.store.ListBlockedDomains(ctx)
	if err == nil {
		state.ManualDomains, _ = json.Marshal(manualDomains)
	}

	// Allowed Domains
	allowedDomains, err := h.store.ListAllowedDomains(ctx)
	if err == nil {
		state.AllowedDomains, _ = json.Marshal(allowedDomains)
	}

	// Whitelist IPs
	whitelistIPs, err := h.store.ListWhitelistIPs(ctx)
	if err == nil {
		state.WhitelistIPs, _ = json.Marshal(whitelistIPs)
	}

	// Auth Config
	authCfg, err := h.store.GetAuthConfig(ctx)
	if err == nil {
		state.AuthConfig, _ = json.Marshal(authCfg)
	}

	// Config Overrides
	overrides, err := h.store.GetConfigOverrides(ctx)
	if err == nil {
		state.ConfigOverrides, _ = json.Marshal(overrides)
	}

	// Blocklist Patterns
	patterns, err := h.store.ListBlocklistPatterns(ctx)
	if err == nil {
		state.BlocklistPatterns, _ = json.Marshal(patterns)
	}

	// TSIG Keys
	tsigKeys, err := h.store.GetTSIGKeys(ctx)
	if err == nil {
		state.TSIGKeys, _ = json.Marshal(tsigKeys)
	}

	return state, nil
}
