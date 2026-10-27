package cluster

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mw7101/domudns/internal/filestore"
	"github.com/rs/zerolog/log"
)

// statePullEvent is the HMAC type tag binding a slave's GET /api/internal/state
// request (payload = the literal string "state").
const statePullEvent SyncEventType = "state_pull"

// pullURLDomainsEvent is the HMAC type tag binding a slave's
// GET /api/internal/url-domains/{id} request (payload = the URL id).
const pullURLDomainsEvent SyncEventType = "url_domains_pull"

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
	switch {
	case path == "/sync":
		h.receiver.ServeHTTP(w, r)
	case path == "/state":
		if r.Method != http.MethodGet {
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		h.serveState(w, r)
	case strings.HasPrefix(path, "/url-domains/"):
		h.serveURLDomains(w, r, strings.TrimPrefix(path, "/url-domains/"))
	case path == "/query-log-sync":
		if h.queryLogSync != nil {
			h.queryLogSync.ServeHTTP(w, r)
		} else {
			http.Error(w, "query log sync not enabled", http.StatusNotFound)
		}
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// serveURLDomains returns the raw gzip domain set for one blocklist URL.
// It authenticates via the same HMAC secret as sync pushes, binding the URL
// id, a timestamp (replay window) and a one-time nonce. This endpoint exists
// so a slave can repair a per-URL domain set whose EventURLDomains push was
// lost, instead of waiting for the master's next (up to 24h) fetch cycle.
func (h *Handler) serveURLDomains(w http.ResponseWriter, r *http.Request, idStr string) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		http.Error(w, "invalid url id", http.StatusBadRequest)
		return
	}
	secret := h.receiver.secret
	if secret == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ts, err := strconv.ParseInt(r.Header.Get("X-Sync-Timestamp"), 10, 64)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	nonce := r.Header.Get("X-Sync-Nonce")
	provided := r.Header.Get("X-Sync-HMAC")

	diff := time.Now().Unix() - ts/int64(time.Second)
	if diff < 0 {
		diff = -diff
	}
	if diff > replayWindowSec {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := validateHMAC(secret, pullURLDomainsEvent, ts, nonce, []byte(strconv.Itoa(id)), provided); err != nil {
		log.Warn().Str("remote", r.RemoteAddr).Int("url_id", id).Msg("cluster: invalid url domains pull HMAC")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := h.receiver.checkAndStoreNonce(nonce); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	data, err := h.store.ReadURLDomainsGz(id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	if _, err := w.Write(data); err != nil {
		log.Warn().Err(err).Int("url_id", id).Msg("cluster: write url domains response failed")
	}
}

// serveState returns the complete master state (for slave poll).
// It requires HMAC-SHA256 authentication (payload = "state") to prevent
// leaking sensitive data (TLS keys, TSIG keys, NamedAPIKeys) over the
// unauthenticated cluster network.
func (h *Handler) serveState(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	secret := h.receiver.secret
	if secret == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ts, err := strconv.ParseInt(r.Header.Get("X-Sync-Timestamp"), 10, 64)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	nonce := r.Header.Get("X-Sync-Nonce")
	provided := r.Header.Get("X-Sync-HMAC")

	diff := time.Now().Unix() - ts/int64(time.Second)
	if diff < 0 {
		diff = -diff
	}
	if diff > replayWindowSec {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := validateHMAC(secret, statePullEvent, ts, nonce, []byte("state"), provided); err != nil {
		log.Warn().Str("remote", r.RemoteAddr).Msg("cluster: invalid state pull HMAC")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := h.receiver.checkAndStoreNonce(nonce); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

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

// setStateSection fetches one master-state section via get and, on
// success, marshals it into *dst. A fetch error is intentionally silent —
// the field is simply omitted (nil) so buildState still returns everything
// else it could gather.
func setStateSection[T any](ctx context.Context, dst *json.RawMessage, get func(context.Context) (T, error)) {
	v, err := get(ctx)
	if err != nil {
		return
	}
	*dst, _ = json.Marshal(v)
}

// setStateSectionLogged is setStateSection for the two sections (TLS ACME
// config, TLS cert) that log a warning on fetch error instead of failing
// silently, and only marshal a non-nil result. logMsg must never mention
// key material — GetTLSCert's KeyPEM must never be logged.
func setStateSectionLogged[T any](ctx context.Context, dst *json.RawMessage, get func(context.Context) (*T, error), logMsg string) {
	v, err := get(ctx)
	if err != nil {
		log.Warn().Err(err).Msg(logMsg)
		return
	}
	if v != nil {
		*dst, _ = json.Marshal(v)
	}
}

// buildState collects the complete state from the FileStore.
func (h *Handler) buildState(ctx context.Context) (*MasterStateResponse, error) {
	state := &MasterStateResponse{}

	setStateSection(ctx, &state.Zones, h.store.ListZones)
	setStateSection(ctx, &state.BlocklistURLs, h.store.ListBlocklistURLs)
	setStateSection(ctx, &state.ManualDomains, h.store.ListBlockedDomains)
	setStateSection(ctx, &state.AllowedDomains, h.store.ListAllowedDomains)
	setStateSection(ctx, &state.WhitelistIPs, h.store.ListWhitelistIPs)
	setStateSection(ctx, &state.AuthConfig, h.store.GetAuthConfig)
	setStateSection(ctx, &state.ConfigOverrides, h.store.GetConfigOverrides)
	setStateSection(ctx, &state.BlocklistPatterns, h.store.ListBlocklistPatterns)
	setStateSection(ctx, &state.TSIGKeys, h.store.GetTSIGKeys)
	// Named API Keys (including key values for slave-side validation)
	setStateSection(ctx, &state.NamedAPIKeys, h.store.GetAllNamedAPIKeys)
	setStateSection(ctx, &state.ClientGroups, h.store.GetClientGroups)
	setStateSection(ctx, &state.URLDomainsMeta, func(context.Context) ([]filestore.URLDomainMeta, error) {
		return h.store.ListURLDomainsMeta()
	})

	setStateSectionLogged(ctx, &state.TLSACMEConfig, h.store.GetTLSACMEConfig, "cluster: load TLS ACME config failed")
	setStateSectionLogged(ctx, &state.TLSCert, h.store.GetTLSCert, "cluster: load TLS cert failed")

	return state, nil
}
