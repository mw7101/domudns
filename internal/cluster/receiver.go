package cluster

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mw7101/domudns/internal/dns"
	"github.com/mw7101/domudns/internal/filestore"
	"github.com/mw7101/domudns/internal/store"
	"github.com/rs/zerolog/log"
)

// ReloadCallbacks contains callback functions for DNS server reloads after sync events.
type ReloadCallbacks struct {
	// ZoneReloader is called after zone events.
	ZoneReloader func() error
	// BlocklistReloader is called after blocklist/whitelist events.
	BlocklistReloader func() error
	// AuthReloader is called after auth events.
	AuthReloader func() error
	// DDNSKeyReloader is called after TSIG key events (nil = no reload).
	DDNSKeyReloader func() error
}

// replayWindowSec is the maximum age difference (seconds) allowed between
// the event timestamp and the current time. Events outside this window are rejected.
const replayWindowSec = 300 // 5 minutes

// nonceTTL is how long a seen nonce is kept in memory. Must be > replayWindowSec.
const nonceTTL = 10 * time.Minute

// ReceiverHandler receives sync events from the master and updates the local FileStore.
type ReceiverHandler struct {
	store      *filestore.FileStore
	secret     string
	callbacks  ReloadCallbacks
	nonceMu    sync.Mutex
	seenNonces map[string]time.Time // nonce → time received; cleaned up periodically
}

// NewReceiverHandler creates a new ReceiverHandler.
func NewReceiverHandler(store *filestore.FileStore, secret string, callbacks ReloadCallbacks) *ReceiverHandler {
	return &ReceiverHandler{
		store:      store,
		secret:     secret,
		callbacks:  callbacks,
		seenNonces: make(map[string]time.Time),
	}
}

// ServeHTTP handles POST /api/internal/sync.
func (h *ReceiverHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 16*1024*1024)) // max 16MB
	if err != nil {
		http.Error(w, "read body failed", http.StatusBadRequest)
		return
	}
	var req SyncRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	// Validate HMAC — secret is always required; no secret = reject all sync requests
	providedHMAC := r.Header.Get("X-Sync-HMAC")
	if h.secret == "" {
		log.Error().
			Str("remote", r.RemoteAddr).
			Msg("cluster: sync rejected — no HMAC secret configured")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := validateHMAC(h.secret, req.Type, req.Timestamp, req.Nonce, req.Data, providedHMAC); err != nil {
		log.Warn().
			Str("event", string(req.Type)).
			Str("remote", r.RemoteAddr).
			Msg("cluster: invalid sync HMAC")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Validate timestamp: reject events more than replayWindowSec seconds old or in the future.
	nowSec := time.Now().Unix()
	tsSec := req.Timestamp / 1_000_000_000
	diff := nowSec - tsSec
	if diff < 0 {
		diff = -diff
	}
	if diff > replayWindowSec {
		log.Warn().
			Str("remote", r.RemoteAddr).
			Int64("ts_diff_sec", diff).
			Msg("cluster: sync rejected — timestamp outside replay window")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Validate nonce: reject replayed requests with duplicate nonces.
	if err := h.checkAndStoreNonce(req.Nonce); err != nil {
		log.Warn().
			Str("remote", r.RemoteAddr).
			Msg("cluster: sync rejected — duplicate nonce")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	if err := h.applyEvent(ctx, req); err != nil {
		log.Error().Err(err).Str("event", string(req.Type)).Msg("cluster: apply event failed")
		http.Error(w, "apply failed", http.StatusInternalServerError)
		return
	}
	log.Debug().Str("event", string(req.Type)).Msg("cluster: sync event applied")
	w.WriteHeader(http.StatusNoContent)
}

// applyEvent applies a sync event to the local FileStore.
func (h *ReceiverHandler) applyEvent(ctx context.Context, req SyncRequest) error {
	switch req.Type {
	case EventZoneUpdated:
		return h.applyZoneUpdated(ctx, req.Data)
	case EventZoneDeleted:
		return h.applyZoneDeleted(ctx, req.Data)
	case EventBlocklistURLs:
		return h.applyBlocklistURLs(ctx, req.Data)
	case EventManualDomains:
		return h.applyManualDomains(ctx, req.Data)
	case EventAllowedDomains:
		return h.applyAllowedDomains(ctx, req.Data)
	case EventWhitelistIPs:
		return h.applyWhitelistIPs(ctx, req.Data)
	case EventURLDomains:
		return h.applyURLDomains(ctx, req.Data)
	case EventAuthConfig:
		return h.applyAuthConfig(ctx, req.Data)
	case EventConfigOverrides:
		return h.applyConfigOverrides(ctx, req.Data)
	case EventBlocklistPatterns:
		return h.applyBlocklistPatterns(ctx, req.Data)
	case EventTSIGKeys:
		return h.applyTSIGKeys(ctx, req.Data)
	case EventAPIKeys:
		return h.applyAPIKeys(ctx, req.Data)
	default:
		log.Warn().Str("event", string(req.Type)).Msg("cluster: unknown event type, ignoring")
		return nil
	}
}

func (h *ReceiverHandler) applyZoneUpdated(ctx context.Context, data json.RawMessage) error {
	var zone dns.Zone
	if err := json.Unmarshal(data, &zone); err != nil {
		return fmt.Errorf("unmarshal zone: %w", err)
	}
	if err := dns.ValidateZone(&zone); err != nil {
		return fmt.Errorf("validate zone: %w", err)
	}
	if err := h.store.PutZone(ctx, &zone); err != nil {
		return fmt.Errorf("put zone: %w", err)
	}
	h.triggerZoneReload()
	return nil
}

func (h *ReceiverHandler) applyZoneDeleted(ctx context.Context, data json.RawMessage) error {
	var key string
	if err := json.Unmarshal(data, &key); err != nil {
		return fmt.Errorf("unmarshal domain: %w", err)
	}
	// Format: "domain" (default zone) or "domain@view" (view zone)
	if idx := strings.LastIndex(key, "@"); idx >= 0 {
		domain := key[:idx]
		view := key[idx+1:]
		if err := h.store.DeleteZoneView(ctx, domain, view); err != nil {
			return fmt.Errorf("delete zone view: %w", err)
		}
	} else {
		if err := h.store.DeleteZone(ctx, key); err != nil {
			return fmt.Errorf("delete zone: %w", err)
		}
	}
	h.triggerZoneReload()
	return nil
}

func (h *ReceiverHandler) applyBlocklistURLs(ctx context.Context, data json.RawMessage) error {
	var urls []store.BlocklistURL
	if err := json.Unmarshal(data, &urls); err != nil {
		return fmt.Errorf("unmarshal urls: %w", err)
	}
	if err := h.store.SetBlocklistURLs(ctx, urls); err != nil {
		return fmt.Errorf("set urls: %w", err)
	}
	return nil
}

func (h *ReceiverHandler) applyManualDomains(ctx context.Context, data json.RawMessage) error {
	var domains []string
	if err := json.Unmarshal(data, &domains); err != nil {
		return fmt.Errorf("unmarshal domains: %w", err)
	}
	if err := h.store.SetManualDomains(ctx, domains); err != nil {
		return fmt.Errorf("set manual domains: %w", err)
	}
	h.triggerBlocklistReload()
	return nil
}

func (h *ReceiverHandler) applyAllowedDomains(ctx context.Context, data json.RawMessage) error {
	var domains []string
	if err := json.Unmarshal(data, &domains); err != nil {
		return fmt.Errorf("unmarshal allowed: %w", err)
	}
	if err := h.store.SetAllowedDomains(ctx, domains); err != nil {
		return fmt.Errorf("set allowed: %w", err)
	}
	h.triggerBlocklistReload()
	return nil
}

func (h *ReceiverHandler) applyWhitelistIPs(ctx context.Context, data json.RawMessage) error {
	var ips []string
	if err := json.Unmarshal(data, &ips); err != nil {
		return fmt.Errorf("unmarshal ips: %w", err)
	}
	if err := h.store.SetWhitelistIPs(ctx, ips); err != nil {
		return fmt.Errorf("set whitelist: %w", err)
	}
	h.triggerBlocklistReload()
	return nil
}

// maxDecompressedSize limits decompressed blocklist data to 16 MB (protection against ZIP bombs).
const maxDecompressedSize = 16 * 1024 * 1024

func (h *ReceiverHandler) applyURLDomains(ctx context.Context, data json.RawMessage) error {
	var payload URLDomainsPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("unmarshal url domains: %w", err)
	}
	// base64 → gzip-decode → domains
	gzBytes, err := base64.StdEncoding.DecodeString(payload.DomainsGzB64)
	if err != nil {
		return fmt.Errorf("base64 decode: %w", err)
	}
	gr, err := gzip.NewReader(strings.NewReader(string(gzBytes)))
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gr.Close()
	rawBytes, err := io.ReadAll(io.LimitReader(gr, maxDecompressedSize))
	if err != nil {
		return fmt.Errorf("gzip read: %w", err)
	}
	domains := strings.Split(string(rawBytes), "\n")
	cleaned := make([]string, 0, len(domains))
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d != "" {
			cleaned = append(cleaned, d)
		}
	}
	if err := h.store.SetBlocklistURLDomains(ctx, payload.URLID, cleaned); err != nil {
		return fmt.Errorf("set url domains: %w", err)
	}
	h.triggerBlocklistReload()
	return nil
}

func (h *ReceiverHandler) applyAuthConfig(ctx context.Context, data json.RawMessage) error {
	var cfg store.AuthConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("unmarshal auth: %w", err)
	}
	if err := h.store.UpdateAuthConfig(ctx, &cfg); err != nil {
		return fmt.Errorf("update auth: %w", err)
	}
	if h.callbacks.AuthReloader != nil {
		go func() {
			if err := h.callbacks.AuthReloader(); err != nil {
				log.Warn().Err(err).Msg("cluster: auth reload failed")
			}
		}()
	}
	return nil
}

func (h *ReceiverHandler) applyConfigOverrides(ctx context.Context, data json.RawMessage) error {
	var overrides map[string]interface{}
	if err := json.Unmarshal(data, &overrides); err != nil {
		return fmt.Errorf("unmarshal overrides: %w", err)
	}
	return h.store.SetConfigOverrides(ctx, overrides)
}

func (h *ReceiverHandler) applyBlocklistPatterns(ctx context.Context, data json.RawMessage) error {
	var patterns []store.BlocklistPattern
	if err := json.Unmarshal(data, &patterns); err != nil {
		return fmt.Errorf("unmarshal patterns: %w", err)
	}
	if err := h.store.SetBlocklistPatterns(ctx, patterns); err != nil {
		return fmt.Errorf("set patterns: %w", err)
	}
	h.triggerBlocklistReload()
	return nil
}

func (h *ReceiverHandler) applyTSIGKeys(ctx context.Context, data json.RawMessage) error {
	var keys []store.TSIGKey
	if err := json.Unmarshal(data, &keys); err != nil {
		return fmt.Errorf("unmarshal tsig keys: %w", err)
	}
	if err := h.store.SetTSIGKeys(ctx, keys); err != nil {
		return fmt.Errorf("set tsig keys: %w", err)
	}
	if h.callbacks.DDNSKeyReloader != nil {
		go func() {
			if err := h.callbacks.DDNSKeyReloader(); err != nil {
				log.Warn().Err(err).Msg("cluster: ddns key reload failed")
			}
		}()
	}
	return nil
}

func (h *ReceiverHandler) applyAPIKeys(ctx context.Context, data json.RawMessage) error {
	var keys []store.NamedAPIKey
	if err := json.Unmarshal(data, &keys); err != nil {
		return fmt.Errorf("unmarshal api keys: %w", err)
	}
	if err := h.store.SetNamedAPIKeys(ctx, keys); err != nil {
		return fmt.Errorf("set api keys: %w", err)
	}
	return nil
}

// checkAndStoreNonce verifies that nonce has not been seen before and records it.
// Old nonces (older than nonceTTL) are evicted on each call.
// Returns an error if the nonce is empty or was already seen.
func (h *ReceiverHandler) checkAndStoreNonce(nonce string) error {
	if nonce == "" {
		return fmt.Errorf("empty nonce")
	}
	h.nonceMu.Lock()
	defer h.nonceMu.Unlock()
	cutoff := time.Now().Add(-nonceTTL)
	for n, t := range h.seenNonces {
		if t.Before(cutoff) {
			delete(h.seenNonces, n)
		}
	}
	if _, exists := h.seenNonces[nonce]; exists {
		return fmt.Errorf("duplicate nonce")
	}
	h.seenNonces[nonce] = time.Now()
	return nil
}

// reloadTimeout limits the maximum time for an async reload callback.
const reloadTimeout = 30 * time.Second

func (h *ReceiverHandler) triggerZoneReload() {
	if h.callbacks.ZoneReloader == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), reloadTimeout)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- h.callbacks.ZoneReloader() }()
		select {
		case err := <-done:
			if err != nil {
				log.Warn().Err(err).Msg("cluster: zone reload failed")
			}
		case <-ctx.Done():
			log.Error().Msg("cluster: zone reload timed out")
		}
	}()
}

func (h *ReceiverHandler) triggerBlocklistReload() {
	if h.callbacks.BlocklistReloader == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), reloadTimeout)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- h.callbacks.BlocklistReloader() }()
		select {
		case err := <-done:
			if err != nil {
				log.Warn().Err(err).Msg("cluster: blocklist reload failed")
			}
		case <-ctx.Done():
			log.Error().Msg("cluster: blocklist reload timed out")
		}
	}()
}
