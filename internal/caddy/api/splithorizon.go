package api

import (
	"encoding/json"
	"net/http"

	"github.com/mw7101/domudns/internal/config"
	"github.com/rs/zerolog/log"
)

// SplitHorizonUpdater is called after a configuration change.
// Enables live-reload of SplitHorizonResolver without service restart.
type SplitHorizonUpdater func(cfg config.SplitHorizonConfig) error

// SplitHorizonHandler handles GET/PUT /api/split-horizon.
// Persists configuration via ConfigStore (config_overrides.json).
type SplitHorizonHandler struct {
	cfg         *config.Config
	configStore ConfigStore
	updater     SplitHorizonUpdater // optional, nil = no live-reload
}

// NewSplitHorizonHandler creates a new SplitHorizonHandler.
func NewSplitHorizonHandler(cfg *config.Config, configStore ConfigStore, updater SplitHorizonUpdater) *SplitHorizonHandler {
	return &SplitHorizonHandler{
		cfg:         cfg,
		configStore: configStore,
		updater:     updater,
	}
}

// ServeHTTP handles GET and PUT /api/split-horizon.
func (h *SplitHorizonHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.get(w, r)
	case http.MethodPut:
		h.put(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Use GET or PUT")
	}
}

// get returns the current split-horizon configuration.
func (h *SplitHorizonHandler) get(w http.ResponseWriter, r *http.Request) {
	cfg := h.cfg.DNSServer.SplitHorizon
	// Nil slice → serialize as empty array (prevents null in JSON)
	if cfg.Views == nil {
		cfg.Views = []config.SplitHorizonView{}
	}
	writeSuccess(w, cfg, http.StatusOK)
}

// put updates the split-horizon configuration and triggers live-reload.
func (h *SplitHorizonHandler) put(w http.ResponseWriter, r *http.Request) {
	var newCfg config.SplitHorizonConfig
	if err := DecodeJSON(r, &newCfg, 0); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}

	// Validate view names
	for _, view := range newCfg.Views {
		if !isValidViewName(view.Name) {
			writeError(w, http.StatusBadRequest, "INVALID_VIEW",
				"Invalid view name "+view.Name+" (only [a-z0-9_-] allowed)")
			return
		}
		// CIDR subnets are parsed and validated by the resolver during live-reload
	}

	// Persist to config overrides
	if h.configStore != nil {
		ctx := r.Context()
		overrides := map[string]interface{}{
			"dnsserver": map[string]interface{}{
				"split_horizon": newCfg,
			},
		}
		if err := h.configStore.UpdateOverrides(ctx, overrides); err != nil {
			writeInternalError(w, "DB_ERROR", err)
			return
		}
	}

	// Update config in-memory
	h.cfg.DNSServer.SplitHorizon = newCfg

	// Trigger live-reload
	if h.updater != nil {
		if err := h.updater(newCfg); err != nil {
			log.Warn().Err(err).Msg("split-horizon live-reload failed")
		}
	}

	log.Info().
		Bool("enabled", newCfg.Enabled).
		Int("views", len(newCfg.Views)).
		Msg("split-horizon config updated")

	writeSuccess(w, newCfg, http.StatusOK)
}

// splitHorizonConfigFromOverrides extracts SplitHorizonConfig from config overrides.
func splitHorizonConfigFromOverrides(overrides map[string]interface{}) (config.SplitHorizonConfig, bool) {
	var cfg config.SplitHorizonConfig
	dnsRaw, ok := overrides["dnsserver"]
	if !ok {
		return cfg, false
	}
	dnsMap, ok := dnsRaw.(map[string]interface{})
	if !ok {
		return cfg, false
	}
	shRaw, ok := dnsMap["split_horizon"]
	if !ok {
		return cfg, false
	}
	data, err := json.Marshal(shRaw)
	if err != nil {
		return cfg, false
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, false
	}
	return cfg, true
}
