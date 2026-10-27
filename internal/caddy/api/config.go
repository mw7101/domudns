package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/mw7101/domudns/internal/config"
)

// ConfigStore reads and writes config overrides (Postgres or etcd).
type ConfigStore interface {
	GetOverrides(ctx context.Context) (map[string]interface{}, error)
	UpdateOverrides(ctx context.Context, overrides map[string]interface{}) error
}

// ConfigReloader is called after a successful PATCH /api/config.
// Enables live-reload of settings without service restart.
// Returns updated *config.Config (after MergeOverrides).
type ConfigReloader func(cfg *config.Config) error

// ConfigHandler serves GET and PATCH /api/config.
type ConfigHandler struct {
	cfg         *config.Config
	configStore ConfigStore
	reloader    ConfigReloader // optional, nil = no live-reload
}

// NewConfigHandler creates a config handler.
func NewConfigHandler(cfg *config.Config, configStore ConfigStore) *ConfigHandler {
	return &ConfigHandler{cfg: cfg, configStore: configStore}
}

// SetReloader registers a callback for live-reload after config changes.
func (h *ConfigHandler) SetReloader(r ConfigReloader) {
	h.reloader = r
}

// configResponse is the safe view of config (api_key redacted).
type configResponse struct {
	DNSServer   config.DNSServerConfig   `json:"dnsserver"`
	Caddy       config.CaddyConfig       `json:"caddy"`
	Acme        config.AcmeConfig        `json:"acme"`
	Blocklist   config.BlocklistConfig   `json:"blocklist"`
	System      configSystemSafe         `json:"system"`
	Performance config.PerformanceConfig `json:"performance"`
}

type configSystemSafe struct {
	LogLevel  string                       `json:"log_level"`
	LogFormat string                       `json:"log_format"`
	Metrics   config.SystemMetricsConfig   `json:"metrics"`
	Auth      configAuthSafe               `json:"auth"`
	RateLimit config.SystemRateLimitConfig `json:"rate_limit"`
	Security  config.SystemSecurityConfig  `json:"security"`
}

type configAuthSafe struct {
	APIKey string `json:"api_key"` // "***" when set
}

// editableKeys is the whitelist of top-level config keys that may be patched.
var editableKeys = map[string]bool{
	"dnsserver": true, "caddy": true, "blocklist": true, "system": true, "performance": true,
}

// ServeHTTP implements http.Handler.
func (h *ConfigHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.serveGet(w)
		return
	case http.MethodPatch:
		h.servePatch(w, r)
		return
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET or PATCH required")
		return
	}
}

func (h *ConfigHandler) serveGet(w http.ResponseWriter) {
	resp := configResponse{
		DNSServer:   h.cfg.DNSServer,
		Caddy:       h.cfg.Caddy,
		Acme:        h.cfg.Acme,
		Blocklist:   h.cfg.Blocklist,
		Performance: h.cfg.Performance,
		System: configSystemSafe{
			LogLevel:  h.cfg.System.LogLevel,
			LogFormat: h.cfg.System.LogFormat,
			Metrics:   h.cfg.System.Metrics,
			RateLimit: h.cfg.System.RateLimit,
			Security:  h.cfg.System.Security,
			Auth: configAuthSafe{
				APIKey: "***",
			},
		},
	}
	writeSuccess(w, resp, http.StatusOK)
}

func (h *ConfigHandler) servePatch(w http.ResponseWriter, r *http.Request) {
	if h.configStore == nil {
		writeError(w, http.StatusServiceUnavailable, "CONFIG_STORE_UNAVAILABLE", "Config updates not available")
		return
	}
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Request body must be valid JSON")
		return
	}
	// Filter to editable keys only
	overrides := make(map[string]interface{})
	for k, v := range body {
		if editableKeys[k] && v != nil {
			overrides[k] = v
		}
	}
	if len(overrides) == 0 {
		writeSuccess(w, map[string]string{"message": "No editable fields to update"}, http.StatusOK)
		return
	}
	if err := h.configStore.UpdateOverrides(r.Context(), overrides); err != nil {
		writeError(w, http.StatusInternalServerError, "UPDATE_FAILED", err.Error())
		return
	}
	// Merge into in-memory config so GET reflects new values immediately
	if err := config.MergeOverrides(h.cfg, overrides); err != nil {
		writeError(w, http.StatusInternalServerError, "MERGE_FAILED", err.Error())
		return
	}
	// Live-reload: apply settings immediately (without restart)
	if h.reloader != nil {
		if err := h.reloader(h.cfg); err != nil {
			// No error to client — config is saved, reload is optional
			writeSuccess(w, map[string]string{"message": "Config updated. Live reload partially failed — some changes require restart."}, http.StatusOK)
			return
		}
	}
	writeSuccess(w, map[string]string{"message": "Config updated. Some changes may require restart."}, http.StatusOK)
}
