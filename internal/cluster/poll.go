package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/mw7101/domudns/internal/dns"
	"github.com/mw7101/domudns/internal/filestore"
	"github.com/mw7101/domudns/internal/store"
	"github.com/rs/zerolog/log"
)

// RunPollLoop starts the slave poll loop that periodically fetches master state.
// Started as goroutine and blocks until ctx is cancelled.
func RunPollLoop(ctx context.Context, masterURL string, fs *filestore.FileStore, interval time.Duration, callbacks ReloadCallbacks) error {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	client := &http.Client{Timeout: 30 * time.Second}

	log.Info().Str("master", masterURL).Dur("interval", interval).Msg("cluster: slave poll loop started")

	// Initial poll immediately on start
	if err := pollMaster(ctx, client, masterURL, fs, callbacks); err != nil {
		log.Warn().Err(err).Msg("cluster: initial poll failed")
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := pollMaster(ctx, client, masterURL, fs, callbacks); err != nil {
				log.Warn().Err(err).Msg("cluster: poll failed")
			}
		}
	}
}

// pollMaster fetches master state and applies it to the local FileStore.
func pollMaster(ctx context.Context, client *http.Client, masterURL string, fs *filestore.FileStore, callbacks ReloadCallbacks) error {
	url := masterURL + "/api/internal/state"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("get state: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("master returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024)) // max 32MB
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	var state MasterStateResponse
	if err := json.Unmarshal(body, &state); err != nil {
		return fmt.Errorf("parse state: %w", err)
	}

	return applyMasterState(ctx, fs, state, callbacks)
}

// applyMasterState applies master state to the local FileStore.
func applyMasterState(ctx context.Context, fs *filestore.FileStore, state MasterStateResponse, callbacks ReloadCallbacks) error {
	zonesChanged := false
	blocklistChanged := false
	authChanged := false

	// Zones
	if len(state.Zones) > 0 && string(state.Zones) != "null" {
		var zones []*dns.Zone
		if err := json.Unmarshal(state.Zones, &zones); err == nil {
			for _, z := range zones {
				if err := fs.PutZone(ctx, z); err != nil {
					log.Warn().Err(err).Str("zone", z.Domain).Msg("cluster: apply zone failed")
				}
			}
			zonesChanged = true
		}
	}

	// BlocklistURLs
	if len(state.BlocklistURLs) > 0 && string(state.BlocklistURLs) != "null" {
		var urls []store.BlocklistURL
		if err := json.Unmarshal(state.BlocklistURLs, &urls); err == nil {
			if err := fs.SetBlocklistURLs(ctx, urls); err != nil {
				log.Warn().Err(err).Msg("cluster: apply blocklist urls failed")
			}
		}
	}

	// ManualDomains
	if len(state.ManualDomains) > 0 && string(state.ManualDomains) != "null" {
		var domains []string
		if err := json.Unmarshal(state.ManualDomains, &domains); err == nil {
			if err := fs.SetManualDomains(ctx, domains); err != nil {
				log.Warn().Err(err).Msg("cluster: apply manual domains failed")
			}
			blocklistChanged = true
		}
	}

	// AllowedDomains
	if len(state.AllowedDomains) > 0 && string(state.AllowedDomains) != "null" {
		var domains []string
		if err := json.Unmarshal(state.AllowedDomains, &domains); err == nil {
			if err := fs.SetAllowedDomains(ctx, domains); err != nil {
				log.Warn().Err(err).Msg("cluster: apply allowed domains failed")
			}
			blocklistChanged = true
		}
	}

	// WhitelistIPs
	if len(state.WhitelistIPs) > 0 && string(state.WhitelistIPs) != "null" {
		var ips []string
		if err := json.Unmarshal(state.WhitelistIPs, &ips); err == nil {
			if err := fs.SetWhitelistIPs(ctx, ips); err != nil {
				log.Warn().Err(err).Msg("cluster: apply whitelist ips failed")
			}
			blocklistChanged = true
		}
	}

	// AuthConfig
	if len(state.AuthConfig) > 0 && string(state.AuthConfig) != "null" {
		var cfg store.AuthConfig
		if err := json.Unmarshal(state.AuthConfig, &cfg); err == nil {
			if err := fs.UpdateAuthConfig(ctx, &cfg); err != nil {
				log.Warn().Err(err).Msg("cluster: apply auth config failed")
			}
			authChanged = true
		}
	}

	// ConfigOverrides
	if len(state.ConfigOverrides) > 0 && string(state.ConfigOverrides) != "null" {
		var overrides map[string]interface{}
		if err := json.Unmarshal(state.ConfigOverrides, &overrides); err == nil {
			if err := fs.SetConfigOverrides(ctx, overrides); err != nil {
				log.Warn().Err(err).Msg("cluster: apply config overrides failed")
			}
		}
	}

	// BlocklistPatterns
	if len(state.BlocklistPatterns) > 0 && string(state.BlocklistPatterns) != "null" {
		var patterns []store.BlocklistPattern
		if err := json.Unmarshal(state.BlocklistPatterns, &patterns); err == nil {
			if err := fs.SetBlocklistPatterns(ctx, patterns); err != nil {
				log.Warn().Err(err).Msg("cluster: apply blocklist patterns failed")
			}
			blocklistChanged = true
		}
	}

	// TSIGKeys
	tsigChanged := false
	if len(state.TSIGKeys) > 0 && string(state.TSIGKeys) != "null" {
		var keys []store.TSIGKey
		if err := json.Unmarshal(state.TSIGKeys, &keys); err == nil {
			if err := fs.SetTSIGKeys(ctx, keys); err != nil {
				log.Warn().Err(err).Msg("cluster: apply tsig keys failed")
			}
			tsigChanged = true
		}
	}

	// Reload-Callbacks triggern
	if zonesChanged && callbacks.ZoneReloader != nil {
		go func() {
			if err := callbacks.ZoneReloader(); err != nil {
				log.Warn().Err(err).Msg("cluster: zone reload after poll failed")
			}
		}()
	}
	if blocklistChanged && callbacks.BlocklistReloader != nil {
		go func() {
			if err := callbacks.BlocklistReloader(); err != nil {
				log.Warn().Err(err).Msg("cluster: blocklist reload after poll failed")
			}
		}()
	}
	if authChanged && callbacks.AuthReloader != nil {
		go func() {
			if err := callbacks.AuthReloader(); err != nil {
				log.Warn().Err(err).Msg("cluster: auth reload after poll failed")
			}
		}()
	}
	if tsigChanged && callbacks.DDNSKeyReloader != nil {
		go func() {
			if err := callbacks.DDNSKeyReloader(); err != nil {
				log.Warn().Err(err).Msg("cluster: ddns key reload after poll failed")
			}
		}()
	}

	return nil
}
