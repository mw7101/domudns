package cluster

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/mw7101/domudns/internal/dns"
	"github.com/mw7101/domudns/internal/filestore"
	"github.com/mw7101/domudns/internal/store"
	"github.com/rs/zerolog/log"
)

// pollState tracks SHA256 checksums of the last-seen master state sections.
// A section triggers a reload callback only when its checksum changes.
type pollState struct {
	zones             [32]byte
	manualDomains     [32]byte
	allowedDomains    [32]byte
	whitelistIPs      [32]byte
	blocklistPatterns [32]byte
	tsigKeys          [32]byte
	authConfig        [32]byte
	clientGroups      [32]byte
	tlsCert           [32]byte
}

// sectionChanged returns true if data's SHA256 differs from *prev and updates *prev.
func sectionChanged(prev *[32]byte, data json.RawMessage) bool {
	h := sha256.Sum256(data)
	if h == *prev {
		return false
	}
	*prev = h
	return true
}

// RunPollLoop starts the slave poll loop that periodically fetches master state.
// Started as goroutine and blocks until ctx is cancelled.
func RunPollLoop(ctx context.Context, masterURL, secret string, fs *filestore.FileStore, interval time.Duration, callbacks ReloadCallbacks) error {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	client := &http.Client{Timeout: 30 * time.Second}
	var ps pollState

	log.Info().Str("master", masterURL).Dur("interval", interval).Msg("cluster: slave poll loop started")

	// Initial poll immediately on start
	if err := pollMaster(ctx, client, masterURL, secret, fs, callbacks, &ps); err != nil {
		log.Warn().Err(err).Msg("cluster: initial poll failed")
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := pollMaster(ctx, client, masterURL, secret, fs, callbacks, &ps); err != nil {
				log.Warn().Err(err).Msg("cluster: poll failed")
			}
		}
	}
}

// pollMaster fetches master state and applies it to the local FileStore.
// It authenticates with HMAC-SHA256 (payload = "state") to prevent
// leaking sensitive data (TLS keys, TSIG keys, NamedAPIKeys).
func pollMaster(ctx context.Context, client *http.Client, masterURL, secret string, fs *filestore.FileStore, callbacks ReloadCallbacks, ps *pollState) error {
	url := masterURL + "/api/internal/state"
	ts := time.Now().UnixNano()
	nonce, err := newNonce()
	if err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	sig := computeHMAC(secret, statePullEvent, ts, nonce, []byte("state"))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("X-Sync-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Sync-Nonce", nonce)
	req.Header.Set("X-Sync-HMAC", sig)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("get state: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

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

	if err := applyMasterState(ctx, fs, state, callbacks, ps); err != nil {
		return err
	}
	syncURLDomains(ctx, client, masterURL, secret, fs, callbacks, state.URLDomainsMeta)
	return nil
}

// maxDomainGzSize bounds a pulled per-URL gzip blob (a few MB for 200k+ domains).
const maxDomainGzSize = 32 * 1024 * 1024

// syncURLDomains pulls per-URL domain sets whose checksum differs from the
// local one. This makes a lost EventURLDomains push self-healing: the slave
// no longer waits up to the full fetch interval (24h) for the next push.
// The master's URL domain lists are too large for the state response, so only
// {url_id, sha256} metadata is polled and the payload is fetched on demand.
func syncURLDomains(ctx context.Context, client *http.Client, masterURL, secret string, fs *filestore.FileStore, callbacks ReloadCallbacks, raw json.RawMessage) {
	if secret == "" || !sectionPresent(raw) {
		return
	}
	var master []filestore.URLDomainMeta
	if err := json.Unmarshal(raw, &master); err != nil || len(master) == 0 {
		return
	}
	localList, err := fs.ListURLDomainsMeta()
	if err != nil {
		log.Warn().Err(err).Msg("cluster: list local url domains meta failed")
		return
	}
	local := make(map[int]string, len(localList))
	for _, m := range localList {
		local[m.URLID] = m.SHA256
	}
	for _, m := range master {
		if m.SHA256 != "" && local[m.URLID] == m.SHA256 {
			continue
		}
		if err := pullURLDomains(ctx, client, masterURL, secret, fs, callbacks, m.URLID, m.SHA256); err != nil {
			log.Warn().Err(err).Int("url_id", m.URLID).Msg("cluster: pull url domains failed")
			continue
		}
		log.Info().Int("url_id", m.URLID).Msg("cluster: pulled stale url domains from master")
	}
}

// pullURLDomains fetches one per-URL domain set from the master, stores the
// exact gzip bytes (so the checksum matches the master's) and refreshes the
// running blocklist in memory.
func pullURLDomains(ctx context.Context, client *http.Client, masterURL, secret string, fs *filestore.FileStore, callbacks ReloadCallbacks, urlID int, wantSHA string) error {
	if urlID <= 0 {
		return fmt.Errorf("invalid url id %d", urlID)
	}
	ts := time.Now().UnixNano()
	nonce, err := newNonce()
	if err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	sig := computeHMAC(secret, pullURLDomainsEvent, ts, nonce, []byte(strconv.Itoa(urlID)))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/api/internal/url-domains/%d", masterURL, urlID), nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("X-Sync-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Sync-Nonce", nonce)
	req.Header.Set("X-Sync-HMAC", sig)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("get url domains: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("master returned %d", resp.StatusCode)
	}
	gzBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxDomainGzSize+1))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if len(gzBytes) > maxDomainGzSize {
		return fmt.Errorf("url domains payload exceeds %d bytes", maxDomainGzSize)
	}
	if wantSHA != "" {
		sum := sha256.Sum256(gzBytes)
		if hex.EncodeToString(sum[:]) != wantSHA {
			return fmt.Errorf("checksum mismatch: master advertised %s", wantSHA)
		}
	}
	// Validate (decompress) before persisting so a corrupt or truncated
	// payload never reaches disk; otherwise every poll would re-pull the
	// same stale set forever.
	domains, err := decodeDomainsGz(gzBytes)
	if err != nil {
		return fmt.Errorf("decode url domains: %w", err)
	}
	if err := fs.WriteURLDomainsGz(urlID, gzBytes); err != nil {
		return fmt.Errorf("store url domains: %w", err)
	}
	if callbacks.BlocklistURLDomainsUpdater != nil {
		callbacks.BlocklistURLDomainsUpdater(urlID, urlCategory(ctx, fs, urlID), domains)
	} else if callbacks.BlocklistReloader != nil {
		callbacks.trigger(true, func() error {
			return runReloadWithTimeout(callbacks.BlocklistReloader, "blocklist")
		}, "blocklist")
	}
	return nil
}

// sectionPresent reports whether a master-state section was actually sent
// (as opposed to an omitted/JSON-null field).
func sectionPresent(raw json.RawMessage) bool {
	return len(raw) > 0 && string(raw) != "null"
}

// applySection is the shared shape behind the nine apply<Section> functions
// below: skip if the section is absent or unchanged since the last poll (by
// SHA256 checksum via sectionPresent/sectionChanged — semantics unchanged),
// else unmarshal raw into a T and hand it to apply.
//
// apply is responsible for calling the right FileStore setter and logging
// any failure itself; its own return value decides whether that failure
// also suppresses the "changed" result:
//   - the seven best-effort sections (zones, manual/allowed domains,
//     whitelist IPs, auth config, blocklist patterns, TSIG keys) always
//     return nil from apply, so a successful unmarshal alone is enough to
//     report changed — matching their original all-or-nothing-unmarshal,
//     best-effort-apply semantics.
//   - applyTLSCertSection and applyClientGroupsSection return the store
//     error from apply, so changed is reported only when the write itself
//     succeeds (a hot-reload with an unwritten value would be worse than no
//     reload) — matching their original semantics too.
func applySection[T any](raw json.RawMessage, prev *[32]byte, apply func(T) error) bool {
	if !sectionPresent(raw) || !sectionChanged(prev, raw) {
		return false
	}
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		return false
	}
	return apply(v) == nil
}

// applyZonesSection applies the Zones section. Reports true (triggering a
// zone reload) as soon as the section unmarshals, even if individual zones
// fail to apply (logged per zone) — matches the original all-or-nothing-
// unmarshal, best-effort-apply semantics.
func applyZonesSection(ctx context.Context, fs *filestore.FileStore, raw json.RawMessage, prev *[32]byte) bool {
	return applySection(raw, prev, func(zones []*dns.Zone) error {
		for _, z := range zones {
			if err := fs.PutZone(ctx, z); err != nil {
				log.Warn().Err(err).Str("zone", z.Domain).Msg("cluster: apply zone failed")
			}
		}
		return nil
	})
}

// applyBlocklistURLsSection applies BlocklistURLs. No reload callback exists
// for it, so it isn't checksum-gated — it's simply reapplied every poll.
func applyBlocklistURLsSection(ctx context.Context, fs *filestore.FileStore, raw json.RawMessage) {
	if !sectionPresent(raw) {
		return
	}
	var urls []store.BlocklistURL
	if err := json.Unmarshal(raw, &urls); err != nil {
		return
	}
	if err := fs.SetBlocklistURLs(ctx, urls); err != nil {
		log.Warn().Err(err).Msg("cluster: apply blocklist urls failed")
	}
}

func applyManualDomainsSection(ctx context.Context, fs *filestore.FileStore, raw json.RawMessage, prev *[32]byte) bool {
	return applySection(raw, prev, func(domains []string) error {
		if err := fs.SetManualDomains(ctx, domains); err != nil {
			log.Warn().Err(err).Msg("cluster: apply manual domains failed")
		}
		return nil
	})
}

func applyAllowedDomainsSection(ctx context.Context, fs *filestore.FileStore, raw json.RawMessage, prev *[32]byte) bool {
	return applySection(raw, prev, func(domains []string) error {
		if err := fs.SetAllowedDomains(ctx, domains); err != nil {
			log.Warn().Err(err).Msg("cluster: apply allowed domains failed")
		}
		return nil
	})
}

func applyWhitelistIPsSection(ctx context.Context, fs *filestore.FileStore, raw json.RawMessage, prev *[32]byte) bool {
	return applySection(raw, prev, func(ips []string) error {
		if err := fs.SetWhitelistIPs(ctx, ips); err != nil {
			log.Warn().Err(err).Msg("cluster: apply whitelist ips failed")
		}
		return nil
	})
}

func applyAuthConfigSection(ctx context.Context, fs *filestore.FileStore, raw json.RawMessage, prev *[32]byte) bool {
	return applySection(raw, prev, func(cfg store.AuthConfig) error {
		if err := fs.UpdateAuthConfig(ctx, &cfg); err != nil {
			log.Warn().Err(err).Msg("cluster: apply auth config failed")
		}
		return nil
	})
}

// applyConfigOverridesSection applies ConfigOverrides. No reload callback
// exists for it, so it isn't checksum-gated.
func applyConfigOverridesSection(ctx context.Context, fs *filestore.FileStore, raw json.RawMessage) {
	if !sectionPresent(raw) {
		return
	}
	var overrides map[string]interface{}
	if err := json.Unmarshal(raw, &overrides); err != nil {
		return
	}
	if err := fs.SetConfigOverrides(ctx, overrides); err != nil {
		log.Warn().Err(err).Msg("cluster: apply config overrides failed")
	}
}

func applyBlocklistPatternsSection(ctx context.Context, fs *filestore.FileStore, raw json.RawMessage, prev *[32]byte) bool {
	return applySection(raw, prev, func(patterns []store.BlocklistPattern) error {
		if err := fs.SetBlocklistPatterns(ctx, patterns); err != nil {
			log.Warn().Err(err).Msg("cluster: apply blocklist patterns failed")
		}
		return nil
	})
}

func applyTSIGKeysSection(ctx context.Context, fs *filestore.FileStore, raw json.RawMessage, prev *[32]byte) bool {
	return applySection(raw, prev, func(keys []store.TSIGKey) error {
		if err := fs.SetTSIGKeys(ctx, keys); err != nil {
			log.Warn().Err(err).Msg("cluster: apply tsig keys failed")
		}
		return nil
	})
}

// applyNamedAPIKeysSection applies NamedAPIKeys. No reload callback exists
// for it, so it isn't checksum-gated.
func applyNamedAPIKeysSection(ctx context.Context, fs *filestore.FileStore, raw json.RawMessage) {
	if !sectionPresent(raw) {
		return
	}
	var apiKeys []store.NamedAPIKey
	if err := json.Unmarshal(raw, &apiKeys); err != nil {
		return
	}
	if err := fs.SetNamedAPIKeys(ctx, apiKeys); err != nil {
		log.Warn().Err(err).Msg("cluster: apply named api keys failed")
	}
}

// applyTLSACMEConfigSection applies TLSACMEConfig. No reload callback exists
// for it, so it isn't checksum-gated.
func applyTLSACMEConfigSection(ctx context.Context, fs *filestore.FileStore, raw json.RawMessage) {
	if !sectionPresent(raw) {
		return
	}
	var tlsCfg store.TLSACMEConfig
	if err := json.Unmarshal(raw, &tlsCfg); err != nil {
		return
	}
	if err := fs.SetTLSACMEConfig(ctx, &tlsCfg); err != nil {
		log.Warn().Err(err).Msg("cluster: apply tls acme config failed")
	}
}

// applyTLSCertSection syncs cert+key to the slave for TLS hot-reload.
// Unlike most sections, it reports changed only when the store write itself
// succeeds — a hot-reload with an unwritten certificate would be worse than
// no reload.
func applyTLSCertSection(ctx context.Context, fs *filestore.FileStore, raw json.RawMessage, prev *[32]byte) bool {
	return applySection(raw, prev, func(tlsCert store.TLSCertPayload) error {
		if err := fs.SetTLSCert(ctx, &tlsCert); err != nil {
			log.Warn().Err(err).Msg("cluster: apply tls cert failed")
			return err
		}
		return nil
	})
}

// applyClientGroupsSection reports changed only when the store write itself
// succeeds (see applyTLSCertSection).
func applyClientGroupsSection(ctx context.Context, fs *filestore.FileStore, raw json.RawMessage, prev *[32]byte) bool {
	return applySection(raw, prev, func(groups []*dns.ClientGroup) error {
		if err := fs.SetClientGroups(ctx, groups); err != nil {
			log.Warn().Err(err).Msg("cluster: apply client groups failed")
			return err
		}
		return nil
	})
}

// applyMasterState applies master state to the local FileStore.
// Reload callbacks are only triggered when the corresponding section's SHA256
// checksum differs from the last-seen value, preventing redundant reloads on
// every poll tick when the master state has not changed.
func applyMasterState(ctx context.Context, fs *filestore.FileStore, state MasterStateResponse, callbacks ReloadCallbacks, ps *pollState) error {
	zonesChanged := applyZonesSection(ctx, fs, state.Zones, &ps.zones)
	applyBlocklistURLsSection(ctx, fs, state.BlocklistURLs)
	manualChanged := applyManualDomainsSection(ctx, fs, state.ManualDomains, &ps.manualDomains)
	allowedChanged := applyAllowedDomainsSection(ctx, fs, state.AllowedDomains, &ps.allowedDomains)
	whitelistChanged := applyWhitelistIPsSection(ctx, fs, state.WhitelistIPs, &ps.whitelistIPs)
	authChanged := applyAuthConfigSection(ctx, fs, state.AuthConfig, &ps.authConfig)
	applyConfigOverridesSection(ctx, fs, state.ConfigOverrides)
	patternsChanged := applyBlocklistPatternsSection(ctx, fs, state.BlocklistPatterns, &ps.blocklistPatterns)
	tsigChanged := applyTSIGKeysSection(ctx, fs, state.TSIGKeys, &ps.tsigKeys)
	applyNamedAPIKeysSection(ctx, fs, state.NamedAPIKeys)
	applyTLSACMEConfigSection(ctx, fs, state.TLSACMEConfig)
	tlsChanged := applyTLSCertSection(ctx, fs, state.TLSCert, &ps.tlsCert)
	clientGroupsChanged := applyClientGroupsSection(ctx, fs, state.ClientGroups, &ps.clientGroups)

	blocklistChanged := manualChanged || allowedChanged || whitelistChanged || patternsChanged

	callbacks.trigger(zonesChanged, callbacks.ZoneReloader, "zone")
	callbacks.trigger(blocklistChanged, callbacks.BlocklistReloader, "blocklist")
	callbacks.trigger(authChanged, callbacks.AuthReloader, "auth")
	callbacks.trigger(tsigChanged, callbacks.DDNSKeyReloader, "ddns key")
	callbacks.trigger(clientGroupsChanged, callbacks.ClientGroupsReloader, "client groups")
	callbacks.trigger(tlsChanged, callbacks.TLSReloader, "tls")

	return nil
}
