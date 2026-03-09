package cluster

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"time"

	"github.com/mw7101/domudns/internal/dns"
	"github.com/mw7101/domudns/internal/filestore"
	"github.com/mw7101/domudns/internal/store"
)

// PropagatingStore decorates FileStore and triggers a push to slaves after every mutation.
// Implements the same interface as FileStore (api.Store).
type PropagatingStore struct {
	*filestore.FileStore
	propagator *Propagator
}

// NewPropagatingStore creates a new PropagatingStore.
func NewPropagatingStore(fs *filestore.FileStore, propagator *Propagator) *PropagatingStore {
	return &PropagatingStore{
		FileStore:  fs,
		propagator: propagator,
	}
}

// PutZone stores a zone and propagates EventZoneUpdated.
// Supports default zones (zone.View == "") and view-specific zones (zone.View != "").
func (s *PropagatingStore) PutZone(ctx context.Context, zone *dns.Zone) error {
	if err := s.FileStore.PutZone(ctx, zone); err != nil {
		return err
	}
	s.propagator.PushAsync(EventZoneUpdated, zone)
	return nil
}

// DeleteZone deletes a zone and propagates EventZoneDeleted.
func (s *PropagatingStore) DeleteZone(ctx context.Context, domain string) error {
	if err := s.FileStore.DeleteZone(ctx, domain); err != nil {
		return err
	}
	s.propagator.PushAsync(EventZoneDeleted, domain)
	return nil
}

// GetZoneView returns a view-specific zone (delegates to FileStore).
func (s *PropagatingStore) GetZoneView(ctx context.Context, domain, view string) (*dns.Zone, error) {
	return s.FileStore.GetZoneView(ctx, domain, view)
}

// DeleteZoneView deletes a view-specific zone and propagates EventZoneDeleted.
// The payload "domain@view" is transmitted so that slaves delete the correct file.
func (s *PropagatingStore) DeleteZoneView(ctx context.Context, domain, view string) error {
	if err := s.FileStore.DeleteZoneView(ctx, domain, view); err != nil {
		return err
	}
	// Payload format: "domain@view" — receiver recognizes this and calls DeleteZoneView
	s.propagator.PushAsync(EventZoneDeleted, domain+"@"+view)
	return nil
}

// PutRecord stores a record and propagates the complete zone.
func (s *PropagatingStore) PutRecord(ctx context.Context, zoneDomain string, record *dns.Record) error {
	if err := s.FileStore.PutRecord(ctx, zoneDomain, record); err != nil {
		return err
	}
	zone, err := s.FileStore.GetZone(ctx, zoneDomain)
	if err == nil {
		s.propagator.PushAsync(EventZoneUpdated, zone)
	}
	return nil
}

// DeleteRecord deletes a record and propagates the current zone.
func (s *PropagatingStore) DeleteRecord(ctx context.Context, zoneDomain string, recordID int) error {
	if err := s.FileStore.DeleteRecord(ctx, zoneDomain, recordID); err != nil {
		return err
	}
	zone, err := s.FileStore.GetZone(ctx, zoneDomain)
	if err == nil {
		s.propagator.PushAsync(EventZoneUpdated, zone)
	}
	return nil
}

// AddBlocklistURL adds a URL and propagates EventBlocklistURLs.
func (s *PropagatingStore) AddBlocklistURL(ctx context.Context, url string, enabled bool) (*store.BlocklistURL, error) {
	result, err := s.FileStore.AddBlocklistURL(ctx, url, enabled)
	if err != nil {
		return nil, err
	}
	s.pushBlocklistURLs(ctx)
	return result, nil
}

// RemoveBlocklistURL removes a URL and propagates EventBlocklistURLs.
func (s *PropagatingStore) RemoveBlocklistURL(ctx context.Context, id int) error {
	if err := s.FileStore.RemoveBlocklistURL(ctx, id); err != nil {
		return err
	}
	s.pushBlocklistURLs(ctx)
	return nil
}

// SetBlocklistURLEnabled sets the enabled flag and propagates EventBlocklistURLs.
func (s *PropagatingStore) SetBlocklistURLEnabled(ctx context.Context, id int, enabled bool) error {
	if err := s.FileStore.SetBlocklistURLEnabled(ctx, id, enabled); err != nil {
		return err
	}
	s.pushBlocklistURLs(ctx)
	return nil
}

// SetBlocklistURLDomains stores domains and propagates EventURLDomains.
func (s *PropagatingStore) SetBlocklistURLDomains(ctx context.Context, urlID int, domains []string) error {
	if err := s.FileStore.SetBlocklistURLDomains(ctx, urlID, domains); err != nil {
		return err
	}
	s.pushURLDomains(urlID, domains)
	return nil
}

// AddBlockedDomain adds a domain and propagates EventManualDomains.
func (s *PropagatingStore) AddBlockedDomain(ctx context.Context, domain string) error {
	if err := s.FileStore.AddBlockedDomain(ctx, domain); err != nil {
		return err
	}
	s.pushManualDomains(ctx)
	return nil
}

// RemoveBlockedDomain removes a domain and propagates EventManualDomains.
func (s *PropagatingStore) RemoveBlockedDomain(ctx context.Context, domain string) error {
	if err := s.FileStore.RemoveBlockedDomain(ctx, domain); err != nil {
		return err
	}
	s.pushManualDomains(ctx)
	return nil
}

// AddAllowedDomain adds an allowed domain and propagates EventAllowedDomains.
func (s *PropagatingStore) AddAllowedDomain(ctx context.Context, domain string) error {
	if err := s.FileStore.AddAllowedDomain(ctx, domain); err != nil {
		return err
	}
	s.pushAllowedDomains(ctx)
	return nil
}

// RemoveAllowedDomain removes an allowed domain and propagates EventAllowedDomains.
func (s *PropagatingStore) RemoveAllowedDomain(ctx context.Context, domain string) error {
	if err := s.FileStore.RemoveAllowedDomain(ctx, domain); err != nil {
		return err
	}
	s.pushAllowedDomains(ctx)
	return nil
}

// AddWhitelistIP adds an IP and propagates EventWhitelistIPs.
func (s *PropagatingStore) AddWhitelistIP(ctx context.Context, ipCIDR string) error {
	if err := s.FileStore.AddWhitelistIP(ctx, ipCIDR); err != nil {
		return err
	}
	s.pushWhitelistIPs(ctx)
	return nil
}

// RemoveWhitelistIP removes an IP and propagates EventWhitelistIPs.
func (s *PropagatingStore) RemoveWhitelistIP(ctx context.Context, ipCIDR string) error {
	if err := s.FileStore.RemoveWhitelistIP(ctx, ipCIDR); err != nil {
		return err
	}
	s.pushWhitelistIPs(ctx)
	return nil
}

// AddBlocklistPattern adds a pattern and propagates EventBlocklistPatterns.
func (s *PropagatingStore) AddBlocklistPattern(ctx context.Context, pattern string, patternType string) (*store.BlocklistPattern, error) {
	result, err := s.FileStore.AddBlocklistPattern(ctx, pattern, patternType)
	if err != nil {
		return nil, err
	}
	s.pushBlocklistPatterns(ctx)
	return result, nil
}

// RemoveBlocklistPattern removes a pattern and propagates EventBlocklistPatterns.
func (s *PropagatingStore) RemoveBlocklistPattern(ctx context.Context, id int) error {
	if err := s.FileStore.RemoveBlocklistPattern(ctx, id); err != nil {
		return err
	}
	s.pushBlocklistPatterns(ctx)
	return nil
}

// UpdateAuthConfig stores the auth config and propagates EventAuthConfig.
func (s *PropagatingStore) UpdateAuthConfig(ctx context.Context, cfg *store.AuthConfig) error {
	if err := s.FileStore.UpdateAuthConfig(ctx, cfg); err != nil {
		return err
	}
	s.propagator.PushAsync(EventAuthConfig, cfg)
	return nil
}

// MarkSetupCompleted sets the setup flag and propagates EventAuthConfig.
func (s *PropagatingStore) MarkSetupCompleted(ctx context.Context) error {
	if err := s.FileStore.MarkSetupCompleted(ctx); err != nil {
		return err
	}
	cfg, err := s.FileStore.GetAuthConfig(ctx)
	if err == nil {
		s.propagator.PushAsync(EventAuthConfig, cfg)
	}
	return nil
}

// UpdateConfigOverrides stores config overrides and propagates EventConfigOverrides.
func (s *PropagatingStore) UpdateConfigOverrides(ctx context.Context, overrides map[string]interface{}) error {
	if err := s.FileStore.UpdateConfigOverrides(ctx, overrides); err != nil {
		return err
	}
	current, err := s.FileStore.GetConfigOverrides(ctx)
	if err == nil {
		s.propagator.PushAsync(EventConfigOverrides, current)
	}
	return nil
}

// PutTSIGKey stores a TSIG key and propagates EventTSIGKeys.
func (s *PropagatingStore) PutTSIGKey(ctx context.Context, key store.TSIGKey) error {
	if err := s.FileStore.PutTSIGKey(ctx, key); err != nil {
		return err
	}
	s.pushTSIGKeys(ctx)
	return nil
}

// DeleteTSIGKey deletes a TSIG key and propagates EventTSIGKeys.
func (s *PropagatingStore) DeleteTSIGKey(ctx context.Context, name string) error {
	if err := s.FileStore.DeleteTSIGKey(ctx, name); err != nil {
		return err
	}
	s.pushTSIGKeys(ctx)
	return nil
}

// UpdateBlocklistURLFetch updates the fetch status and propagates URL metadata.
func (s *PropagatingStore) UpdateBlocklistURLFetch(ctx context.Context, id int, lastError *string) error {
	if err := s.FileStore.UpdateBlocklistURLFetch(ctx, id, lastError); err != nil {
		return err
	}
	s.pushBlocklistURLs(ctx)
	return nil
}

// CreateNamedAPIKey creates a named API key and propagates EventAPIKeys to slaves.
func (s *PropagatingStore) CreateNamedAPIKey(ctx context.Context, name, description string) (*store.NamedAPIKey, error) {
	key, err := s.FileStore.CreateNamedAPIKey(ctx, name, description)
	if err != nil {
		return nil, err
	}
	s.pushNamedAPIKeys(ctx)
	return key, nil
}

// DeleteNamedAPIKey deletes a named API key and propagates EventAPIKeys to slaves.
func (s *PropagatingStore) DeleteNamedAPIKey(ctx context.Context, id string) error {
	if err := s.FileStore.DeleteNamedAPIKey(ctx, id); err != nil {
		return err
	}
	s.pushNamedAPIKeys(ctx)
	return nil
}

// PutACMEChallenge delegates to FileStore (no propagation - short-lived).
func (s *PropagatingStore) PutACMEChallenge(ctx context.Context, fqdn, value string, ttl time.Duration) error {
	return s.FileStore.PutACMEChallenge(ctx, fqdn, value, ttl)
}

// DeleteACMEChallenge delegates to FileStore.
func (s *PropagatingStore) DeleteACMEChallenge(ctx context.Context, fqdn string) error {
	return s.FileStore.DeleteACMEChallenge(ctx, fqdn)
}

// --- Helper functions for bulk pushes ---

func (s *PropagatingStore) pushBlocklistURLs(ctx context.Context) {
	urls, err := s.FileStore.ListBlocklistURLs(ctx)
	if err == nil {
		s.propagator.PushAsync(EventBlocklistURLs, urls)
	}
}

func (s *PropagatingStore) pushManualDomains(ctx context.Context) {
	domains, err := s.FileStore.ListBlockedDomains(ctx)
	if err == nil {
		s.propagator.PushAsync(EventManualDomains, domains)
	}
}

func (s *PropagatingStore) pushAllowedDomains(ctx context.Context) {
	domains, err := s.FileStore.ListAllowedDomains(ctx)
	if err == nil {
		s.propagator.PushAsync(EventAllowedDomains, domains)
	}
}

func (s *PropagatingStore) pushBlocklistPatterns(ctx context.Context) {
	patterns, err := s.FileStore.ListBlocklistPatterns(ctx)
	if err == nil {
		s.propagator.PushAsync(EventBlocklistPatterns, patterns)
	}
}

func (s *PropagatingStore) pushWhitelistIPs(ctx context.Context) {
	ips, err := s.FileStore.ListWhitelistIPs(ctx)
	if err == nil {
		s.propagator.PushAsync(EventWhitelistIPs, ips)
	}
}

func (s *PropagatingStore) pushTSIGKeys(ctx context.Context) {
	keys, err := s.FileStore.GetTSIGKeys(ctx)
	if err == nil {
		s.propagator.PushAsync(EventTSIGKeys, keys)
	}
}

func (s *PropagatingStore) pushNamedAPIKeys(ctx context.Context) {
	keys, err := s.FileStore.GetAllNamedAPIKeys(ctx)
	if err == nil {
		s.propagator.PushAsync(EventAPIKeys, keys)
	}
}

func (s *PropagatingStore) pushURLDomains(urlID int, domains []string) {
	payload := buildURLDomainsPayload(urlID, domains)
	s.propagator.PushAsync(EventURLDomains, payload)
}

// buildURLDomainsPayload creates a URLDomainsPayload with a gzip+base64 encoded domain list.
func buildURLDomainsPayload(urlID int, domains []string) URLDomainsPayload {
	var raw bytes.Buffer
	for _, d := range domains {
		raw.WriteString(d + "\n")
	}
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	_, _ = gz.Write(raw.Bytes())
	_ = gz.Close()
	return URLDomainsPayload{
		URLID:        urlID,
		DomainsGzB64: base64.StdEncoding.EncodeToString(gzBuf.Bytes()),
	}
}
