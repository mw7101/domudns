package filestore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mw7101/domudns/internal/store"
	"github.com/rs/zerolog/log"
)

// ListBlocklistURLs returns all blocklist URLs.
func (s *FileStore) ListBlocklistURLs(_ context.Context) ([]store.BlocklistURL, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadURLs()
}

// AddBlocklistURL adds a new blocklist URL.
func (s *FileStore) AddBlocklistURL(_ context.Context, url string, enabled bool) (*store.BlocklistURL, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	urls, err := s.loadURLs()
	if err != nil {
		return nil, err
	}
	// Duplicate check
	for _, u := range urls {
		if u.URL == url {
			return nil, fmt.Errorf("duplicate url")
		}
	}
	// Next ID
	maxID := 0
	for _, u := range urls {
		if u.ID > maxID {
			maxID = u.ID
		}
	}
	now := time.Now()
	newURL := store.BlocklistURL{
		ID:        maxID + 1,
		URL:       url,
		Enabled:   enabled,
		CreatedAt: now,
	}
	urls = append(urls, newURL)
	if err := atomicWriteJSON(s.urlsPath(), urls); err != nil {
		return nil, err
	}
	return &newURL, nil
}

// RemoveBlocklistURL removes a blocklist URL and its stored domains.
func (s *FileStore) RemoveBlocklistURL(_ context.Context, id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	urls, err := s.loadURLs()
	if err != nil {
		return err
	}
	newURLs := make([]store.BlocklistURL, 0, len(urls))
	for _, u := range urls {
		if u.ID != id {
			newURLs = append(newURLs, u)
		}
	}
	if err := atomicWriteJSON(s.urlsPath(), newURLs); err != nil {
		return err
	}
	// Delete domain file for this URL (best-effort; URL already removed from list)
	domainPath := filepath.Join(s.urlDomainsDir(), fmt.Sprintf("%d.domains.gz", id))
	if err := os.Remove(domainPath); err != nil && !os.IsNotExist(err) {
		log.Warn().Err(err).Str("path", domainPath).Msg("filestore: remove blocklist domain file failed")
	}
	return nil
}

// SetBlocklistURLEnabled sets the enabled flag of a blocklist URL.
func (s *FileStore) SetBlocklistURLEnabled(_ context.Context, id int, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	urls, err := s.loadURLs()
	if err != nil {
		return err
	}
	for i := range urls {
		if urls[i].ID == id {
			urls[i].Enabled = enabled
			return atomicWriteJSON(s.urlsPath(), urls)
		}
	}
	return fmt.Errorf("url id %d not found", id)
}

// UpdateBlocklistURLFetch updates last_fetched_at and last_error.
func (s *FileStore) UpdateBlocklistURLFetch(_ context.Context, id int, lastError *string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	urls, err := s.loadURLs()
	if err != nil {
		return err
	}
	now := time.Now()
	for i := range urls {
		if urls[i].ID == id {
			urls[i].LastFetchedAt = &now
			urls[i].LastError = lastError
			return atomicWriteJSON(s.urlsPath(), urls)
		}
	}
	return fmt.Errorf("url id %d not found", id)
}

// SetBlocklistURLDomains stores the domains for a blocklist URL (gzip).
func (s *FileStore) SetBlocklistURLDomains(_ context.Context, urlID int, domains []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.urlDomainsDir(), fmt.Sprintf("%d.domains.gz", urlID))
	return writeGzipDomains(path, domains)
}

// ListBlockedDomains returns all manually blocked domains.
func (s *FileStore) ListBlockedDomains(_ context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadStringList(s.manualDomainsPath())
}

// AddBlockedDomain adds a manually blocked domain.
func (s *FileStore) AddBlockedDomain(_ context.Context, domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	domains, err := s.loadStringList(s.manualDomainsPath())
	if err != nil {
		return err
	}
	for _, d := range domains {
		if d == domain {
			return nil // already present
		}
	}
	domains = append(domains, domain)
	return atomicWriteJSON(s.manualDomainsPath(), domains)
}

// RemoveBlockedDomain removes a manually blocked domain.
func (s *FileStore) RemoveBlockedDomain(_ context.Context, domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	domains, err := s.loadStringList(s.manualDomainsPath())
	if err != nil {
		return err
	}
	newDomains := make([]string, 0, len(domains))
	for _, d := range domains {
		if d != domain {
			newDomains = append(newDomains, d)
		}
	}
	return atomicWriteJSON(s.manualDomainsPath(), newDomains)
}

// ListAllowedDomains returns all allowed domains.
func (s *FileStore) ListAllowedDomains(_ context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadStringList(s.allowedDomainsPath())
}

// AddAllowedDomain adds an allowed domain.
func (s *FileStore) AddAllowedDomain(_ context.Context, domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	domains, err := s.loadStringList(s.allowedDomainsPath())
	if err != nil {
		return err
	}
	for _, d := range domains {
		if d == domain {
			return nil
		}
	}
	domains = append(domains, domain)
	return atomicWriteJSON(s.allowedDomainsPath(), domains)
}

// RemoveAllowedDomain removes an allowed domain.
func (s *FileStore) RemoveAllowedDomain(_ context.Context, domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	domains, err := s.loadStringList(s.allowedDomainsPath())
	if err != nil {
		return err
	}
	newDomains := make([]string, 0, len(domains))
	for _, d := range domains {
		if d != domain {
			newDomains = append(newDomains, d)
		}
	}
	return atomicWriteJSON(s.allowedDomainsPath(), newDomains)
}

// ListWhitelistIPs returns all whitelist IPs.
func (s *FileStore) ListWhitelistIPs(_ context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadStringList(s.whitelistIPsPath())
}

// AddWhitelistIP adds an IP/CIDR to the whitelist.
func (s *FileStore) AddWhitelistIP(_ context.Context, ipCIDR string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ips, err := s.loadStringList(s.whitelistIPsPath())
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if ip == ipCIDR {
			return nil
		}
	}
	ips = append(ips, ipCIDR)
	return atomicWriteJSON(s.whitelistIPsPath(), ips)
}

// RemoveWhitelistIP removes an IP/CIDR from the whitelist.
func (s *FileStore) RemoveWhitelistIP(_ context.Context, ipCIDR string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ips, err := s.loadStringList(s.whitelistIPsPath())
	if err != nil {
		return err
	}
	newIPs := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip != ipCIDR {
			newIPs = append(newIPs, ip)
		}
	}
	return atomicWriteJSON(s.whitelistIPsPath(), newIPs)
}

// GetMergedBlocklist returns all blocked domains (URL domains + manual), minus allowed.
// Implements blocklist.MergedBlocklistStore and dnsserver.BlocklistStore.
func (s *FileStore) GetMergedBlocklist(_ context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	urls, err := s.loadURLs()
	if err != nil {
		return nil, err
	}

	// Collect all blocked domains
	blockedSet := make(map[string]struct{})

	// URL domains (only enabled URLs)
	for _, u := range urls {
		if !u.Enabled {
			continue
		}
		domainPath := filepath.Join(s.urlDomainsDir(), fmt.Sprintf("%d.domains.gz", u.ID))
		domains, err := readGzipDomains(domainPath)
		if err != nil {
			continue
		}
		for _, d := range domains {
			blockedSet[strings.ToLower(d)] = struct{}{}
		}
	}

	// Manual domains
	manualDomains, err := s.loadStringList(s.manualDomainsPath())
	if err != nil {
		return nil, err
	}
	for _, d := range manualDomains {
		blockedSet[strings.ToLower(d)] = struct{}{}
	}

	// Load allowed domains
	allowedDomains, err := s.loadStringList(s.allowedDomainsPath())
	if err != nil {
		return nil, err
	}
	allowedSet := make(map[string]struct{}, len(allowedDomains))
	for _, d := range allowedDomains {
		allowedSet[strings.ToLower(d)] = struct{}{}
	}

	// Filter out allowed domains (including subdomains)
	result := make([]string, 0, len(blockedSet))
	for d := range blockedSet {
		if isAllowed(d, allowedSet) {
			continue
		}
		result = append(result, d)
	}
	return result, nil
}

// isAllowed checks whether domain is in allowedSet or is a subdomain of an allowed entry.
func isAllowed(domain string, allowedSet map[string]struct{}) bool {
	if _, ok := allowedSet[domain]; ok {
		return true
	}
	// Subdomain check: is domain a subdomain of an allowed entry?
	for allowed := range allowedSet {
		if strings.HasSuffix(domain, "."+allowed) {
			return true
		}
	}
	return false
}

// GetBlockedDomains implements dnsserver.BlocklistStore.
func (s *FileStore) GetBlockedDomains(ctx context.Context) ([]string, error) {
	return s.GetMergedBlocklist(ctx)
}

// GetWhitelistIPs implements dnsserver.BlocklistStore.
func (s *FileStore) GetWhitelistIPs(ctx context.Context) ([]string, error) {
	return s.ListWhitelistIPs(ctx)
}

// SetBlocklistURLs replaces all blocklist URLs completely (for cluster sync).
func (s *FileStore) SetBlocklistURLs(_ context.Context, urls []store.BlocklistURL) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return atomicWriteJSON(s.urlsPath(), urls)
}

// SetManualDomains replaces all manually blocked domains (for cluster sync).
func (s *FileStore) SetManualDomains(_ context.Context, domains []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return atomicWriteJSON(s.manualDomainsPath(), domains)
}

// SetAllowedDomains replaces all allowed domains (for cluster sync).
func (s *FileStore) SetAllowedDomains(_ context.Context, domains []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return atomicWriteJSON(s.allowedDomainsPath(), domains)
}

// SetWhitelistIPs replaces all whitelist IPs (for cluster sync).
func (s *FileStore) SetWhitelistIPs(_ context.Context, ips []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return atomicWriteJSON(s.whitelistIPsPath(), ips)
}

// loadURLs loads URLs from the JSON file (without lock, for internal use).
func (s *FileStore) loadURLs() ([]store.BlocklistURL, error) {
	var urls []store.BlocklistURL
	if err := readJSON(s.urlsPath(), &urls); err != nil {
		return nil, err
	}
	return urls, nil
}

// loadStringList loads a string list from a JSON file.
func (s *FileStore) loadStringList(path string) ([]string, error) {
	var list []string
	if err := readJSON(path, &list); err != nil {
		return nil, err
	}
	return list, nil
}

// ListBlocklistPatterns returns all blocklist patterns.
func (s *FileStore) ListBlocklistPatterns(_ context.Context) ([]store.BlocklistPattern, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadPatterns()
}

// AddBlocklistPattern adds a wildcard or regex pattern.
func (s *FileStore) AddBlocklistPattern(_ context.Context, pattern string, patternType string) (*store.BlocklistPattern, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	patterns, err := s.loadPatterns()
	if err != nil {
		return nil, err
	}
	for _, p := range patterns {
		if p.Pattern == pattern {
			return nil, fmt.Errorf("duplicate pattern")
		}
	}
	maxID := 0
	for _, p := range patterns {
		if p.ID > maxID {
			maxID = p.ID
		}
	}
	newPattern := store.BlocklistPattern{
		ID:        maxID + 1,
		Pattern:   pattern,
		Type:      patternType,
		CreatedAt: time.Now(),
	}
	patterns = append(patterns, newPattern)
	if err := atomicWriteJSON(s.patternsPath(), patterns); err != nil {
		return nil, err
	}
	return &newPattern, nil
}

// RemoveBlocklistPattern removes a pattern by ID.
func (s *FileStore) RemoveBlocklistPattern(_ context.Context, id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	patterns, err := s.loadPatterns()
	if err != nil {
		return err
	}
	newPatterns := make([]store.BlocklistPattern, 0, len(patterns))
	for _, p := range patterns {
		if p.ID != id {
			newPatterns = append(newPatterns, p)
		}
	}
	return atomicWriteJSON(s.patternsPath(), newPatterns)
}

// SetBlocklistPatterns replaces all patterns (for cluster sync).
func (s *FileStore) SetBlocklistPatterns(_ context.Context, patterns []store.BlocklistPattern) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return atomicWriteJSON(s.patternsPath(), patterns)
}

// GetBlocklistPatterns returns wildcard and regex patterns as separate lists (for dnsserver.BlocklistStore).
func (s *FileStore) GetBlocklistPatterns(ctx context.Context) (wildcards []string, regexps []string, err error) {
	patterns, err := s.ListBlocklistPatterns(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, p := range patterns {
		switch p.Type {
		case "wildcard":
			wildcards = append(wildcards, p.Pattern)
		case "regex":
			regexps = append(regexps, p.Pattern)
		}
	}
	return wildcards, regexps, nil
}

// loadPatterns loads patterns from the JSON file (without lock, for internal use).
func (s *FileStore) loadPatterns() ([]store.BlocklistPattern, error) {
	var patterns []store.BlocklistPattern
	if err := readJSON(s.patternsPath(), &patterns); err != nil {
		return nil, err
	}
	return patterns, nil
}
