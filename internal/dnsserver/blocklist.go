package dnsserver

import (
	"context"
	"net"
	"regexp"
	"strings"
	"sync"

	"github.com/mw7101/domudns/internal/store"
	"github.com/rs/zerolog/log"
)

// urlDomainEntry holds a single URL's domain set for in-memory tracking.
type urlDomainEntry struct {
	category string
	domains  map[string]struct{}
}

// BlocklistManager manages blocklist domains, wildcard/regex patterns, and whitelist IPs in-memory.
type BlocklistManager struct {
	// Flat maps for fast O(1) lookup — rebuilt after every update.
	uncatDomains map[string]struct{}
	catDomains   map[string]map[string]struct{}
	// Per-source domain sets for targeted in-memory updates (no disk I/O).
	urlSets        map[int]urlDomainEntry // urlID → domain set
	manualDomains  map[string]struct{}    // manually added domains (always uncategorized)
	allowedDomains map[string]struct{}    // exempt domains — excluded from flat maps
	// Patterns and IP whitelist
	wildcards []string
	regexps   []*regexp.Regexp
	whitelist []*net.IPNet
	mu        sync.RWMutex
}

// NewBlocklistManager creates a new blocklist manager.
func NewBlocklistManager() *BlocklistManager {
	return &BlocklistManager{
		uncatDomains:   make(map[string]struct{}),
		catDomains:     make(map[string]map[string]struct{}),
		urlSets:        make(map[int]urlDomainEntry),
		manualDomains:  make(map[string]struct{}),
		allowedDomains: make(map[string]struct{}),
		wildcards:      make([]string, 0),
		regexps:        make([]*regexp.Regexp, 0),
		whitelist:      make([]*net.IPNet, 0),
	}
}

// rebuildFlatMapsLocked rebuilds uncatDomains and catDomains from urlSets and manualDomains.
// Must be called with b.mu held for writing.
func (b *BlocklistManager) rebuildFlatMapsLocked() {
	uncatDomains := make(map[string]struct{})
	catDomains := make(map[string]map[string]struct{})

	for _, entry := range b.urlSets {
		if entry.category == "" {
			for d := range entry.domains {
				uncatDomains[d] = struct{}{}
			}
		} else {
			if catDomains[entry.category] == nil {
				catDomains[entry.category] = make(map[string]struct{})
			}
			for d := range entry.domains {
				catDomains[entry.category][d] = struct{}{}
			}
		}
	}

	// Manual domains are always uncategorized
	for d := range b.manualDomains {
		uncatDomains[d] = struct{}{}
	}

	b.uncatDomains = uncatDomains
	b.catDomains = catDomains
}

// parseCIDRList parses a list of IP/CIDR strings into []*net.IPNet.
// Plain IPs without a suffix are automatically extended to /32 (IPv4) or /128 (IPv6).
func parseCIDRList(cidrs []string) []*net.IPNet {
	result := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		entry := cidr
		if !strings.Contains(entry, "/") {
			ip := net.ParseIP(entry)
			if ip == nil {
				log.Warn().Str("ip", entry).Msg("invalid whitelist IP, skipping")
				continue
			}
			if ip.To4() != nil {
				entry = entry + "/32"
			} else {
				entry = entry + "/128"
			}
		}
		_, ipNet, err := net.ParseCIDR(entry)
		if err != nil {
			log.Warn().Str("cidr", entry).Err(err).Msg("invalid whitelist CIDR, skipping")
			continue
		}
		result = append(result, ipNet)
	}
	return result
}

// blocklistSources holds the raw data Load fetches from the provider,
// before building the in-memory lookup structures.
type blocklistSources struct {
	urlSets          []store.URLDomainSet
	manualList       []string
	allowedList      []string
	whitelistCIDRs   []string
	wildcardPatterns []string
	regexpPatterns   []string
}

// loadBlocklistSources fetches everything Load needs from provider. A
// failed pattern fetch is logged and treated as "no patterns" rather than
// failing the whole load — patterns are the least critical source.
func loadBlocklistSources(ctx context.Context, provider BlocklistProvider) (blocklistSources, error) {
	var s blocklistSources
	var err error

	if s.urlSets, err = provider.GetBlocklistURLSets(ctx); err != nil {
		return blocklistSources{}, err
	}
	if s.manualList, err = provider.GetManualBlockedDomains(ctx); err != nil {
		return blocklistSources{}, err
	}
	if s.allowedList, err = provider.GetAllowedBlockedDomains(ctx); err != nil {
		return blocklistSources{}, err
	}
	if s.whitelistCIDRs, err = provider.GetWhitelistIPs(ctx); err != nil {
		return blocklistSources{}, err
	}
	if wp, rp, err := provider.GetBlocklistPatterns(ctx); err == nil {
		s.wildcardPatterns, s.regexpPatterns = wp, rp
	} else {
		log.Warn().Err(err).Msg("blocklist: failed to load patterns")
	}
	return s, nil
}

// buildDomainSet normalizes list (lowercase, no trailing dot) into a set.
func buildDomainSet(list []string) map[string]struct{} {
	set := make(map[string]struct{}, len(list))
	for _, d := range list {
		set[strings.ToLower(strings.TrimSuffix(d, "."))] = struct{}{}
	}
	return set
}

// buildFilteredDomainSet is buildDomainSet, excluding entries present in
// allowedDomains.
func buildFilteredDomainSet(list []string, allowedDomains map[string]struct{}) map[string]struct{} {
	set := make(map[string]struct{}, len(list))
	for _, d := range list {
		norm := strings.ToLower(strings.TrimSuffix(d, "."))
		if _, blocked := allowedDomains[norm]; !blocked {
			set[norm] = struct{}{}
		}
	}
	return set
}

// buildFilteredURLSets converts urlSets to the internal map keyed by URL
// ID, excluding domains present in allowedDomains.
func buildFilteredURLSets(urlSets []store.URLDomainSet, allowedDomains map[string]struct{}) map[int]urlDomainEntry {
	newURLSets := make(map[int]urlDomainEntry, len(urlSets))
	for _, us := range urlSets {
		newURLSets[us.URLID] = urlDomainEntry{
			category: us.Category,
			domains:  buildFilteredDomainSet(us.Domains, allowedDomains),
		}
	}
	return newURLSets
}

// Load loads blocklist domains (with categories), patterns, and whitelist IPs from the store.
func (b *BlocklistManager) Load(ctx context.Context, provider BlocklistProvider) error {
	src, err := loadBlocklistSources(ctx, provider)
	if err != nil {
		return err
	}

	whitelist := parseCIDRList(src.whitelistCIDRs)
	wildcards := parseWildcards(src.wildcardPatterns)
	regexps := compileRegexps(src.regexpPatterns)

	allowedDomains := buildDomainSet(src.allowedList)
	manualDomains := buildFilteredDomainSet(src.manualList, allowedDomains)
	newURLSets := buildFilteredURLSets(src.urlSets, allowedDomains)

	b.mu.Lock()
	defer b.mu.Unlock()

	b.urlSets = newURLSets
	b.manualDomains = manualDomains
	b.allowedDomains = allowedDomains
	b.whitelist = whitelist
	b.wildcards = wildcards
	b.regexps = regexps

	b.rebuildFlatMapsLocked()

	totalCat := 0
	for _, s := range b.catDomains {
		totalCat += len(s)
	}
	log.Info().
		Int("uncategorized_domains", len(b.uncatDomains)).
		Int("categorized_domains", totalCat).
		Int("wildcards", len(wildcards)).
		Int("regexps", len(regexps)).
		Int("whitelist_ips", len(b.whitelist)).
		Msg("blocklist loaded")

	return nil
}

// ApplyURLDomains updates the in-memory blocklist for a single URL without any disk I/O.
// Called by the cluster receiver after EventURLDomains is stored to disk.
// The rebuild of the flat lookup maps is O(total_domains) over in-memory maps — typically <100ms.
func (b *BlocklistManager) ApplyURLDomains(urlID int, category string, domains []string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	entry := urlDomainEntry{
		category: category,
		domains:  make(map[string]struct{}, len(domains)),
	}
	for _, d := range domains {
		norm := strings.ToLower(strings.TrimSuffix(d, "."))
		if _, allowed := b.allowedDomains[norm]; !allowed {
			entry.domains[norm] = struct{}{}
		}
	}

	b.urlSets[urlID] = entry
	b.rebuildFlatMapsLocked()

	log.Debug().
		Int("url_id", urlID).
		Str("category", category).
		Int("domains", len(entry.domains)).
		Msg("blocklist: URL domains updated in-memory")
}

// parseWildcards extracts suffixes from wildcard patterns (e.g. "*.doubleclick.net" → "doubleclick.net").
func parseWildcards(patterns []string) []string {
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		if strings.HasPrefix(p, "*.") {
			out = append(out, strings.ToLower(p[2:]))
		}
	}
	return out
}

// compileRegexps compiles regex patterns (optionally with /.../ delimiter).
func compileRegexps(patterns []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		raw := p
		if strings.HasPrefix(raw, "/") && strings.HasSuffix(raw, "/") && len(raw) > 2 {
			raw = raw[1 : len(raw)-1]
		}
		re, err := regexp.Compile(raw)
		if err != nil {
			log.Warn().Str("pattern", p).Err(err).Msg("blocklist: invalid regex pattern, skipping")
			continue
		}
		out = append(out, re)
	}
	return out
}

// ReloadWhitelist reloads only the whitelist IPs (without the 220k+ domains).
// Called periodically on every cluster node so that whitelist changes made
// via the API on another node are picked up.
func (b *BlocklistManager) ReloadWhitelist(ctx context.Context, store BlocklistProvider) error {
	whitelistCIDRs, err := store.GetWhitelistIPs(ctx)
	if err != nil {
		return err
	}

	whitelist := parseCIDRList(whitelistCIDRs)

	b.mu.Lock()
	defer b.mu.Unlock()
	b.whitelist = whitelist

	log.Debug().Int("whitelist_ips", len(b.whitelist)).Msg("whitelist synced")
	return nil
}

// IsBlocked checks if a domain is blocked for a client with the given enabled categories.
// Uncategorized domains (category="") are always checked.
// Categorized domains are checked only if their category is in enabledCats.
func (b *BlocklistManager) IsBlocked(domain string, enabledCats []string) bool {
	normalized := strings.ToLower(strings.TrimSuffix(domain, "."))

	b.mu.RLock()
	_, uncatHit := b.uncatDomains[normalized]
	// Check categorized domains under lock
	catHit := false
	for _, cat := range enabledCats {
		if set, ok := b.catDomains[cat]; ok {
			if _, ok := set[normalized]; ok {
				catHit = true
				break
			}
		}
	}
	// Copy slice headers (shallow copy; elements are immutable after Load)
	wildcards := b.wildcards
	regexps := b.regexps
	b.mu.RUnlock()

	if uncatHit || catHit {
		return true
	}

	// Wildcards and regexps are always uncategorized in v1
	for _, suffix := range wildcards {
		if normalized == suffix || strings.HasSuffix(normalized, "."+suffix) {
			return true
		}
	}
	for _, re := range regexps {
		if re.MatchString(normalized) {
			return true
		}
	}
	return false
}

// IsWhitelisted checks if an IP is in the whitelist.
func (b *BlocklistManager) IsWhitelisted(ip net.IP) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, ipNet := range b.whitelist {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// Stats returns current blocklist statistics.
func (b *BlocklistManager) Stats() (blockedDomains, wildcards, regexps, whitelistIPs int) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	total := len(b.uncatDomains)
	for _, s := range b.catDomains {
		total += len(s)
	}
	return total, len(b.wildcards), len(b.regexps), len(b.whitelist)
}
