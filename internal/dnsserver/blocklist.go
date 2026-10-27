package dnsserver

import (
	"context"
	"net"
	"regexp"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

// BlocklistManager manages blocklist domains, wildcard/regex patterns, and whitelist IPs in-memory.
type BlocklistManager struct {
	domains   map[string]struct{} // Blocked domains (exact match)
	wildcards []string            // Wildcard suffixes (suffix after "*."), e.g. "doubleclick.net"
	regexps   []*regexp.Regexp    // Compiled regex patterns
	whitelist []*net.IPNet        // Whitelisted IP CIDRs
	mu        sync.RWMutex
}

// NewBlocklistManager creates a new blocklist manager.
func NewBlocklistManager() *BlocklistManager {
	return &BlocklistManager{
		domains:   make(map[string]struct{}),
		wildcards: make([]string, 0),
		regexps:   make([]*regexp.Regexp, 0),
		whitelist: make([]*net.IPNet, 0),
	}
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

// Load loads blocklist domains, patterns, and whitelist IPs from the store.
func (b *BlocklistManager) Load(ctx context.Context, store BlocklistProvider) error {
	// Load blocked domains
	domains, err := store.GetBlockedDomains(ctx)
	if err != nil {
		return err
	}

	// Load whitelist IPs
	whitelistCIDRs, err := store.GetWhitelistIPs(ctx)
	if err != nil {
		return err
	}

	// Load wildcard/regex patterns (non-fatal if not supported)
	var wildcardPatterns, regexpPatterns []string
	if wp, rp, err := store.GetBlocklistPatterns(ctx); err == nil {
		wildcardPatterns = wp
		regexpPatterns = rp
	} else {
		log.Warn().Err(err).Msg("blocklist: failed to load patterns")
	}

	whitelist := parseCIDRList(whitelistCIDRs)
	wildcards := parseWildcards(wildcardPatterns)
	regexps := compileRegexps(regexpPatterns)

	// Update in-memory data
	b.mu.Lock()
	defer b.mu.Unlock()

	b.domains = make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		normalized := strings.ToLower(strings.TrimSuffix(domain, "."))
		b.domains[normalized] = struct{}{}
	}
	b.whitelist = whitelist
	b.wildcards = wildcards
	b.regexps = regexps

	log.Info().
		Int("blocked_domains", len(b.domains)).
		Int("wildcards", len(b.wildcards)).
		Int("regexps", len(b.regexps)).
		Int("whitelist_ips", len(b.whitelist)).
		Msg("blocklist loaded")

	return nil
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

// IsBlocked checks if a domain is in the blocklist (exact, wildcard, or regex).
// Snapshot pattern: the lock is held only briefly for the exact match; wildcard and
// regex iteration run lock-free on a shallow copy of the slice headers.
func (b *BlocklistManager) IsBlocked(domain string) bool {
	normalized := strings.ToLower(strings.TrimSuffix(domain, "."))

	b.mu.RLock()
	_, exactHit := b.domains[normalized]
	// Copy slice headers (shallow copy; elements are immutable after Load)
	wildcards := b.wildcards
	regexps := b.regexps
	b.mu.RUnlock()

	// 1. Exact match (O(1)) — already checked under lock
	if exactHit {
		return true
	}

	// 2. Wildcard match: suffix "doubleclick.net" matches "a.doubleclick.net" and "doubleclick.net"
	for _, suffix := range wildcards {
		if normalized == suffix || strings.HasSuffix(normalized, "."+suffix) {
			return true
		}
	}

	// 3. Regex match (Go regexp uses RE2 → no catastrophic backtracking risk)
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
	return len(b.domains), len(b.wildcards), len(b.regexps), len(b.whitelist)
}
