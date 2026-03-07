package dnsserver

import (
	"net"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
)

// rebindingConfig holds the configurable parameters.
// Swapped atomically as pointer for lock-free live-reload.
type rebindingConfig struct {
	enabled   bool
	whitelist []string // normalized domain suffixes (lowercase, no trailing dot)
}

// RebindingProtector checks upstream responses for DNS rebinding attacks.
// Thread-safe via atomic.Value (pointer swap, no mutex needed).
//
// DNS Rebinding: An attacker makes an external domain (evil.com) resolve to a
// private IP (192.168.1.1). The browser thinks it talks to a local device and
// bypasses same-origin protection.
type RebindingProtector struct {
	cfg atomic.Value // stores *rebindingConfig
}

// privateRanges contains all RFC1918/Loopback/Link-Local IP ranges.
// Filled once in init() — immutable at runtime, no mutex needed.
var privateRanges []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",     // RFC1918 Class A
		"172.16.0.0/12",  // RFC1918 Class B
		"192.168.0.0/16", // RFC1918 Class C
		"127.0.0.0/8",    // IPv4 Loopback
		"169.254.0.0/16", // IPv4 Link-Local (APIPA)
		"100.64.0.0/10",  // Shared Address Space (RFC 6598, Carrier-Grade NAT)
		"::1/128",        // IPv6 Loopback
		"fc00::/7",       // IPv6 Unique Local Address (ULA)
		"fe80::/10",      // IPv6 Link-Local
	}
	privateRanges = make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			privateRanges = append(privateRanges, ipNet)
		}
	}
}

// NewRebindingProtector creates a new RebindingProtector.
func NewRebindingProtector(enabled bool, whitelist []string) *RebindingProtector {
	rp := &RebindingProtector{}
	rp.cfg.Store(newRebindingConfig(enabled, whitelist))
	return rp
}

// Update replaces the configuration at runtime (thread-safe, no restart needed).
func (rp *RebindingProtector) Update(enabled bool, whitelist []string) {
	rp.cfg.Store(newRebindingConfig(enabled, whitelist))
}

// IsRebindingAttack checks if the upstream response represents a DNS rebinding attack.
// Returns true if the response should be blocked.
//
// qname: the queried domain name (e.g. "evil.com.")
// resp: the upstream response (nil-safe)
func (rp *RebindingProtector) IsRebindingAttack(qname string, resp *dns.Msg) bool {
	cfg := rp.cfg.Load().(*rebindingConfig)
	if !cfg.enabled {
		return false
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		return false
	}
	if cfg.isWhitelisted(qname) {
		return false
	}
	for _, rr := range resp.Answer {
		if isPrivateRR(rr) {
			return true
		}
	}
	return false
}

// isWhitelisted checks if qname is on the whitelist (suffix match, case-insensitive).
func (c *rebindingConfig) isWhitelisted(qname string) bool {
	name := strings.ToLower(strings.TrimSuffix(qname, "."))
	for _, suffix := range c.whitelist {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return true
		}
	}
	return false
}

// isPrivateRR returns true if a DNS RR points to a private IP.
func isPrivateRR(rr dns.RR) bool {
	switch v := rr.(type) {
	case *dns.A:
		return isPrivateIP(v.A)
	case *dns.AAAA:
		return isPrivateIP(v.AAAA)
	}
	return false
}

// isPrivateIP checks if an IP is in one of the private ranges.
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, network := range privateRanges {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func newRebindingConfig(enabled bool, whitelist []string) *rebindingConfig {
	normalized := make([]string, 0, len(whitelist))
	for _, w := range whitelist {
		if n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(w), ".")); n != "" {
			normalized = append(normalized, n)
		}
	}
	return &rebindingConfig{enabled: enabled, whitelist: normalized}
}
