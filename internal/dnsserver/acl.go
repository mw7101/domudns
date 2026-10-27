package dnsserver

import (
	"net"
	"strings"

	"github.com/rs/zerolog/log"
)

// networkACL is an immutable allowlist of client networks. A nil or empty ACL
// allows every client (the default — no access control). Instances are swapped
// atomically on live config reload, so they are never mutated after creation.
type networkACL struct {
	nets []*net.IPNet
}

// parseNetworks parses CIDR strings and bare IPs into networks. Invalid entries
// are logged (with configKey for context) and skipped rather than blocking
// startup — a typo in one entry must never take the DNS server down.
func parseNetworks(entries []string, configKey string) []*net.IPNet {
	var nets []*net.IPNet
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, ipnet, err := net.ParseCIDR(entry); err == nil {
			nets = append(nets, ipnet)
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		log.Warn().Str("network", entry).Str("config", configKey).Msg("invalid CIDR/IP, ignored")
	}
	return nets
}

// Allows reports whether ip is permitted. A nil ACL or one without networks
// allows everything.
func (a *networkACL) Allows(ip net.IP) bool {
	if a == nil || len(a.nets) == 0 {
		return true
	}
	for _, n := range a.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
