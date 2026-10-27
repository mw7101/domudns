package dns

import (
	"fmt"
	"net"
	"strings"
)

// ReverseZoneForIP returns the reverse DNS zone for an IP address.
// For IPv4, returns the /24 zone (e.g. "1.168.192.in-addr.arpa" for 192.168.1.42).
// For IPv6, returns the /64 zone (e.g. "0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa" for 2001:db8::1).
// Returns ("", false) if ip cannot be parsed.
func ReverseZoneForIP(ip string) (string, bool) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", false
	}
	if p4 := parsed.To4(); p4 != nil {
		return fmt.Sprintf("%d.%d.%d.in-addr.arpa", p4[2], p4[1], p4[0]), true
	}
	p16 := parsed.To16()
	nibbles := ipv6Nibbles(p16)
	// Zone: first 16 nibbles (= /64 prefix) reversed, dot-joined
	parts := make([]string, 16)
	for i := 0; i < 16; i++ {
		parts[i] = string(nibbles[15-i])
	}
	return strings.Join(parts, ".") + ".ip6.arpa", true
}

// PTRNameForIP returns the PTR record name relative to the reverse zone.
// For IPv4: last octet as decimal (e.g. "42" for 192.168.1.42).
// For IPv6: last 16 nibbles reversed, dot-separated (host part of /64 zone).
// Returns "" if ip cannot be parsed.
func PTRNameForIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	if p4 := parsed.To4(); p4 != nil {
		return fmt.Sprintf("%d", p4[3])
	}
	p16 := parsed.To16()
	nibbles := ipv6Nibbles(p16)
	// PTR name: last 16 nibbles reversed, dot-joined
	parts := make([]string, 16)
	for i := 0; i < 16; i++ {
		parts[i] = string(nibbles[31-i])
	}
	return strings.Join(parts, ".")
}

// ipv6Nibbles expands 16 IPv6 bytes to 32 lowercase hex nibbles.
func ipv6Nibbles(p16 []byte) []byte {
	nibbles := make([]byte, 32)
	for i := 0; i < 16; i++ {
		nibbles[i*2] = hexNibble(p16[i] >> 4)
		nibbles[i*2+1] = hexNibble(p16[i] & 0x0f)
	}
	return nibbles
}

func hexNibble(b byte) byte {
	if b < 10 {
		return '0' + b
	}
	return 'a' + b - 10
}
