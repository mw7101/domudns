package dns

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

var (
	// ErrInvalidIPv4 is returned for invalid A record values.
	ErrInvalidIPv4 = errors.New("invalid IPv4 address")
	// ErrInvalidIPv6 is returned for invalid AAAA record values.
	ErrInvalidIPv6 = errors.New("invalid IPv6 address")
	// ErrCNAMEAtApex is returned when CNAME is used at zone apex.
	ErrCNAMEAtApex = errors.New("CNAME not allowed at zone apex")
	// ErrInvalidMXPriority is returned for invalid MX priority.
	ErrInvalidMXPriority = errors.New("MX priority must be 0-65535")
	// ErrTXTTooLong is returned when TXT string exceeds 255 chars.
	ErrTXTTooLong = errors.New("TXT string exceeds 255 characters")
	// ErrInvalidDomain is returned for invalid domain names.
	ErrInvalidDomain = errors.New("invalid domain name")
	// ErrInvalidSRV is returned for invalid SRV record values.
	ErrInvalidSRV = errors.New("SRV requires valid target and port 0-65535")
	// ErrInvalidCAA is returned for invalid CAA record values.
	ErrInvalidCAA = errors.New("CAA requires tag (issue, issuewild, iodef) and value")
	// ErrInvalidURI is returned for invalid URI record values.
	ErrInvalidURI = errors.New("URI value must be a valid URL")
	// ErrInvalidLabel is returned for invalid DNS record names (labels).
	ErrInvalidLabel = errors.New("invalid DNS label")
	// ErrInvalidFWD is returned for invalid FWD record values.
	ErrInvalidFWD = errors.New("FWD requires at least one valid DNS server (IP or FQDN)")
	// ErrInvalidPTR is returned for invalid PTR record values.
	ErrInvalidPTR = errors.New("invalid PTR record")
)

// IsValidDNSLabel returns true if s is a valid DNS label (@, or max 63 chars: a-z, A-Z, 0-9, hyphen).
func IsValidDNSLabel(s string) bool {
	if s == "" {
		return false
	}
	if s == "@" {
		return true
	}
	if len(s) > 63 {
		return false
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '*') {
			return false
		}
	}
	return true
}

// ValidateRecord validates a DNS record according to type-specific rules.
func ValidateRecord(record Record, zoneDomain string) error {
	// Validate name (must be @ or valid DNS label)
	if record.Name == "" {
		return fmt.Errorf("%w: name cannot be empty", ErrInvalidDomain)
	}
	if !IsValidDNSLabel(record.Name) {
		return fmt.Errorf("%w: invalid record name %q", ErrInvalidLabel, record.Name)
	}

	// Validate TTL
	if record.TTL < 0 {
		return fmt.Errorf("TTL cannot be negative")
	}
	if record.TTL > 0 && record.TTL < 300 {
		return fmt.Errorf("TTL should be at least 300 seconds")
	}

	switch record.Type {
	case TypeA:
		ip := net.ParseIP(record.Value)
		if ip == nil || ip.To4() == nil {
			return ErrInvalidIPv4
		}
	case TypeAAAA:
		ip := net.ParseIP(record.Value)
		if ip == nil || ip.To4() != nil {
			return ErrInvalidIPv6
		}
	case TypeCNAME:
		if record.Name == "@" {
			return ErrCNAMEAtApex
		}
		if !isValidFQDN(record.Value) {
			return fmt.Errorf("%w: invalid CNAME target %q", ErrInvalidDomain, record.Value)
		}
	case TypeMX:
		if record.Priority < 0 || record.Priority > 65535 {
			return ErrInvalidMXPriority
		}
		if !isValidFQDN(record.Value) {
			return fmt.Errorf("%w: invalid MX target %q", ErrInvalidDomain, record.Value)
		}
	case TypeTXT:
		if len(record.Value) > 255 {
			return ErrTXTTooLong
		}
	case TypeNS:
		if !isValidFQDN(record.Value) {
			return fmt.Errorf("%w: invalid NS target %q", ErrInvalidDomain, record.Value)
		}
	case TypeSOA:
		// SOA has multiple fields - basic validation
		if record.Value == "" {
			return fmt.Errorf("SOA requires value")
		}
	case TypeSRV:
		if record.Priority < 0 || record.Priority > 65535 {
			return ErrInvalidMXPriority
		}
		if record.Weight < 0 || record.Weight > 65535 {
			return fmt.Errorf("SRV weight must be 0-65535")
		}
		if record.Port < 0 || record.Port > 65535 {
			return fmt.Errorf("SRV port must be 0-65535")
		}
		if !isValidFQDN(record.Value) {
			return fmt.Errorf("%w: invalid SRV target %q", ErrInvalidDomain, record.Value)
		}
	case TypePTR:
		// Value must not be an IP address — common mistake (PTR points to hostname, not IP)
		if net.ParseIP(record.Value) != nil {
			return fmt.Errorf("%w: value must be a hostname, not an IP address", ErrInvalidPTR)
		}
		if !isValidFQDN(record.Value) {
			return fmt.Errorf("%w: invalid PTR target name %q", ErrInvalidDomain, record.Value)
		}
		// In in-addr.arpa zones: name must be @ or a number 0-255 (last IP octet)
		if strings.HasSuffix(zoneDomain, "in-addr.arpa") && record.Name != "@" {
			if !isValidIPv4Octet(record.Name) {
				return fmt.Errorf("%w: name in in-addr.arpa must be a number 0-255, not %q", ErrInvalidPTR, record.Name)
			}
		}
		// In ip6.arpa zones: name must be @ or a hex nibble (0-9, a-f)
		if strings.HasSuffix(zoneDomain, "ip6.arpa") && record.Name != "@" {
			if !isValidIPv6Nibble(record.Name) {
				return fmt.Errorf("%w: name in ip6.arpa must be a hex nibble (0-9 or a-f), not %q", ErrInvalidPTR, record.Name)
			}
		}
	case TypeCAA:
		// Tag: issue, issuewild, iodef. Priority: flags 0-255. Value: CA domain or iodef URL
		if record.Value == "" {
			return ErrInvalidCAA
		}
		tag := strings.ToLower(strings.TrimSpace(record.Tag))
		if tag == "" || (tag != "issue" && tag != "issuewild" && tag != "iodef") {
			return fmt.Errorf("%w: tag must be issue, issuewild, or iodef", ErrInvalidCAA)
		}
		if record.Priority < 0 || record.Priority > 255 {
			return fmt.Errorf("CAA flags must be 0-255")
		}
		if len(record.Value) > 255 {
			return ErrTXTTooLong
		}
	case TypeDNAME:
		if record.Name == "@" {
			return fmt.Errorf("DNAME not allowed at zone apex")
		}
		if !isValidFQDN(record.Value) {
			return fmt.Errorf("%w: invalid DNAME target %q", ErrInvalidDomain, record.Value)
		}
	case TypeSPF:
		if len(record.Value) > 255 {
			return ErrTXTTooLong
		}
	case TypeURI:
		if record.Priority < 0 || record.Priority > 65535 {
			return ErrInvalidMXPriority
		}
		if record.Value == "" || !isValidURI(record.Value) {
			return ErrInvalidURI
		}
	case TypeFWD:
		if record.Name != "@" {
			return fmt.Errorf("FWD record must be at zone apex (@)")
		}
		if record.Value == "" {
			return ErrInvalidFWD
		}
		for _, s := range strings.Split(record.Value, ",") {
			s = strings.TrimSpace(s)
			host, _, err := net.SplitHostPort(s)
			if err != nil {
				host = s
			}
			if net.ParseIP(host) == nil && !isValidFQDN(host) {
				return fmt.Errorf("%w: invalid server %q", ErrInvalidFWD, s)
			}
		}
	default:
		return fmt.Errorf("unsupported record type: %s", record.Type)
	}

	return nil
}

// ValidateZone validates zone metadata.
func ValidateZone(zone *Zone) error {
	if zone == nil {
		return errors.New("zone cannot be nil")
	}
	if zone.Domain == "" {
		return fmt.Errorf("%w: domain cannot be empty", ErrInvalidDomain)
	}
	if !IsValidDomain(zone.Domain) {
		return fmt.Errorf("%w: %q", ErrInvalidDomain, zone.Domain)
	}
	if zone.TTL > 0 && zone.TTL < 300 {
		return fmt.Errorf("zone TTL should be at least 300 seconds")
	}
	if zone.TTLOverride < 0 {
		return fmt.Errorf("ttl_override must not be negative")
	}
	if zone.TTLOverride > 0 && zone.TTLOverride < 60 {
		return fmt.Errorf("ttl_override must be at least 60 seconds")
	}
	if zone.TTLOverride > 604800 {
		return fmt.Errorf("ttl_override must not exceed 604800 seconds (7 days)")
	}
	for _, r := range zone.Records {
		if err := ValidateRecord(r, zone.Domain); err != nil {
			return fmt.Errorf("invalid record %s: %w", r.Name, err)
		}
	}
	return nil
}

func isValidFQDN(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return false
	}
	return isValidHostname(s)
}

// isValidHostname validates a DNS hostname that may appear as a record target
// (PTR, MX, NS, SRV values). Unlike IsValidDomain, underscores are allowed
// because DHCP-registered hostnames (e.g. ESP_CC8108) and service labels
// (e.g. _sip._tcp) legitimately contain underscores.
func isValidHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '*') {
				return false
			}
		}
	}
	return true
}

// IsValidDomain returns true if s is a valid DNS domain name (e.g. example.com).
// Use for validating user-provided domain names from URLs or API input.
func IsValidDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '*') {
				return false
			}
		}
	}
	return true
}

// NormalizeDomain normalizes a domain name for consistent storage/comparison.
// Converts to lowercase, trims whitespace, and removes trailing dot.
func NormalizeDomain(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimSuffix(domain, ".")
	return domain
}

func isValidURI(s string) bool {
	if len(s) == 0 || len(s) > 2048 {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || len(s) <= len(u.Scheme)+1 {
		return false
	}
	// SSRF prevention: reject file scheme (local file access)
	if strings.EqualFold(u.Scheme, "file") {
		return false
	}
	if isInternalHost(u.Host) {
		return false
	}
	return true
}

// isValidIPv4Octet checks whether s is a valid number 0-255 (for PTR names in in-addr.arpa).
func isValidIPv4Octet(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n >= 0 && n <= 255
}

// isValidIPv6Nibble checks whether s is a single hex character (for PTR names in ip6.arpa).
func isValidIPv6Nibble(s string) bool {
	if len(s) != 1 {
		return false
	}
	c := s[0]
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}

// isInternalHost returns true for localhost, loopback, and private IP ranges.
func isInternalHost(host string) bool {
	hostname := host
	if len(host) >= 2 && host[0] == '[' {
		if end := strings.Index(host, "]"); end > 0 {
			hostname = host[1:end]
		}
	} else if idx := strings.LastIndex(host, ":"); idx > 0 {
		// host:port for IPv4
		if net.ParseIP(host[:idx]) != nil {
			hostname = host[:idx]
		}
	}
	ip := net.ParseIP(hostname)
	if ip == nil {
		return strings.EqualFold(hostname, "localhost")
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return true
	}
	return false
}
