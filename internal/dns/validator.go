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
	// ErrALIASConflict is returned when ALIAS and CNAME exist at the same name.
	ErrALIASConflict = errors.New("ALIAS and CNAME cannot coexist at the same name")
)

// isValidLabel validates a single DNS label: 1-63 chars, no leading or
// trailing hyphen, and only characters isValidLabelChar allows.
func isValidLabel(label string, allowUnderscore bool) bool {
	if len(label) == 0 || len(label) > 63 {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, c := range label {
		if !isValidLabelChar(c, allowUnderscore) {
			return false
		}
	}
	return true
}

// IsValidDNSLabel returns true if s is a valid DNS label (@, or max 63 chars: a-z, A-Z, 0-9, hyphen).
func IsValidDNSLabel(s string) bool {
	if s == "@" {
		return true
	}
	return isValidLabel(s, true)
}

// IsValidRelativeRecordName reports whether s is a valid record name relative
// to a zone: "@" for the apex, or one or more dot-separated labels
// (e.g. "www", "_acme-challenge.pve-node"), each 1-63 chars. Every label uses the
// same character rules as a hostname label (a-z, A-Z, 0-9, '-', '*', '_').
// A multi-label name containing "*" (e.g. "*.dev") is rejected: a "*" label
// only acts as a DNS wildcard when it is a record's sole label.
func IsValidRelativeRecordName(s string) bool {
	if s == "@" {
		return true
	}
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	// A "*" label only acts as a DNS wildcard when it is a record's sole
	// label (see ZoneManager.matchZoneRecords, which wildcards only a bare
	// "*" for single-label subdomains). A multi-label name containing "*"
	// (e.g. "*.dev") would be stored but never match as a wildcard, so reject
	// it rather than accept a silent no-op. Single-label "*" and literal
	// "*"-containing single labels (e.g. "a*b") keep their previous behaviour.
	if strings.Contains(s, ".") && strings.Contains(s, "*") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !isValidLabel(label, true) {
			return false
		}
	}
	return true
}

// MinRecordTTL is the minimum TTL (in seconds) a stored record may have.
// The API layer clamps client-supplied values to it instead of rejecting them.
const MinRecordTTL = 300

// ValidateRecord validates a DNS record according to type-specific rules.
func ValidateRecord(record Record, zoneDomain string) error {
	// Validate name (must be @ or a valid zone-relative record name)
	if record.Name == "" {
		return fmt.Errorf("%w: name cannot be empty", ErrInvalidDomain)
	}
	if !IsValidRelativeRecordName(record.Name) {
		return fmt.Errorf("%w: invalid record name %q", ErrInvalidLabel, record.Name)
	}

	// Validate TTL
	if record.TTL < 0 {
		return fmt.Errorf("TTL cannot be negative")
	}
	if record.TTL > 0 && record.TTL < MinRecordTTL {
		return fmt.Errorf("TTL should be at least %d seconds", MinRecordTTL)
	}

	validate, ok := recordValidators[record.Type]
	if !ok {
		return fmt.Errorf("unsupported record type: %s", record.Type)
	}
	return validate(record, zoneDomain)
}

// recordValidators holds one type-specific validation function per record
// type, keyed by Record.Type. Each entry does exactly one type's checks;
// ValidateRecord only dispatches to them after the shared name/TTL checks.
var recordValidators = map[RecordType]func(Record, string) error{
	TypeA:     validateARecord,
	TypeAAAA:  validateAAAARecord,
	TypeCNAME: validateCNAMERecord,
	TypeMX:    validateMXRecord,
	TypeTXT:   validateTXTRecord,
	TypeNS:    validateNSRecord,
	TypeSOA:   validateSOARecord,
	TypeSRV:   validateSRVRecord,
	TypePTR:   validatePTRRecord,
	TypeCAA:   validateCAARecord,
	TypeDNAME: validateDNAMERecord,
	TypeSPF:   validateSPFRecord,
	TypeURI:   validateURIRecord,
	TypeALIAS: validateALIASRecord,
	TypeFWD:   validateFWDRecord,
}

func validateARecord(record Record, _ string) error {
	ip := net.ParseIP(record.Value)
	if ip == nil || ip.To4() == nil {
		return ErrInvalidIPv4
	}
	return nil
}

func validateAAAARecord(record Record, _ string) error {
	ip := net.ParseIP(record.Value)
	if ip == nil || ip.To4() != nil {
		return ErrInvalidIPv6
	}
	return nil
}

func validateCNAMERecord(record Record, _ string) error {
	if record.Name == "@" {
		return ErrCNAMEAtApex
	}
	if !isValidFQDN(record.Value) {
		return fmt.Errorf("%w: invalid CNAME target %q", ErrInvalidDomain, record.Value)
	}
	return nil
}

func validateMXRecord(record Record, _ string) error {
	if record.Priority < 0 || record.Priority > 65535 {
		return ErrInvalidMXPriority
	}
	if !isValidFQDN(record.Value) {
		return fmt.Errorf("%w: invalid MX target %q", ErrInvalidDomain, record.Value)
	}
	return nil
}

func validateTXTRecord(record Record, _ string) error {
	if len(record.Value) > 255 {
		return ErrTXTTooLong
	}
	return nil
}

func validateNSRecord(record Record, _ string) error {
	if !isValidFQDN(record.Value) {
		return fmt.Errorf("%w: invalid NS target %q", ErrInvalidDomain, record.Value)
	}
	return nil
}

// validateSOARecord: SOA has multiple fields - basic validation.
func validateSOARecord(record Record, _ string) error {
	if record.Value == "" {
		return fmt.Errorf("SOA requires value")
	}
	return nil
}

func validateSRVRecord(record Record, _ string) error {
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
	return nil
}

func validatePTRRecord(record Record, zoneDomain string) error {
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
	return nil
}

// validateCAARecord: Tag: issue, issuewild, iodef. Priority: flags 0-255. Value: CA domain or iodef URL.
func validateCAARecord(record Record, _ string) error {
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
	return nil
}

func validateDNAMERecord(record Record, _ string) error {
	if record.Name == "@" {
		return fmt.Errorf("DNAME not allowed at zone apex")
	}
	if !isValidFQDN(record.Value) {
		return fmt.Errorf("%w: invalid DNAME target %q", ErrInvalidDomain, record.Value)
	}
	return nil
}

func validateSPFRecord(record Record, _ string) error {
	if len(record.Value) > 255 {
		return ErrTXTTooLong
	}
	return nil
}

func validateURIRecord(record Record, _ string) error {
	if record.Priority < 0 || record.Priority > 65535 {
		return ErrInvalidMXPriority
	}
	if record.Value == "" || !isValidURI(record.Value) {
		return ErrInvalidURI
	}
	return nil
}

func validateALIASRecord(record Record, _ string) error {
	if !isValidFQDN(record.Value) {
		return fmt.Errorf("%w: invalid ALIAS target %q", ErrInvalidDomain, record.Value)
	}
	return nil
}

func validateFWDRecord(record Record, _ string) error {
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
	// Check for ALIAS + CNAME conflict at the same name (R6).
	type typePair struct{ hasAlias, hasCNAME bool }
	namePairs := make(map[string]*typePair)
	for _, r := range zone.Records {
		p := namePairs[r.Name]
		if p == nil {
			p = &typePair{}
			namePairs[r.Name] = p
		}
		if r.Type == TypeALIAS {
			p.hasAlias = true
		}
		if r.Type == TypeCNAME {
			p.hasCNAME = true
		}
	}
	for name, p := range namePairs {
		if p.hasAlias && p.hasCNAME {
			return fmt.Errorf("record %s: %w", name, ErrALIASConflict)
		}
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
	for _, label := range strings.Split(s, ".") {
		if !isValidLabel(label, true) {
			return false
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
	for _, label := range strings.Split(s, ".") {
		if !isValidLabel(label, false) {
			return false
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
