package dhcp

import (
	"regexp"
	"strings"
	"time"
)

// Lease represents a DHCP lease entry.
type Lease struct {
	MAC      string
	IP       string
	Hostname string
	Expiry   time.Time // Zero value = expiry unknown
}

// SyncStatus contains the current state of DHCP sync.
type SyncStatus struct {
	Enabled     bool      `json:"enabled"`
	Source      string    `json:"source"`
	LastSync    time.Time `json:"last_sync"`
	LastError   string    `json:"last_error,omitempty"`
	LeaseCount  int       `json:"lease_count"`
	RecordCount int       `json:"record_count"`
	NextSync    time.Time `json:"next_sync"`
}

// TrackedLease stores the state of a synchronized lease.
type TrackedLease struct {
	Hostname    string    `json:"hostname"`
	IP          string    `json:"ip"`
	MAC         string    `json:"mac"`
	ARecordID   int       `json:"a_record_id"`
	PTRRecordID int       `json:"ptr_record_id"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// hostnameRegex allows only valid DNS label characters.
var hostnameRegex = regexp.MustCompile(`[^a-z0-9-]`)

// sanitizeHostname cleans a hostname for DNS use.
// Result: only [a-z0-9-], max 63 chars, no - at start/end.
// Empty string or "*" yields "".
func sanitizeHostname(name string) string {
	if name == "" || name == "*" {
		return ""
	}

	// Convert to lowercase
	name = strings.ToLower(name)

	// Remove domain suffix if present (e.g. "laptop.home.lan" -> "laptop")
	if idx := strings.IndexByte(name, '.'); idx > 0 {
		name = name[:idx]
	}

	// Replace invalid chars with -
	name = hostnameRegex.ReplaceAllString(name, "-")

	// Collapse multiple hyphens
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}

	// Remove hyphens at start/end
	name = strings.Trim(name, "-")

	// Max 63 chars (DNS label limit)
	if len(name) > 63 {
		name = name[:63]
		name = strings.TrimRight(name, "-")
	}

	return name
}
