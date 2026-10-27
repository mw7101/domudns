package store

import "time"

// TSIGKey is a TSIG key for RFC 2136 DDNS authentication.
type TSIGKey struct {
	Name      string    `json:"name"`      // Key name (matches dhcpd key-name)
	Algorithm string    `json:"algorithm"` // "hmac-sha256" | "hmac-sha512" | "hmac-sha1"
	Secret    string    `json:"secret"`    // Base64-encoded (ISC dhcpd format)
	CreatedAt time.Time `json:"created_at"`
}

// BlocklistPattern represents a wildcard or regex domain blocking rule.
type BlocklistPattern struct {
	ID int `json:"id"`
	// Pattern is either "*.example.com" (wildcard) or "/^regexp$/" (regex, delimited by /).
	Pattern string `json:"pattern"`
	// Type is "wildcard" or "regex".
	Type      string    `json:"type"`
	CreatedAt time.Time `json:"created_at"`
}

// BlocklistURL represents a blocklist URL entry (shared type for postgres, etcd, API).
type BlocklistURL struct {
	ID            int        `json:"id"`
	URL           string     `json:"url"`
	Enabled       bool       `json:"enabled"`
	LastFetchedAt *time.Time `json:"last_fetched_at,omitempty"`
	LastError     *string    `json:"last_error,omitempty"` // nil when no fetch error yet
	CreatedAt     time.Time  `json:"created_at"`
}
