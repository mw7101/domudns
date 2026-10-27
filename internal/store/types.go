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
	Category      string     `json:"category,omitempty"` // "" = uncategorized = always active
	Enabled       bool       `json:"enabled"`
	LastFetchedAt *time.Time `json:"last_fetched_at,omitempty"`
	LastError     *string    `json:"last_error,omitempty"` // nil when no fetch error yet
	CreatedAt     time.Time  `json:"created_at"`
}

// BlockedDomainEntry pairs a domain with its blocklist URL source category.
// Category "" means uncategorized (always active for all clients).
type BlockedDomainEntry struct {
	Domain   string
	Category string
}

// URLDomainSet groups blocked domains by their source blocklist URL.
// Used for efficient in-memory updates when a single URL's domains change.
type URLDomainSet struct {
	URLID    int
	Category string
	Domains  []string
}

// TLSACMEConfig holds the Let's Encrypt ACME configuration.
// Stored as tls_acme.json in the data directory.
type TLSACMEConfig struct {
	Enabled bool   `json:"enabled"`
	Domain  string `json:"domain"`  // FQDN, e.g. "dns.example.com"
	Email   string `json:"email"`   // contact email for Let's Encrypt
	Staging bool   `json:"staging"` // true = Let's Encrypt staging CA
}

// TLSCertPayload holds a TLS certificate and private key in PEM format.
// Used as cluster sync payload for EventTLSCert.
// SECURITY: KeyPEM must never appear in log output at any log level.
type TLSCertPayload struct {
	CertPEM string `json:"cert_pem"` // full certificate chain, PEM-encoded
	KeyPEM  string `json:"key_pem"`  // private key, PEM-encoded — NEVER LOG
}

// TLSCertStatus holds the current TLS certificate status for the API.
// Defined here (not in caddy/api or certmanager) to avoid import cycles.
// Both certmanager.CertManager.Status() and caddy/api.CertStatusProvider.Status() use this type.
type TLSCertStatus struct {
	Domain      string    `json:"domain"`
	ValidUntil  time.Time `json:"valid_until,omitempty"`
	LastRenewed time.Time `json:"last_renewed,omitempty"`
	Error       string    `json:"error,omitempty"`
}
