package store

import (
	"context"
	"time"

	"github.com/mw7101/domudns/internal/dns"
)

// ---------------------------------------------------------------------------
// Blocklist
// ---------------------------------------------------------------------------

// BlocklistReader provides read-only access to blocklist data.
type BlocklistReader interface {
	ListBlocklistURLs(ctx context.Context) ([]BlocklistURL, error)
	ListBlockedDomains(ctx context.Context) ([]string, error)
	ListAllowedDomains(ctx context.Context) ([]string, error)
	ListWhitelistIPs(ctx context.Context) ([]string, error)
	GetMergedBlocklist(ctx context.Context) ([]string, error)
	ListBlocklistPatterns(ctx context.Context) ([]BlocklistPattern, error)
}

// BlocklistWriter provides write access to blocklist data.
type BlocklistWriter interface {
	AddBlocklistURL(ctx context.Context, url string, enabled bool) (*BlocklistURL, error)
	RemoveBlocklistURL(ctx context.Context, id int) error
	SetBlocklistURLEnabled(ctx context.Context, id int, enabled bool) error
	UpdateBlocklistURLFetch(ctx context.Context, id int, lastError *string) error
	SetBlocklistURLDomains(ctx context.Context, urlID int, domains []string) error
	AddBlockedDomain(ctx context.Context, domain string) error
	RemoveBlockedDomain(ctx context.Context, domain string) error
	AddAllowedDomain(ctx context.Context, domain string) error
	RemoveAllowedDomain(ctx context.Context, domain string) error
	AddWhitelistIP(ctx context.Context, ipCIDR string) error
	RemoveWhitelistIP(ctx context.Context, ipCIDR string) error
	AddBlocklistPattern(ctx context.Context, pattern string, patternType string) (*BlocklistPattern, error)
	RemoveBlocklistPattern(ctx context.Context, id int) error
}

// BlocklistStore provides full read/write access to blocklist data.
type BlocklistStore interface {
	BlocklistReader
	BlocklistWriter
}

// ---------------------------------------------------------------------------
// Zones
// ---------------------------------------------------------------------------

// ZoneReader provides read-only access to zone data.
type ZoneReader interface {
	GetZone(ctx context.Context, domain string) (*dns.Zone, error)
	GetZoneView(ctx context.Context, domain, view string) (*dns.Zone, error)
	ListZones(ctx context.Context) ([]*dns.Zone, error)
}

// ZoneWriter provides write access to zone data.
type ZoneWriter interface {
	PutZone(ctx context.Context, zone *dns.Zone) error
	DeleteZone(ctx context.Context, domain string) error
	DeleteZoneView(ctx context.Context, domain, view string) error
}

// ZoneStore provides full read/write access to zone data.
type ZoneStore interface {
	ZoneReader
	ZoneWriter
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

// RecordReader provides read-only access to record data.
// It embeds ZoneReader because record lookups require loading the parent zone.
type RecordReader interface {
	ZoneReader
	GetRecords(ctx context.Context, zoneDomain string) ([]dns.Record, error)
}

// RecordWriter provides write access to record data.
type RecordWriter interface {
	PutRecord(ctx context.Context, zoneDomain string, record *dns.Record) error
	DeleteRecord(ctx context.Context, zoneDomain string, recordID int) error
}

// RecordStore provides full read/write access to record data.
type RecordStore interface {
	RecordReader
	RecordWriter
}

// ---------------------------------------------------------------------------
// ACME
// ---------------------------------------------------------------------------

// ACMEReader provides read-only access to ACME challenge data.
type ACMEReader interface {
	// (no read methods defined in the current API layer)
}

// ACMEWriter provides write access to ACME challenge data.
type ACMEWriter interface {
	PutACMEChallenge(ctx context.Context, fqdn, value string, ttl time.Duration) error
	DeleteACMEChallenge(ctx context.Context, fqdn string) error
}

// ACMEStore provides full read/write access to ACME challenge data.
type ACMEStore interface {
	ACMEReader
	ACMEWriter
}

// ---------------------------------------------------------------------------
// TSIG Keys
// ---------------------------------------------------------------------------

// TSIGKeyStore manages TSIG keys for RFC 2136 DDNS authentication.
type TSIGKeyStore interface {
	GetTSIGKeys(ctx context.Context) ([]TSIGKey, error)
	PutTSIGKey(ctx context.Context, key TSIGKey) error
	DeleteTSIGKey(ctx context.Context, name string) error
}

// ---------------------------------------------------------------------------
// Named API Keys
// ---------------------------------------------------------------------------

// NamedAPIKeyStore manages named API keys for external tool authentication.
type NamedAPIKeyStore interface {
	CreateNamedAPIKey(ctx context.Context, name, description string) (*NamedAPIKey, error)
	ListNamedAPIKeys(ctx context.Context) ([]NamedAPIKey, error)
	DeleteNamedAPIKey(ctx context.Context, id string) error
	ValidateNamedAPIKey(ctx context.Context, key string) bool
}
