// Package cluster implements the master/slave sync protocol for file-based clustering.
// Push protocol: master POST → /api/internal/sync on each slave (secured with HMAC-SHA256).
// Fallback: slave polls master every 30s (GET /api/internal/state).
package cluster

import "encoding/json"

// SyncEventType identifies the type of a sync event.
type SyncEventType string

const (
	// EventZoneUpdated: data = *dns.Zone (complete zone state)
	EventZoneUpdated SyncEventType = "zone_updated"
	// EventZoneDeleted: data = string (domain)
	EventZoneDeleted SyncEventType = "zone_deleted"
	// EventBlocklistURLs: data = []store.BlocklistURL
	EventBlocklistURLs SyncEventType = "blocklist_urls"
	// EventManualDomains: data = []string (manually blocked domains)
	EventManualDomains SyncEventType = "manual_domains"
	// EventAllowedDomains: data = []string (allowed domains)
	EventAllowedDomains SyncEventType = "allowed_domains"
	// EventWhitelistIPs: data = []string (client IP CIDRs)
	EventWhitelistIPs SyncEventType = "whitelist_ips"
	// EventURLDomains: data = URLDomainsPayload
	EventURLDomains SyncEventType = "url_domains"
	// EventAuthConfig: data = store.AuthConfig
	EventAuthConfig SyncEventType = "auth_config"
	// EventConfigOverrides: data = map[string]interface{}
	EventConfigOverrides SyncEventType = "config_overrides"
	// EventBlocklistPatterns: data = []store.BlocklistPattern
	EventBlocklistPatterns SyncEventType = "blocklist_patterns"
	// EventTSIGKeys: data = []store.TSIGKey
	EventTSIGKeys SyncEventType = "tsig_keys"
	// EventAPIKeys: data = []store.NamedAPIKey (including Key field for validation on slaves)
	EventAPIKeys SyncEventType = "api_keys"
	// EventClientGroups: data = []*dns.ClientGroup
	EventClientGroups SyncEventType = "client_groups"
	// EventTLSCert: data = store.TLSCertPayload (cert + key PEM, NEVER LOG KeyPEM)
	EventTLSCert SyncEventType = "tls_cert"
)

// SyncRequest is the HTTP body for POST /api/internal/sync.
type SyncRequest struct {
	Type      SyncEventType   `json:"type"`
	Data      json.RawMessage `json:"data"`
	Timestamp int64           `json:"ts"`    // Unix nanoseconds; required for replay protection
	Nonce     string          `json:"nonce"` // 16-byte random hex; required for replay protection
}

// URLDomainsPayload contains domains for a blocklist URL (gzip + base64).
type URLDomainsPayload struct {
	URLID        int    `json:"url_id"`
	DomainsGzB64 string `json:"domains_gz_b64"` // base64(gzip(newline-separated domains))
}

// MasterStateResponse is the response to GET /api/internal/state.
// Contains the complete state of the master for initial slave sync.
type MasterStateResponse struct {
	Zones             json.RawMessage `json:"zones"`              // []*dns.Zone
	BlocklistURLs     json.RawMessage `json:"blocklist_urls"`     // []store.BlocklistURL
	ManualDomains     json.RawMessage `json:"manual_domains"`     // []string
	AllowedDomains    json.RawMessage `json:"allowed_domains"`    // []string
	WhitelistIPs      json.RawMessage `json:"whitelist_ips"`      // []string
	AuthConfig        json.RawMessage `json:"auth_config"`        // store.AuthConfig
	ConfigOverrides   json.RawMessage `json:"config_overrides"`   // map[string]interface{}
	BlocklistPatterns json.RawMessage `json:"blocklist_patterns"` // []store.BlocklistPattern
	TSIGKeys          json.RawMessage `json:"tsig_keys"`          // []store.TSIGKey
	NamedAPIKeys      json.RawMessage `json:"named_api_keys"`     // []store.NamedAPIKey (with Key field)
	ClientGroups      json.RawMessage `json:"client_groups"`      // []*dns.ClientGroup
	TLSACMEConfig     json.RawMessage `json:"tls_acme_config"`    // store.TLSACMEConfig
	TLSCert           json.RawMessage `json:"tls_cert"`           // store.TLSCertPayload (incl. KeyPEM)
	// URLDomainsMeta carries {url_id, sha256} for each per-URL domain set.
	// The lists themselves are too large for the state response and are
	// transferred via EventURLDomains; this metadata lets a slave detect a
	// lost push and pull only the stale/missing sets.
	URLDomainsMeta json.RawMessage `json:"url_domains_meta"`
	// URLDomains is transmitted separately via EventURLDomains (too large for state response)
}
