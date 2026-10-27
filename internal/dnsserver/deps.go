package dnsserver

import (
	"context"

	"github.com/mw7101/domudns/internal/dns"
	"github.com/mw7101/domudns/internal/querylog"
	"github.com/mw7101/domudns/internal/store"
)

// BlocklistProvider is the minimal interface the DNS pipeline needs from the blocklist.
// Implemented by *filestore.FileStore (via blocklist fetch loop).
type BlocklistProvider interface {
	// GetBlocklistURLSets returns blocked domains grouped by their source URL ID and category.
	// Only enabled URLs are included. Called once during Load().
	GetBlocklistURLSets(ctx context.Context) ([]store.URLDomainSet, error)
	// GetManualBlockedDomains returns the list of manually blocked domains (no URL source).
	GetManualBlockedDomains(ctx context.Context) ([]string, error)
	// GetAllowedBlockedDomains returns the blocklist allowlist — domains exempt from blocking.
	GetAllowedBlockedDomains(ctx context.Context) ([]string, error)
	GetWhitelistIPs(ctx context.Context) ([]string, error)
	// GetBlocklistPatterns returns wildcard patterns (e.g. "*.ads.com") and regex patterns.
	GetBlocklistPatterns(ctx context.Context) (wildcards []string, regexps []string, err error)
}

// ZoneProvider is the minimal interface the DNS pipeline needs from zone storage.
// Implemented by *filestore.FileStore.
type ZoneProvider interface {
	ListZones(ctx context.Context) ([]*dns.Zone, error)
	GetRecords(ctx context.Context, zoneDomain string) ([]dns.Record, error)
}

// ACMEChallengeProvider serves ACME TXT challenges to the DNS pipeline.
// Implemented by *filestore.FileStore.
type ACMEChallengeProvider interface {
	GetACMEChallenge(ctx context.Context, fqdn string) (string, bool)
}

// QueryLogProvider gives the cache warmer access to query stats.
// Implemented by *querylog.QueryLogger.
type QueryLogProvider interface {
	Stats() querylog.QueryLogStats
}

// DDNSStoreProvider is the minimal store interface for RFC 2136 DDNS updates.
// Provides only the methods update.go actually calls: GetZone, GetRecords, PutRecord, DeleteRecord.
type DDNSStoreProvider interface {
	GetZone(ctx context.Context, domain string) (*dns.Zone, error)
	GetRecords(ctx context.Context, zoneDomain string) ([]dns.Record, error)
	PutRecord(ctx context.Context, zoneDomain string, record *dns.Record) error
	DeleteRecord(ctx context.Context, zoneDomain string, recordID int) error
}
