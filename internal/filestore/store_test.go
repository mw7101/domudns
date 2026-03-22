package filestore_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/mw7101/domudns/internal/dns"
	"github.com/mw7101/domudns/internal/filestore"
	"github.com/mw7101/domudns/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStore(t *testing.T) (*filestore.FileStore, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "filestore-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	fs, err := filestore.NewFileStore(dir)
	require.NoError(t, err)
	return fs, dir
}

func TestFileStore_HealthCheck(t *testing.T) {
	fs, _ := newTestStore(t)
	assert.NoError(t, fs.HealthCheck(context.Background()))
}

func TestFileStore_Zones(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestStore(t)

	// GetZone: not found
	_, err := fs.GetZone(ctx, "example.com")
	assert.ErrorIs(t, err, dns.ErrZoneNotFound)

	// PutZone
	zone := &dns.Zone{
		Domain: "example.com",
		TTL:    3600,
		Records: []dns.Record{
			{ID: 1, Name: "@", Type: dns.TypeA, TTL: 3600, Value: "1.2.3.4"},
		},
	}
	require.NoError(t, fs.PutZone(ctx, zone))

	// GetZone
	got, err := fs.GetZone(ctx, "example.com")
	require.NoError(t, err)
	assert.Equal(t, "example.com", got.Domain)
	assert.Len(t, got.Records, 1)
	assert.Equal(t, "1.2.3.4", got.Records[0].Value)

	// ListZones
	zones, err := fs.ListZones(ctx)
	require.NoError(t, err)
	assert.Len(t, zones, 1)

	// DeleteZone
	require.NoError(t, fs.DeleteZone(ctx, "example.com"))
	_, err = fs.GetZone(ctx, "example.com")
	assert.ErrorIs(t, err, dns.ErrZoneNotFound)
}

func TestFileStore_Records(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestStore(t)

	// Create zone
	zone := &dns.Zone{Domain: "test.local", TTL: 3600, Records: []dns.Record{}}
	require.NoError(t, fs.PutZone(ctx, zone))

	// PutRecord
	rec := &dns.Record{Name: "www", Type: dns.TypeA, TTL: 300, Value: "10.0.0.1"}
	require.NoError(t, fs.PutRecord(ctx, "test.local", rec))
	assert.Greater(t, rec.ID, 0)

	// GetRecords
	records, err := fs.GetRecords(ctx, "test.local")
	require.NoError(t, err)
	assert.Len(t, records, 1)

	// DeleteRecord
	require.NoError(t, fs.DeleteRecord(ctx, "test.local", rec.ID))
	records, err = fs.GetRecords(ctx, "test.local")
	require.NoError(t, err)
	assert.Len(t, records, 0)
}

func TestFileStore_PutRecord_IncrementsSOASerial(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestStore(t)

	zone := &dns.Zone{
		Domain:  "serial.local",
		TTL:     3600,
		Records: []dns.Record{},
		SOA:     &dns.SOA{Serial: 2020010100},
	}
	require.NoError(t, fs.PutZone(ctx, zone))

	rec := &dns.Record{Name: "a", Type: dns.TypeA, TTL: 300, Value: "10.0.0.1"}
	require.NoError(t, fs.PutRecord(ctx, "serial.local", rec))

	got, err := fs.GetZone(ctx, "serial.local")
	require.NoError(t, err)
	require.NotNil(t, got.SOA)
	assert.Greater(t, got.SOA.Serial, uint32(2020010100), "serial must be incremented after PutRecord")

	// Second PutRecord must increment again
	serial1 := got.SOA.Serial
	rec2 := &dns.Record{Name: "b", Type: dns.TypeA, TTL: 300, Value: "10.0.0.2"}
	require.NoError(t, fs.PutRecord(ctx, "serial.local", rec2))
	got, err = fs.GetZone(ctx, "serial.local")
	require.NoError(t, err)
	assert.Greater(t, got.SOA.Serial, serial1, "serial must increase on each PutRecord")
}

func TestFileStore_DeleteRecord_IncrementsSOASerial(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestStore(t)

	zone := &dns.Zone{
		Domain:  "delserial.local",
		TTL:     3600,
		Records: []dns.Record{},
		SOA:     &dns.SOA{Serial: 2020010100},
	}
	require.NoError(t, fs.PutZone(ctx, zone))

	rec := &dns.Record{Name: "x", Type: dns.TypeA, TTL: 300, Value: "10.1.1.1"}
	require.NoError(t, fs.PutRecord(ctx, "delserial.local", rec))

	got, err := fs.GetZone(ctx, "delserial.local")
	require.NoError(t, err)
	serialAfterAdd := got.SOA.Serial

	require.NoError(t, fs.DeleteRecord(ctx, "delserial.local", rec.ID))
	got, err = fs.GetZone(ctx, "delserial.local")
	require.NoError(t, err)
	assert.Greater(t, got.SOA.Serial, serialAfterAdd, "serial must be incremented after DeleteRecord")
}

func TestFileStore_Auth(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestStore(t)

	// GetAuthConfig: empty config
	cfg, err := fs.GetAuthConfig(ctx)
	require.NoError(t, err)
	assert.Equal(t, "", cfg.Username)

	// UpdateAuthConfig
	cfg = &store.AuthConfig{
		Username:       "admin",
		PasswordHash:   "$2a$12$test",
		APIKey:         "abc123",
		SetupCompleted: false,
	}
	require.NoError(t, fs.UpdateAuthConfig(ctx, cfg))

	// Load and verify
	loaded, err := fs.GetAuthConfig(ctx)
	require.NoError(t, err)
	assert.Equal(t, "admin", loaded.Username)
	assert.Equal(t, "$2a$12$test", loaded.PasswordHash)
	assert.False(t, loaded.SetupCompleted)

	// MarkSetupCompleted
	require.NoError(t, fs.MarkSetupCompleted(ctx))
	loaded, err = fs.GetAuthConfig(ctx)
	require.NoError(t, err)
	assert.True(t, loaded.SetupCompleted)
}

func TestFileStore_Blocklist(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestStore(t)

	// AddBlocklistURL
	u, err := fs.AddBlocklistURL(ctx, "https://example.com/list.txt", true)
	require.NoError(t, err)
	assert.Equal(t, 1, u.ID)

	// ListBlocklistURLs
	urls, err := fs.ListBlocklistURLs(ctx)
	require.NoError(t, err)
	assert.Len(t, urls, 1)

	// SetBlocklistURLDomains
	domains := []string{"ads.example.com", "tracker.example.net"}
	require.NoError(t, fs.SetBlocklistURLDomains(ctx, u.ID, domains))

	// GetMergedBlocklist
	merged, err := fs.GetMergedBlocklist(ctx)
	require.NoError(t, err)
	assert.Len(t, merged, 2)

	// AddAllowedDomain → should be removed from blocklist
	require.NoError(t, fs.AddAllowedDomain(ctx, "ads.example.com"))
	merged, err = fs.GetMergedBlocklist(ctx)
	require.NoError(t, err)
	assert.Len(t, merged, 1)
	assert.Equal(t, "tracker.example.net", merged[0])

	// WhitelistIPs
	require.NoError(t, fs.AddWhitelistIP(ctx, "192.168.1.0/24"))
	ips, err := fs.ListWhitelistIPs(ctx)
	require.NoError(t, err)
	assert.Contains(t, ips, "192.168.1.0/24")

	// RemoveWhitelistIP
	require.NoError(t, fs.RemoveWhitelistIP(ctx, "192.168.1.0/24"))
	ips, err = fs.ListWhitelistIPs(ctx)
	require.NoError(t, err)
	assert.NotContains(t, ips, "192.168.1.0/24")
}

func TestFileStore_ManualDomains(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestStore(t)

	require.NoError(t, fs.AddBlockedDomain(ctx, "evil.example.com"))
	domains, err := fs.ListBlockedDomains(ctx)
	require.NoError(t, err)
	assert.Contains(t, domains, "evil.example.com")

	merged, err := fs.GetMergedBlocklist(ctx)
	require.NoError(t, err)
	assert.Contains(t, merged, "evil.example.com")

	require.NoError(t, fs.RemoveBlockedDomain(ctx, "evil.example.com"))
	domains, err = fs.ListBlockedDomains(ctx)
	require.NoError(t, err)
	assert.NotContains(t, domains, "evil.example.com")
}

func TestFileStore_ConfigOverrides(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestStore(t)

	// Empty
	overrides, err := fs.GetConfigOverrides(ctx)
	require.NoError(t, err)
	assert.Empty(t, overrides)

	// Update
	require.NoError(t, fs.UpdateConfigOverrides(ctx, map[string]interface{}{
		"system": map[string]interface{}{
			"log_level": "debug",
		},
	}))

	// Load
	overrides, err = fs.GetConfigOverrides(ctx)
	require.NoError(t, err)
	system, ok := overrides["system"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "debug", system["log_level"])
}

func TestFileStore_ACME(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestStore(t)

	// PutACMEChallenge
	require.NoError(t, fs.PutACMEChallenge(ctx, "_acme-challenge.example.com", "xyz123", 60*time.Second))
	// DeleteACMEChallenge
	require.NoError(t, fs.DeleteACMEChallenge(ctx, "_acme-challenge.example.com"))
}

func TestFileStore_URLFetchUpdate(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestStore(t)

	u, err := fs.AddBlocklistURL(ctx, "https://example.com/list.txt", true)
	require.NoError(t, err)

	// UpdateBlocklistURLFetch - success
	require.NoError(t, fs.UpdateBlocklistURLFetch(ctx, u.ID, nil))
	urls, err := fs.ListBlocklistURLs(ctx)
	require.NoError(t, err)
	assert.NotNil(t, urls[0].LastFetchedAt)
	assert.Nil(t, urls[0].LastError)

	// UpdateBlocklistURLFetch - error
	errStr := "connection refused"
	require.NoError(t, fs.UpdateBlocklistURLFetch(ctx, u.ID, &errStr))
	urls, err = fs.ListBlocklistURLs(ctx)
	require.NoError(t, err)
	assert.Equal(t, "connection refused", *urls[0].LastError)
}

func TestFileStore_PathTraversalProtection(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestStore(t)

	_, err := fs.GetZone(ctx, "../../../etc/passwd")
	assert.Error(t, err)

	err = fs.PutZone(ctx, &dns.Zone{Domain: "../../../etc/passwd"})
	assert.Error(t, err)
}
