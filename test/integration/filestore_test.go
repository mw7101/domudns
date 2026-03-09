//go:build integration

package integration

import (
	"context"
	"os"
	"testing"

	"github.com/mw7101/domudns/internal/dns"
	"github.com/mw7101/domudns/internal/filestore"
	"github.com/mw7101/domudns/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStore(t *testing.T) *filestore.FileStore {
	t.Helper()
	dir, err := os.MkdirTemp("", "integration-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	fs, err := filestore.NewFileStore(dir)
	require.NoError(t, err)
	return fs
}

func TestIntegration_ZoneLifecycle(t *testing.T) {
	ctx := context.Background()
	fs := newTestStore(t)

	// Zone anlegen
	zone := &dns.Zone{
		Domain: "integration.test.",
		TTL:    3600,
		Records: []dns.Record{
			{Name: "@", Type: dns.TypeA, TTL: 300, Value: "10.0.0.1"},
			{Name: "www", Type: dns.TypeA, TTL: 300, Value: "10.0.0.2"},
			{Name: "mail", Type: dns.TypeMX, TTL: 300, Value: "10 mail.integration.test."},
		},
	}
	require.NoError(t, fs.PutZone(ctx, zone))

	// Laden und prüfen
	loaded, err := fs.GetZone(ctx, "integration.test.")
	require.NoError(t, err)
	assert.Equal(t, "integration.test.", loaded.Domain)
	assert.Len(t, loaded.Records, 3)

	// Record hinzufügen
	rec := &dns.Record{Name: "vpn", Type: dns.TypeA, TTL: 60, Value: "10.0.0.3"}
	require.NoError(t, fs.PutRecord(ctx, "integration.test.", rec))
	assert.Greater(t, rec.ID, 0)

	// Zone mit neuem Record laden
	loaded, err = fs.GetZone(ctx, "integration.test.")
	require.NoError(t, err)
	assert.Len(t, loaded.Records, 4)

	// Record löschen
	require.NoError(t, fs.DeleteRecord(ctx, "integration.test.", rec.ID))
	loaded, err = fs.GetZone(ctx, "integration.test.")
	require.NoError(t, err)
	assert.Len(t, loaded.Records, 3)

	// Zone löschen
	require.NoError(t, fs.DeleteZone(ctx, "integration.test."))
	_, err = fs.GetZone(ctx, "integration.test.")
	assert.ErrorIs(t, err, dns.ErrZoneNotFound)
}

func TestIntegration_BlocklistLifecycle(t *testing.T) {
	ctx := context.Background()
	fs := newTestStore(t)

	// URL hinzufügen
	u, err := fs.AddBlocklistURL(ctx, "https://example.com/blocklist.txt", true)
	require.NoError(t, err)
	assert.Equal(t, 1, u.ID)

	// Domains setzen (simuliert Fetch-Ergebnis)
	domains := []string{"ads.evil.com", "tracker.evil.com", "malware.evil.com"}
	require.NoError(t, fs.SetBlocklistURLDomains(ctx, u.ID, domains))

	// Merged Blocklist
	merged, err := fs.GetMergedBlocklist(ctx)
	require.NoError(t, err)
	assert.Len(t, merged, 3)

	// Manuelle Domain blockieren
	require.NoError(t, fs.AddBlockedDomain(ctx, "phishing.example.com"))
	merged, err = fs.GetMergedBlocklist(ctx)
	require.NoError(t, err)
	assert.Len(t, merged, 4)

	// Domain erlauben (whitelist) — ads.evil.com soll nicht mehr geblockt werden
	require.NoError(t, fs.AddAllowedDomain(ctx, "ads.evil.com"))
	merged, err = fs.GetMergedBlocklist(ctx)
	require.NoError(t, err)
	assert.Len(t, merged, 3) // ads.evil.com entfernt
	assert.NotContains(t, merged, "ads.evil.com")

	// Whitelist-IP
	require.NoError(t, fs.AddWhitelistIP(ctx, "192.168.100.0/24"))
	ips, err := fs.ListWhitelistIPs(ctx)
	require.NoError(t, err)
	assert.Contains(t, ips, "192.168.100.0/24")
}

func TestIntegration_AuthLifecycle(t *testing.T) {
	ctx := context.Background()
	fs := newTestStore(t)

	// Initiale Auth-Config leer
	cfg, err := fs.GetAuthConfig(ctx)
	require.NoError(t, err)
	assert.Equal(t, "", cfg.Username)
	assert.False(t, cfg.SetupCompleted)

	// Auth-Config setzen
	newCfg := &store.AuthConfig{
		Username:       "admin",
		PasswordHash:   "$2a$12$testhashtesthashhashtest",
		APIKey:         "abc123def456",
		SetupCompleted: false,
	}
	require.NoError(t, fs.UpdateAuthConfig(ctx, newCfg))

	// Setup abschließen
	require.NoError(t, fs.MarkSetupCompleted(ctx))

	// Prüfen
	loaded, err := fs.GetAuthConfig(ctx)
	require.NoError(t, err)
	assert.Equal(t, "admin", loaded.Username)
	assert.True(t, loaded.SetupCompleted)
}

func TestIntegration_ConfigOverrides(t *testing.T) {
	ctx := context.Background()
	fs := newTestStore(t)

	overrides := map[string]interface{}{
		"system": map[string]interface{}{
			"log_level": "debug",
		},
		"blocklist": map[string]interface{}{
			"enabled": true,
		},
	}
	require.NoError(t, fs.UpdateConfigOverrides(ctx, overrides))

	loaded, err := fs.GetConfigOverrides(ctx)
	require.NoError(t, err)

	system, ok := loaded["system"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "debug", system["log_level"])
}
