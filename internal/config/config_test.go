package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeOverrides(t *testing.T) {
	t.Run("empty overrides no-op", func(t *testing.T) {
		cfg := &Config{
			Blocklist: BlocklistConfig{Enabled: true},
		}
		err := MergeOverrides(cfg, nil)
		require.NoError(t, err)
		assert.True(t, cfg.Blocklist.Enabled)

		err = MergeOverrides(cfg, map[string]interface{}{})
		require.NoError(t, err)
		assert.True(t, cfg.Blocklist.Enabled)
	})

	t.Run("blocklist enabled override", func(t *testing.T) {
		cfg := &Config{
			Blocklist: BlocklistConfig{Enabled: true},
		}
		err := MergeOverrides(cfg, map[string]interface{}{
			"blocklist": map[string]interface{}{"enabled": false},
		})
		require.NoError(t, err)
		assert.False(t, cfg.Blocklist.Enabled)
	})

	t.Run("nested cache override", func(t *testing.T) {
		cfg := &Config{
			DNSServer: DNSServerConfig{
				Cache: CacheConfig{Enabled: true, Size: 1000, TTL: 300},
			},
		}
		err := MergeOverrides(cfg, map[string]interface{}{
			"dnsserver": map[string]interface{}{
				"cache": map[string]interface{}{"enabled": false, "size": float64(500)},
			},
		})
		require.NoError(t, err)
		assert.False(t, cfg.DNSServer.Cache.Enabled)
		assert.Equal(t, 500, cfg.DNSServer.Cache.Size)
		assert.Equal(t, 300, cfg.DNSServer.Cache.TTL) // unchanged
	})

	t.Run("blocklist with extra top-level key", func(t *testing.T) {
		cfg := &Config{Blocklist: BlocklistConfig{Enabled: true}}
		err := MergeOverrides(cfg, map[string]interface{}{
			"blocklist": map[string]interface{}{"enabled": false},
		})
		require.NoError(t, err)
		assert.False(t, cfg.Blocklist.Enabled)
	})
}
