//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/mw7101/domudns/internal/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration_ALIAS_RecordStoredAndRetrieved(t *testing.T) {
	ctx := context.Background()
	fs := newTestStore(t)

	zone := &dns.Zone{
		Domain: "alias-integration.test.",
		TTL:    3600,
		Records: []dns.Record{
			{Name: "@", Type: dns.TypeALIAS, TTL: 3600, Value: "cdn.example.com"},
			{Name: "www", Type: dns.TypeALIAS, TTL: 3600, Value: "www.cdn.example.com"},
		},
	}

	err := fs.PutZone(ctx, zone)
	require.NoError(t, err)

	got, err := fs.GetZone(ctx, "alias-integration.test.")
	require.NoError(t, err)
	require.Len(t, got.Records, 2)

	byName := make(map[string]dns.Record, len(got.Records))
	for _, r := range got.Records {
		byName[r.Name] = r
	}

	apex, ok := byName["@"]
	require.True(t, ok, "expected record with Name=\"@\"")
	assert.Equal(t, dns.TypeALIAS, apex.Type)
	assert.Equal(t, "cdn.example.com", apex.Value)

	www, ok := byName["www"]
	require.True(t, ok, "expected record with Name=\"www\"")
	assert.Equal(t, dns.TypeALIAS, www.Type)
	assert.Equal(t, "www.cdn.example.com", www.Value)
}
