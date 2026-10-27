package filestore

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestURLDomainsMetaReflectsFilesAndChanges(t *testing.T) {
	fs, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	ctx := context.Background()

	meta, err := fs.ListURLDomainsMeta()
	require.NoError(t, err)
	require.Empty(t, meta)

	require.NoError(t, fs.SetBlocklistURLDomains(ctx, 7, []string{"a.com", "b.com"}))

	meta, err = fs.ListURLDomainsMeta()
	require.NoError(t, err)
	require.Len(t, meta, 1)
	require.Equal(t, 7, meta[0].URLID)
	require.NotEmpty(t, meta[0].SHA256)

	// Cached call returns the same checksum.
	again, err := fs.ListURLDomainsMeta()
	require.NoError(t, err)
	require.Equal(t, meta[0].SHA256, again[0].SHA256)

	// Changing the domain set changes the checksum.
	require.NoError(t, fs.SetBlocklistURLDomains(ctx, 7, []string{"a.com"}))
	changed, err := fs.ListURLDomainsMeta()
	require.NoError(t, err)
	require.NotEqual(t, meta[0].SHA256, changed[0].SHA256)
}

func TestWriteURLDomainsGzMatchesSameBytes(t *testing.T) {
	fs, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, fs.SetBlocklistURLDomains(ctx, 1, []string{"x.com", "y.com"}))
	gz, err := fs.ReadURLDomainsGz(1)
	require.NoError(t, err)
	require.NotEmpty(t, gz)

	// A byte-for-byte copy must produce the identical checksum.
	require.NoError(t, fs.WriteURLDomainsGz(2, gz))
	meta, err := fs.ListURLDomainsMeta()
	require.NoError(t, err)
	require.Len(t, meta, 2)
	require.Equal(t, meta[0].SHA256, meta[1].SHA256)
	require.Equal(t, 1, meta[0].URLID)
	require.Equal(t, 2, meta[1].URLID)
}

func TestURLDomainsGzRejectsInvalidID(t *testing.T) {
	fs, err := NewFileStore(t.TempDir())
	require.NoError(t, err)

	_, err = fs.ReadURLDomainsGz(0)
	require.Error(t, err)
	require.Error(t, fs.WriteURLDomainsGz(-1, []byte("x")))
}
