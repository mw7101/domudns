package blocklist

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteHostsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.hosts")
	err := WriteHostsFile(path, []string{"evil.com", "ads.example.com"}, "0.0.0.0", "::")
	require.NoError(t, err)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	content := string(data)
	assert.Contains(t, content, "0.0.0.0 evil.com")
	assert.Contains(t, content, ":: evil.com")
	assert.Contains(t, content, "0.0.0.0 ads.example.com")
	assert.Contains(t, content, ":: ads.example.com")
}

func TestWriteHostsFile_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.hosts")
	err := WriteHostsFile(path, []string{}, "0.0.0.0", "::")
	require.NoError(t, err)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Empty(t, data)
}

func TestWriteHostsFile_CreatesDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "blocklist.hosts")
	err := WriteHostsFile(path, []string{"test.com"}, "0.0.0.0", "::")
	require.NoError(t, err)
	assert.FileExists(t, path)
}
