package api

import (
	"context"

	"github.com/mw7101/domudns/internal/filestore"
)

// FileConfigStore adaptiert *filestore.FileStore auf ConfigStore.
type FileConfigStore struct {
	Store *filestore.FileStore
}

// GetOverrides returns config overrides from file.
func (f *FileConfigStore) GetOverrides(ctx context.Context) (map[string]interface{}, error) {
	return f.Store.GetConfigOverrides(ctx)
}

// UpdateOverrides merges and persists config overrides in file.
func (f *FileConfigStore) UpdateOverrides(ctx context.Context, overrides map[string]interface{}) error {
	return f.Store.UpdateConfigOverrides(ctx, overrides)
}
