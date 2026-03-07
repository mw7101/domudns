package filestore

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/mw7101/domudns/internal/store"
)

// tsigKeysPath returns the path to the TSIG keys file.
func (s *FileStore) tsigKeysPath() string {
	return filepath.Join(s.dataDir, "tsig_keys.json")
}

// GetTSIGKeys returns all stored TSIG keys.
func (s *FileStore) GetTSIGKeys(_ context.Context) ([]store.TSIGKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var keys []store.TSIGKey
	if err := readJSON(s.tsigKeysPath(), &keys); err != nil {
		return nil, fmt.Errorf("GetTSIGKeys: %w", err)
	}
	if keys == nil {
		return []store.TSIGKey{}, nil
	}
	return keys, nil
}

// PutTSIGKey stores a TSIG key (upsert by name).
func (s *FileStore) PutTSIGKey(_ context.Context, key store.TSIGKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var keys []store.TSIGKey
	if err := readJSON(s.tsigKeysPath(), &keys); err != nil {
		return fmt.Errorf("PutTSIGKey read: %w", err)
	}

	updated := false
	for i, k := range keys {
		if k.Name == key.Name {
			keys[i] = key
			updated = true
			break
		}
	}
	if !updated {
		keys = append(keys, key)
	}

	if err := atomicWriteJSON(s.tsigKeysPath(), keys); err != nil {
		return fmt.Errorf("PutTSIGKey write: %w", err)
	}
	return nil
}

// DeleteTSIGKey deletes a TSIG key by name.
func (s *FileStore) DeleteTSIGKey(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var keys []store.TSIGKey
	if err := readJSON(s.tsigKeysPath(), &keys); err != nil {
		return fmt.Errorf("DeleteTSIGKey read: %w", err)
	}

	filtered := make([]store.TSIGKey, 0, len(keys))
	for _, k := range keys {
		if k.Name != name {
			filtered = append(filtered, k)
		}
	}

	if err := atomicWriteJSON(s.tsigKeysPath(), filtered); err != nil {
		return fmt.Errorf("DeleteTSIGKey write: %w", err)
	}
	return nil
}

// SetTSIGKeys replaces all TSIG keys (for cluster sync).
func (s *FileStore) SetTSIGKeys(_ context.Context, keys []store.TSIGKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if keys == nil {
		keys = []store.TSIGKey{}
	}
	if err := atomicWriteJSON(s.tsigKeysPath(), keys); err != nil {
		return fmt.Errorf("SetTSIGKeys write: %w", err)
	}
	return nil
}
