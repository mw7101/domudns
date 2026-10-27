package filestore

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"time"

	"github.com/mw7101/domudns/internal/store"
)

// apiKeysPath returns the path to the named API keys file.
func (s *FileStore) apiKeysPath() string {
	return filepath.Join(s.dataDir, "api_keys.json")
}

// CreateNamedAPIKey generates a new named API key, stores it, and returns it with the Key field set.
func (s *FileStore) CreateNamedAPIKey(_ context.Context, name, description string) (*store.NamedAPIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	key := hex.EncodeToString(keyBytes)

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("generate id: %w", err)
	}
	id := hex.EncodeToString(idBytes)

	var keys []store.NamedAPIKey
	if err := readJSON(s.apiKeysPath(), &keys); err != nil {
		return nil, fmt.Errorf("read api keys: %w", err)
	}

	entry := store.NamedAPIKey{
		ID:          id,
		Name:        name,
		Description: description,
		Key:         key,
		CreatedAt:   time.Now().UTC(),
	}
	keys = append(keys, entry)

	if err := atomicWriteJSON(s.apiKeysPath(), keys); err != nil {
		return nil, err
	}
	return &entry, nil
}

// ListNamedAPIKeys returns all named API keys without the Key field.
func (s *FileStore) ListNamedAPIKeys(_ context.Context) ([]store.NamedAPIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var keys []store.NamedAPIKey
	if err := readJSON(s.apiKeysPath(), &keys); err != nil {
		return []store.NamedAPIKey{}, nil
	}
	// Strip key values from list response
	result := make([]store.NamedAPIKey, len(keys))
	for i, k := range keys {
		result[i] = store.NamedAPIKey{
			ID:          k.ID,
			Name:        k.Name,
			Description: k.Description,
			CreatedAt:   k.CreatedAt,
		}
	}
	return result, nil
}

// GetAllNamedAPIKeys returns all named API keys including the Key field (for cluster sync).
func (s *FileStore) GetAllNamedAPIKeys(_ context.Context) ([]store.NamedAPIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var keys []store.NamedAPIKey
	if err := readJSON(s.apiKeysPath(), &keys); err != nil {
		return []store.NamedAPIKey{}, nil
	}
	return keys, nil
}

// SetNamedAPIKeys replaces the full list of named API keys (for cluster sync on slaves).
func (s *FileStore) SetNamedAPIKeys(_ context.Context, keys []store.NamedAPIKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if keys == nil {
		keys = []store.NamedAPIKey{}
	}
	return atomicWriteJSON(s.apiKeysPath(), keys)
}

// DeleteNamedAPIKey removes a named API key by ID.
func (s *FileStore) DeleteNamedAPIKey(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var keys []store.NamedAPIKey
	if err := readJSON(s.apiKeysPath(), &keys); err != nil {
		return fmt.Errorf("read api keys: %w", err)
	}
	newKeys := make([]store.NamedAPIKey, 0, len(keys))
	found := false
	for _, k := range keys {
		if k.ID == id {
			found = true
		} else {
			newKeys = append(newKeys, k)
		}
	}
	if !found {
		return fmt.Errorf("api key not found: %s", id)
	}
	return atomicWriteJSON(s.apiKeysPath(), newKeys)
}

// ValidateNamedAPIKey checks whether key matches any stored named API key (constant-time).
func (s *FileStore) ValidateNamedAPIKey(_ context.Context, key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if key == "" {
		return false
	}
	var keys []store.NamedAPIKey
	if err := readJSON(s.apiKeysPath(), &keys); err != nil {
		return false
	}
	// Use constant-time comparison across all keys to prevent timing attacks.
	// Avoid early-exit so execution time is independent of match position.
	var found int
	for _, k := range keys {
		found |= subtle.ConstantTimeCompare([]byte(key), []byte(k.Key))
	}
	return found == 1
}
