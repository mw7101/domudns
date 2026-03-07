package filestore

import (
	"context"
	"time"

	"github.com/mw7101/domudns/internal/store"
)

// GetAuthConfig liest die Auth-Konfiguration aus auth.json.
func (s *FileStore) GetAuthConfig(_ context.Context) (*store.AuthConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var cfg store.AuthConfig
	if err := readJSON(s.authPath(), &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// UpdateAuthConfig schreibt die Auth-Konfiguration in auth.json.
func (s *FileStore) UpdateAuthConfig(_ context.Context, cfg *store.AuthConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg.UpdatedAt = time.Now()
	return atomicWriteJSON(s.authPath(), cfg)
}

// MarkSetupCompleted setzt setup_completed = true in auth.json.
func (s *FileStore) MarkSetupCompleted(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var cfg store.AuthConfig
	if err := readJSON(s.authPath(), &cfg); err != nil {
		return err
	}
	cfg.SetupCompleted = true
	cfg.UpdatedAt = time.Now()
	return atomicWriteJSON(s.authPath(), &cfg)
}
