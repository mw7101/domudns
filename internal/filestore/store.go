// Package filestore implements the api.Store via local JSON files.
// Replaces PostgreSQL and etcd as the storage backend for file-based cluster setup.
package filestore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// FileStore implements api.Store via local JSON files.
// Thread-safe via RWMutex for all file accesses.
type FileStore struct {
	dataDir string
	mu      sync.RWMutex
}

// NewFileStore creates a new FileStore with the specified data directory.
func NewFileStore(dataDir string) (*FileStore, error) {
	s := &FileStore{dataDir: dataDir}
	if err := s.ensureDirs(); err != nil {
		return nil, fmt.Errorf("filestore init: %w", err)
	}
	return s, nil
}

// ensureDirs creates all required subdirectories.
func (s *FileStore) ensureDirs() error {
	dirs := []string{
		filepath.Join(s.dataDir, "zones"),
		filepath.Join(s.dataDir, "blocklist", "url_domains"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	return nil
}

// DataDir returns the data directory.
func (s *FileStore) DataDir() string {
	return s.dataDir
}

// HealthCheck checks whether the data directory exists and is readable.
func (s *FileStore) HealthCheck(ctx context.Context) error {
	if _, err := os.Stat(s.dataDir); err != nil {
		return fmt.Errorf("data directory not accessible: %w", err)
	}
	return nil
}

// zonesDir returns the path to the zones directory.
func (s *FileStore) zonesDir() string {
	return filepath.Join(s.dataDir, "zones")
}

// blocklistDir returns the path to the blocklist directory.
func (s *FileStore) blocklistDir() string {
	return filepath.Join(s.dataDir, "blocklist")
}

// urlDomainsDir returns the path to the URL domains directory.
func (s *FileStore) urlDomainsDir() string {
	return filepath.Join(s.dataDir, "blocklist", "url_domains")
}

// authPath returns the path to the auth config file.
func (s *FileStore) authPath() string {
	return filepath.Join(s.dataDir, "auth.json")
}

// configOverridesPath returns the path to the config overrides file.
func (s *FileStore) configOverridesPath() string {
	return filepath.Join(s.dataDir, "config_overrides.json")
}

// acmePath returns the path to the ACME challenges file.
func (s *FileStore) acmePath() string {
	return filepath.Join(s.dataDir, "acme_challenges.json")
}

// urlsPath returns the path to the blocklist URLs file.
func (s *FileStore) urlsPath() string {
	return filepath.Join(s.dataDir, "blocklist", "urls.json")
}

// manualDomainsPath returns the path to the manual blocked domains file.
func (s *FileStore) manualDomainsPath() string {
	return filepath.Join(s.dataDir, "blocklist", "domains_manual.json")
}

// allowedDomainsPath returns the path to the allowed domains file.
func (s *FileStore) allowedDomainsPath() string {
	return filepath.Join(s.dataDir, "blocklist", "allowed_domains.json")
}

// whitelistIPsPath returns the path to the whitelist IPs file.
func (s *FileStore) whitelistIPsPath() string {
	return filepath.Join(s.dataDir, "blocklist", "whitelist_ips.json")
}

// patternsPath returns the path to the blocklist patterns file.
func (s *FileStore) patternsPath() string {
	return filepath.Join(s.dataDir, "blocklist", "patterns.json")
}
