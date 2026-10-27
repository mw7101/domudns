package filestore

import (
	"context"
	"path/filepath"

	"github.com/mw7101/domudns/internal/dns"
)

func (s *FileStore) clientGroupsPath() string {
	return filepath.Join(s.dataDir, "client_groups.json")
}

// GetClientGroups returns the configured client groups.
// Returns an empty slice (not nil) if the file does not exist.
func (s *FileStore) GetClientGroups(_ context.Context) ([]*dns.ClientGroup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var groups []*dns.ClientGroup
	err := readJSON(s.clientGroupsPath(), &groups)
	if err != nil {
		return nil, err
	}
	if groups == nil {
		groups = []*dns.ClientGroup{}
	}
	return groups, nil
}

// SetClientGroups writes the client groups atomically.
func (s *FileStore) SetClientGroups(_ context.Context, groups []*dns.ClientGroup) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if groups == nil {
		groups = []*dns.ClientGroup{}
	}
	return atomicWriteJSON(s.clientGroupsPath(), groups)
}
