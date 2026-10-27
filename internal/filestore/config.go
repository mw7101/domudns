package filestore

import (
	"context"
	"encoding/json"
)

// GetConfigOverrides reads config overrides from config_overrides.json.
func (s *FileStore) GetConfigOverrides(_ context.Context) (map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var overrides map[string]interface{}
	if err := readJSON(s.configOverridesPath(), &overrides); err != nil {
		return nil, err
	}
	if overrides == nil {
		return map[string]interface{}{}, nil
	}
	return overrides, nil
}

// UpdateConfigOverrides merges new overrides and saves them.
func (s *FileStore) UpdateConfigOverrides(_ context.Context, overrides map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var existing map[string]interface{}
	if err := readJSON(s.configOverridesPath(), &existing); err != nil {
		return err
	}
	if existing == nil {
		existing = make(map[string]interface{})
	}
	merged := mergeOverridesMap(existing, overrides)
	return atomicWriteJSON(s.configOverridesPath(), merged)
}

// mergeOverridesMap deep-merges src into dst. Values in src overwrite dst.
func mergeOverridesMap(dst, src map[string]interface{}) map[string]interface{} {
	if dst == nil {
		dst = make(map[string]interface{})
	}
	for k, v := range src {
		if v == nil {
			continue
		}
		if srcMap, ok := v.(map[string]interface{}); ok {
			if dstV, exists := dst[k]; exists {
				if dstMap, ok := dstV.(map[string]interface{}); ok {
					dst[k] = mergeOverridesMap(dstMap, srcMap)
					continue
				}
			}
			dst[k] = mergeOverridesMap(map[string]interface{}{}, srcMap)
		} else {
			dst[k] = v
		}
	}
	return dst
}

// SetConfigOverrides completely overwrites config overrides (for cluster sync).
func (s *FileStore) SetConfigOverrides(_ context.Context, overrides map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return atomicWriteJSON(s.configOverridesPath(), overrides)
}

// GetRawConfigOverrides returns the config overrides as JSON bytes (for cluster sync).
func (s *FileStore) GetRawConfigOverrides(_ context.Context) (json.RawMessage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var overrides map[string]interface{}
	if err := readJSON(s.configOverridesPath(), &overrides); err != nil {
		return nil, err
	}
	if overrides == nil {
		return json.RawMessage("{}"), nil
	}
	return json.Marshal(overrides)
}
