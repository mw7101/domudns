package filestore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mw7101/domudns/internal/dns"
)

// isValidViewName checks whether a view name is valid: only [a-z0-9_-], max 64 characters.
func isValidViewName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// sanitizeZoneFilename returns the filename for a zone.
// For default zones: sanitizeDomainFilename(domain).
// For view zones: sanitizeDomainFilename(domain) + "@" + view.
func sanitizeZoneFilename(domain, view string) (string, error) {
	d, err := sanitizeDomainFilename(domain)
	if err != nil {
		return "", err
	}
	if view == "" {
		return d, nil
	}
	if !isValidViewName(view) {
		return "", fmt.Errorf("invalid view name: %q", view)
	}
	return d + "@" + view, nil
}

// splitZoneKey splits a zone key (e.g. "nas.home@internal") into domain + view.
func splitZoneKey(key string) (domain, view string) {
	if idx := strings.LastIndex(key, "@"); idx >= 0 {
		return key[:idx], key[idx+1:]
	}
	return key, ""
}

// GetZone loads a default zone from the file zones/<domain>.json.
func (s *FileStore) GetZone(_ context.Context, domain string) (*dns.Zone, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadZoneFile(domain)
}

// GetZoneView loads a view-specific zone from zones/<domain>@<view>.json.
func (s *FileStore) GetZoneView(_ context.Context, domain, view string) (*dns.Zone, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadZoneViewFile(domain, view)
}

// ListZones returns all zones (default + view-specific).
func (s *FileStore) ListZones(_ context.Context) ([]*dns.Zone, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.zonesDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list zones: %w", err)
	}

	var zones []*dns.Zone
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		key := strings.TrimSuffix(e.Name(), ".json")
		zone, err := s.loadZoneFile(key)
		if err != nil {
			continue
		}
		zones = append(zones, zone)
	}
	return zones, nil
}

// PutZone saves a zone to zones/<domain>.json (or zones/<domain>@<view>.json if View != "").
func (s *FileStore) PutZone(_ context.Context, zone *dns.Zone) error {
	if zone.Domain == "" {
		return fmt.Errorf("zone domain required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveZoneFile(zone)
}

// DeleteZone deletes the default zone file (zones/<domain>.json).
func (s *FileStore) DeleteZone(_ context.Context, domain string) error {
	filename, err := sanitizeDomainFilename(domain)
	if err != nil {
		return fmt.Errorf("invalid domain: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.zonesDir(), filename+".json")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete zone: %w", err)
	}
	return nil
}

// DeleteZoneView deletes a view-specific zone file (zones/<domain>@<view>.json).
func (s *FileStore) DeleteZoneView(_ context.Context, domain, view string) error {
	filename, err := sanitizeZoneFilename(domain, view)
	if err != nil {
		return fmt.Errorf("invalid zone: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.zonesDir(), filename+".json")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("delete zone view: %w", err)
	}
	return nil
}

// PutRecord adds a record to a zone or updates it.
// zoneDomain can be "domain" (default zone) or "domain@view" (view zone).
func (s *FileStore) PutRecord(_ context.Context, zoneDomain string, record *dns.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	zone, err := s.loadZoneFile(zoneDomain)
	if err != nil {
		return err
	}
	if zone == nil {
		return dns.ErrZoneNotFound
	}
	if record.ID == 0 {
		record.ID = zone.NextRecordID()
	}
	found := false
	for i := range zone.Records {
		if zone.Records[i].ID == record.ID {
			zone.Records[i] = *record
			found = true
			break
		}
	}
	if !found {
		zone.Records = append(zone.Records, *record)
	}
	return s.saveZoneFile(zone)
}

// GetRecords returns all records of a zone.
// zoneDomain can be "domain" (default zone) or "domain@view" (view zone).
func (s *FileStore) GetRecords(_ context.Context, zoneDomain string) ([]dns.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	zone, err := s.loadZoneFile(zoneDomain)
	if err != nil {
		return nil, err
	}
	if zone == nil {
		return nil, dns.ErrZoneNotFound
	}
	return zone.Records, nil
}

// DeleteRecord removes a record from a zone.
// zoneDomain can be "domain" (default zone) or "domain@view" (view zone).
func (s *FileStore) DeleteRecord(_ context.Context, zoneDomain string, recordID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	zone, err := s.loadZoneFile(zoneDomain)
	if err != nil {
		return err
	}
	if zone == nil {
		return dns.ErrZoneNotFound
	}
	if zone.RecordByID(recordID) == nil {
		return dns.ErrRecordNotFound
	}
	newRecords := make([]dns.Record, 0, len(zone.Records))
	for _, r := range zone.Records {
		if r.ID != recordID {
			newRecords = append(newRecords, r)
		}
	}
	zone.Records = newRecords
	return s.saveZoneFile(zone)
}

// loadZoneFile loads a zone from the file (without lock, for internal use).
// key can be "domain" (default) or "domain@view" (view zone).
func (s *FileStore) loadZoneFile(key string) (*dns.Zone, error) {
	domain, view := splitZoneKey(key)
	filename, err := sanitizeZoneFilename(domain, view)
	if err != nil {
		return nil, fmt.Errorf("invalid zone key: %w", err)
	}
	path := filepath.Join(s.zonesDir(), filename+".json")
	var zone dns.Zone
	if err := readJSON(path, &zone); err != nil {
		return nil, err
	}
	if zone.Domain == "" {
		return nil, dns.ErrZoneNotFound
	}
	return &zone, nil
}

// loadZoneViewFile loads a view-specific zone (without lock, for internal use).
func (s *FileStore) loadZoneViewFile(domain, view string) (*dns.Zone, error) {
	filename, err := sanitizeZoneFilename(domain, view)
	if err != nil {
		return nil, fmt.Errorf("invalid zone: %w", err)
	}
	path := filepath.Join(s.zonesDir(), filename+".json")
	var zone dns.Zone
	if err := readJSON(path, &zone); err != nil {
		return nil, err
	}
	if zone.Domain == "" {
		return nil, dns.ErrZoneNotFound
	}
	return &zone, nil
}

// saveZoneFile saves a zone to the file (without lock, for internal use).
// The filename is determined from zone.Domain and zone.View.
func (s *FileStore) saveZoneFile(zone *dns.Zone) error {
	filename, err := sanitizeZoneFilename(zone.Domain, zone.View)
	if err != nil {
		return fmt.Errorf("invalid zone: %w", err)
	}
	path := filepath.Join(s.zonesDir(), filename+".json")
	return atomicWriteJSON(path, zone)
}
