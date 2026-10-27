package filestore

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// URLDomainMeta identifies a per-URL blocklist domain set by a checksum over
// its raw gzip bytes. Master and slave compute it identically because both
// persist the same deterministic gzip stream (newline-separated domains,
// gzipped with default settings). It lets a slave detect stale or missing
// per-URL domain sets during the normal poll and pull only those.
type URLDomainMeta struct {
	URLID  int    `json:"url_id"`
	SHA256 string `json:"sha256"`
}

// ListURLDomainsMeta returns a checksum for every per-URL blocklist domain
// file. The hash (over the raw gzip bytes) is cached by size+mtime, so a
// periodic poll over unchanged files does not re-read them.
func (s *FileStore) ListURLDomainsMeta() ([]URLDomainMeta, error) {
	dir := s.urlDomainsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read url domains dir: %w", err)
	}

	s.domainsMetaMu.Lock()
	defer s.domainsMetaMu.Unlock()
	if s.domainsMetaCache == nil {
		s.domainsMetaCache = make(map[int]domainMetaCacheEntry)
	}

	seen := make(map[int]struct{}, len(entries))
	out := make([]URLDomainMeta, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".domains.gz") {
			continue
		}
		id, err := strconv.Atoi(strings.TrimSuffix(name, ".domains.gz"))
		if err != nil || id <= 0 {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		seen[id] = struct{}{}
		size, mtime := info.Size(), info.ModTime().UnixNano()
		if c, ok := s.domainsMetaCache[id]; ok && c.size == size && c.mtime == mtime {
			out = append(out, URLDomainMeta{URLID: id, SHA256: c.sha})
			continue
		}
		sha, err := hashFileSHA256(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		s.domainsMetaCache[id] = domainMetaCacheEntry{size: size, mtime: mtime, sha: sha}
		out = append(out, URLDomainMeta{URLID: id, SHA256: sha})
	}
	for id := range s.domainsMetaCache {
		if _, ok := seen[id]; !ok {
			delete(s.domainsMetaCache, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URLID < out[j].URLID })
	return out, nil
}

// ReadURLDomainsGz returns the raw gzip bytes of a per-URL blocklist file.
func (s *FileStore) ReadURLDomainsGz(urlID int) ([]byte, error) {
	if urlID <= 0 {
		return nil, fmt.Errorf("invalid url id %d", urlID)
	}
	path := filepath.Join(s.urlDomainsDir(), fmt.Sprintf("%d.domains.gz", urlID))
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read url domains %d: %w", urlID, err)
	}
	return data, nil
}

// WriteURLDomainsGz atomically stores raw gzip bytes for a URL. Used by a
// slave pulling a domain set from the master. The bytes are written verbatim
// so the resulting local checksum matches the master's exactly.
func (s *FileStore) WriteURLDomainsGz(urlID int, gz []byte) error {
	if urlID <= 0 {
		return fmt.Errorf("invalid url id %d", urlID)
	}
	path := filepath.Join(s.urlDomainsDir(), fmt.Sprintf("%d.domains.gz", urlID))
	return atomicWriteBytes(path, gz)
}

// hashFileSHA256 returns the hex SHA256 of a file's contents.
func hashFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
