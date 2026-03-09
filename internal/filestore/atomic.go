package filestore

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// atomicWriteJSON serializes v as JSON and writes it atomically to path.
// Uses temp-file + os.Rename (guaranteed atomic on Linux).
func atomicWriteJSON(path string, v interface{}) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		// Delete temp file if rename failed
		if _, err := os.Stat(tmpPath); err == nil {
			_ = os.Remove(tmpPath)
		}
	}()
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// readJSON reads and deserializes JSON from path into v.
// Returns nil if the file does not exist (empty state).
func readJSON(path string, v interface{}) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

// writeGzipDomains writes domains gzip-compressed as newline-separated strings.
func writeGzipDomains(path string, domains []string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-gz-")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if _, err := os.Stat(tmpPath); err == nil {
			_ = os.Remove(tmpPath)
		}
	}()
	gz := gzip.NewWriter(tmp)
	for _, d := range domains {
		if _, err := io.WriteString(gz, d+"\n"); err != nil {
			return fmt.Errorf("write gz: %w", err)
		}
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("close gz: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	return os.Rename(tmpPath, path)
}

// readGzipDomains reads newline-separated domains from a gzip file.
func readGzipDomains(path string) ([]string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer gr.Close()
	data, err := io.ReadAll(gr)
	if err != nil {
		return nil, fmt.Errorf("read gz: %w", err)
	}
	lines := strings.Split(string(data), "\n")
	domains := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			domains = append(domains, l)
		}
	}
	return domains, nil
}

// sanitizeDomainFilename checks domain name for allowed characters (path traversal protection).
func sanitizeDomainFilename(domain string) (string, error) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, c := range domain {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_') {
			return "", fmt.Errorf("invalid domain character: %c", c)
		}
	}
	if domain == "" || domain == "." || domain == ".." {
		return "", fmt.Errorf("invalid domain name: %q", domain)
	}
	return domain, nil
}
