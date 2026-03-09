package blocklist

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteHostsFile writes a hosts-format blocklist file.
// Each domain gets two lines: ip4 and ip6.
func WriteHostsFile(path string, domains []string, ip4, ip6 string) error {
	if ip4 == "" {
		ip4 = "0.0.0.0"
	}
	if ip6 == "" {
		ip6 = "::"
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create blocklist dir: %w", err)
	}
	var buf []byte
	for _, d := range domains {
		if d == "" {
			continue
		}
		buf = append(buf, fmt.Sprintf("%s %s\n", ip4, d)...)
		buf = append(buf, fmt.Sprintf("%s %s\n", ip6, d)...)
	}
	return os.WriteFile(path, buf, 0644)
}
