package blocklist

import (
	"strings"
)

// Merge returns blocked domains minus allowed.
// A domain is excluded if it equals an allowed domain or is a subdomain of one.
func Merge(blocked []string, allowed []string) []string {
	allowedSet := make(map[string]bool)
	for _, a := range allowed {
		a = strings.TrimSpace(strings.ToLower(a))
		a = strings.TrimSuffix(a, ".")
		if a != "" {
			allowedSet[a] = true
		}
	}
	var result []string
	for _, b := range blocked {
		b = strings.TrimSpace(strings.ToLower(b))
		b = strings.TrimSuffix(b, ".")
		if b == "" {
			continue
		}
		if isAllowed(b, allowedSet) {
			continue
		}
		result = append(result, b)
	}
	return result
}

func isAllowed(domain string, allowed map[string]bool) bool {
	if allowed[domain] {
		return true
	}
	// Check if domain is subdomain of an allowed domain (e.g. ads.evil.com for allowed evil.com)
	for a := range allowed {
		if domain == a {
			return true
		}
		if strings.HasSuffix(domain, "."+a) {
			return true
		}
	}
	return false
}
