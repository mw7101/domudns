package blocklist

import (
	"bufio"
	"regexp"
	"strings"
)

// ParseHostsOrDomains parses blocklist content.
// Supports: hosts format (0.0.0.0 domain), domains format (one per line), adblock-style (||domain^).
func ParseHostsOrDomains(content string) []string {
	seen := make(map[string]bool)
	var domains []string

	// Adblock-style: ||domain.com^ or ||sub.domain.com^
	adblockRe := regexp.MustCompile(`^\|\|([a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)*)\^`)

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Adblock format
		if m := adblockRe.FindStringSubmatch(line); len(m) > 1 {
			d := normalizeDomain(m[1])
			if d != "" && !seen[d] {
				seen[d] = true
				domains = append(domains, d)
			}
			continue
		}
		// Hosts format: IP domain [domain ...] or domain-only line
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			// First field might be IP; rest are domains
			for i := 1; i < len(fields); i++ {
				d := normalizeDomain(fields[i])
				if d != "" && !seen[d] {
					seen[d] = true
					domains = append(domains, d)
				}
			}
		} else if len(fields) == 1 {
			d := normalizeDomain(fields[0])
			if d != "" && !seen[d] {
				seen[d] = true
				domains = append(domains, d)
			}
		}
	}
	return domains
}

func normalizeDomain(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" || domain == "localhost" {
		return ""
	}
	return domain
}
