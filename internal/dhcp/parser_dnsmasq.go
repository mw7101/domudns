package dhcp

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// DnsmasqParser reads DHCP leases from a dnsmasq.leases file.
// Format: <timestamp> <mac> <ip> <hostname> [<client-id>]
type DnsmasqParser struct {
	Path string
}

// Parse reads all active leases from the dnsmasq lease file.
func (p *DnsmasqParser) Parse(_ context.Context) ([]Lease, error) {
	f, err := os.Open(p.Path)
	if err != nil {
		return nil, fmt.Errorf("dnsmasq: open %s: %w", p.Path, err)
	}
	defer f.Close()

	now := time.Now()
	var leases []Lease

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Timestamp: Unix seconds, 0 = static (never expires)
		ts, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			continue
		}

		mac := fields[1]
		ip := fields[2]
		hostname := fields[3]

		// Hostname "*" = no name set
		if hostname == "*" {
			continue
		}

		// Skip expired leases (0 = static/never expires)
		var expiry time.Time
		if ts > 0 {
			expiry = time.Unix(ts, 0)
			if expiry.Before(now) {
				continue
			}
		}

		leases = append(leases, Lease{
			MAC:      mac,
			IP:       ip,
			Hostname: hostname,
			Expiry:   expiry,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("dnsmasq: read %s: %w", p.Path, err)
	}

	return leases, nil
}
