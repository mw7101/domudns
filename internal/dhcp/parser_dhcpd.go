package dhcp

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// DhcpdParser reads DHCP leases from an ISC dhcpd.leases file.
// Block-Format:
//
//	lease <IP> {
//	  starts <weekday> <YYYY/MM/DD> <HH:MM:SS>;
//	  ends <weekday> <YYYY/MM/DD> <HH:MM:SS>;
//	  hardware ethernet <MAC>;
//	  client-hostname "<hostname>";
//	}
type DhcpdParser struct {
	Path string
}

// dhcpdTimeLayout ist das Zeitformat in dhcpd.leases.
const dhcpdTimeLayout = "2006/01/02 15:04:05"

// Parse reads all active leases from the dhcpd.leases file.
// For duplicates (same IP), the newest entry is taken.
func (p *DhcpdParser) Parse(_ context.Context) ([]Lease, error) {
	f, err := os.Open(p.Path)
	if err != nil {
		return nil, fmt.Errorf("dhcpd: open %s: %w", p.Path, err)
	}
	defer f.Close()

	now := time.Now()
	// Map for deduplication: same IP → newest lease
	leaseMap := make(map[string]Lease)

	var (
		inLease  bool
		ip       string
		mac      string
		hostname string
		ends     time.Time
		endsSet  bool
		never    bool
	)

	resetLease := func() {
		inLease = false
		ip = ""
		mac = ""
		hostname = ""
		ends = time.Time{}
		endsSet = false
		never = false
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "lease ") && strings.HasSuffix(line, "{") {
			// New lease block: "lease 192.168.1.10 {"
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				resetLease()
				inLease = true
				ip = parts[1]
			}
			continue
		}

		if !inLease {
			continue
		}

		if line == "}" {
			// End lease block
			if ip != "" && hostname != "" && mac != "" {
				// Only active leases (ends > now or "never")
				if never || !endsSet || ends.After(now) {
					lease := Lease{
						MAC:      mac,
						IP:       ip,
						Hostname: hostname,
						Expiry:   ends,
					}
					// For duplicates: prefer newer lease
					if existing, ok := leaseMap[ip]; ok {
						if lease.Expiry.After(existing.Expiry) {
							leaseMap[ip] = lease
						}
					} else {
						leaseMap[ip] = lease
					}
				}
			}
			resetLease()
			continue
		}

		// Parse fields
		line = strings.TrimSuffix(line, ";")

		if strings.HasPrefix(line, "hardware ethernet ") {
			mac = strings.TrimPrefix(line, "hardware ethernet ")
			mac = strings.TrimSpace(mac)
		} else if strings.HasPrefix(line, "client-hostname ") {
			hostname = strings.TrimPrefix(line, "client-hostname ")
			hostname = strings.Trim(hostname, "\"")
		} else if strings.HasPrefix(line, "ends ") {
			parts := strings.Fields(line)
			// "ends <weekday> <date> <time>" oder "ends never"
			if len(parts) >= 2 && parts[1] == "never" {
				never = true
				endsSet = true
			} else if len(parts) >= 4 {
				t, err := time.Parse(dhcpdTimeLayout, parts[2]+" "+parts[3])
				if err == nil {
					ends = t
					endsSet = true
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("dhcpd: read %s: %w", p.Path, err)
	}

	leases := make([]Lease, 0, len(leaseMap))
	for _, l := range leaseMap {
		leases = append(leases, l)
	}

	return leases, nil
}
