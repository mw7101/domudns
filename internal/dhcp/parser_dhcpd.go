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

// dhcpdLeaseState accumulates fields for the lease block currently being
// parsed (between a "lease <ip> {" line and its closing "}").
type dhcpdLeaseState struct {
	active   bool
	ip       string
	mac      string
	hostname string
	ends     time.Time
	endsSet  bool
	never    bool
}

func (s *dhcpdLeaseState) reset() {
	*s = dhcpdLeaseState{}
}

// isActive reports whether the lease hasn't expired: explicit "never", no
// end time seen at all, or an end time still in the future.
func (s *dhcpdLeaseState) isActive(now time.Time) bool {
	return s.never || !s.endsSet || s.ends.After(now)
}

// toLease converts the accumulated fields to a Lease, or reports ok=false
// if a required field (ip, hostname, mac) is missing.
func (s *dhcpdLeaseState) toLease() (Lease, bool) {
	if s.ip == "" || s.hostname == "" || s.mac == "" {
		return Lease{}, false
	}
	return Lease{MAC: s.mac, IP: s.ip, Hostname: s.hostname, Expiry: s.ends}, true
}

// applyField parses one "key value;" line inside a lease block.
func (s *dhcpdLeaseState) applyField(line string) {
	switch {
	case strings.HasPrefix(line, "hardware ethernet "):
		s.mac = strings.TrimSpace(strings.TrimPrefix(line, "hardware ethernet "))
	case strings.HasPrefix(line, "client-hostname "):
		s.hostname = strings.Trim(strings.TrimPrefix(line, "client-hostname "), "\"")
	case strings.HasPrefix(line, "ends "):
		s.applyEnds(line)
	}
}

// applyEnds parses "ends <weekday> <date> <time>" or "ends never".
func (s *dhcpdLeaseState) applyEnds(line string) {
	parts := strings.Fields(line)
	if len(parts) >= 2 && parts[1] == "never" {
		s.never = true
		s.endsSet = true
		return
	}
	if len(parts) >= 4 {
		if t, err := time.Parse(dhcpdTimeLayout, parts[2]+" "+parts[3]); err == nil {
			s.ends = t
			s.endsSet = true
		}
	}
}

// dhcpdLeaseIP extracts the IP from a "lease <ip> {" line, or ok=false if
// the line doesn't have the expected two fields.
func dhcpdLeaseIP(line string) (ip string, ok bool) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", false
	}
	return parts[1], true
}

// addActiveLease finalizes state's lease block: if it's complete (all
// required fields present) and active, add it to leaseMap, keeping the
// newer of two leases seen for the same IP.
func addActiveLease(leaseMap map[string]Lease, state *dhcpdLeaseState, now time.Time) {
	lease, ok := state.toLease()
	if !ok || !state.isActive(now) {
		return
	}
	if existing, exists := leaseMap[lease.IP]; !exists || lease.Expiry.After(existing.Expiry) {
		leaseMap[lease.IP] = lease
	}
}

// Parse reads all active leases from the dhcpd.leases file.
// For duplicates (same IP), the newest entry is taken.
func (p *DhcpdParser) Parse(_ context.Context) ([]Lease, error) {
	f, err := os.Open(p.Path)
	if err != nil {
		return nil, fmt.Errorf("dhcpd: open %s: %w", p.Path, err)
	}
	defer func() { _ = f.Close() }()

	now := time.Now()
	leaseMap := make(map[string]Lease) // dedup: same IP -> newest lease
	var state dhcpdLeaseState

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "lease ") && strings.HasSuffix(line, "{") {
			// New lease block: "lease 192.168.1.10 {"
			if ip, ok := dhcpdLeaseIP(line); ok {
				state.reset()
				state.active = true
				state.ip = ip
			}
			continue
		}

		if !state.active {
			continue
		}

		if line == "}" {
			addActiveLease(leaseMap, &state, now)
			state.reset()
			continue
		}

		state.applyField(strings.TrimSuffix(line, ";"))
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
