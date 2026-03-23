package dns

import (
	"testing"
)

func TestReverseZoneForIP(t *testing.T) {
	tests := []struct {
		ip   string
		zone string
		ok   bool
	}{
		// IPv4
		{"192.168.1.42", "1.168.192.in-addr.arpa", true},
		{"10.0.0.1", "0.0.10.in-addr.arpa", true},
		{"192.168.50.100", "50.168.192.in-addr.arpa", true},
		{"127.0.0.1", "0.0.127.in-addr.arpa", true},
		// IPv6
		{"2001:db8::1", "0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", true},
		{"fe80::1", "0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa", true},
		{"::1", "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", true},
		// Invalid
		{"", "", false},
		{"invalid", "", false},
		{"not.an.ip", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.ip, func(t *testing.T) {
			got, ok := ReverseZoneForIP(tc.ip)
			if ok != tc.ok {
				t.Errorf("ReverseZoneForIP(%q): ok=%v want %v", tc.ip, ok, tc.ok)
			}
			if got != tc.zone {
				t.Errorf("ReverseZoneForIP(%q): zone=%q want %q", tc.ip, got, tc.zone)
			}
		})
	}
}

func TestPTRNameForIP(t *testing.T) {
	tests := []struct {
		ip   string
		name string
	}{
		// IPv4
		{"192.168.1.42", "42"},
		{"10.0.0.1", "1"},
		{"192.168.50.100", "100"},
		// IPv6
		{"2001:db8::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0"},
		{"fe80::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0"},
		{"::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0"},
		{"2001:db8::abcd", "d.c.b.a.0.0.0.0.0.0.0.0.0.0.0.0"},
		// Invalid
		{"", ""},
		{"invalid", ""},
	}
	for _, tc := range tests {
		t.Run(tc.ip, func(t *testing.T) {
			got := PTRNameForIP(tc.ip)
			if got != tc.name {
				t.Errorf("PTRNameForIP(%q): %q want %q", tc.ip, got, tc.name)
			}
		})
	}
}

func TestReverseCombined(t *testing.T) {
	// Verify zone + PTR name form a correct ARPA FQDN
	tests := []struct {
		ip   string
		fqdn string
	}{
		{"192.168.1.42", "42.1.168.192.in-addr.arpa"},
		{"2001:db8::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"},
	}
	for _, tc := range tests {
		t.Run(tc.ip, func(t *testing.T) {
			zone, ok := ReverseZoneForIP(tc.ip)
			if !ok {
				t.Fatalf("ReverseZoneForIP(%q) failed", tc.ip)
			}
			name := PTRNameForIP(tc.ip)
			got := name + "." + zone
			if got != tc.fqdn {
				t.Errorf("combined ARPA for %q: %q want %q", tc.ip, got, tc.fqdn)
			}
		})
	}
}
