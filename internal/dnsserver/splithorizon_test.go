package dnsserver

import (
	"net"
	"testing"
)

func parseCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ungültiges CIDR %q: %v", s, err)
	}
	return ipNet
}

func TestSplitHorizonResolver_Disabled(t *testing.T) {
	r := NewSplitHorizonResolver(false, []SplitHorizonView{
		{Name: "internal", Subnets: []*net.IPNet{parseCIDR(t, "192.168.0.0/16")}},
	})
	// Deaktiviert → immer ""
	ip := net.ParseIP("192.168.1.50")
	if got := r.GetView(ip); got != "" {
		t.Errorf("disabled: want \"\", got %q", got)
	}
}

func TestSplitHorizonResolver_CIDRMatch(t *testing.T) {
	r := NewSplitHorizonResolver(true, []SplitHorizonView{
		{Name: "internal", Subnets: []*net.IPNet{
			parseCIDR(t, "192.168.0.0/16"),
			parseCIDR(t, "10.0.0.0/8"),
		}},
	})

	tests := []struct {
		ip   string
		want string
	}{
		{"192.168.1.100", "internal"},
		{"192.168.0.1", "internal"},
		{"10.0.0.1", "internal"},
		{"8.8.8.8", ""},
		{"172.16.0.1", ""},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		got := r.GetView(ip)
		if got != tt.want {
			t.Errorf("ip=%s: want %q, got %q", tt.ip, tt.want, got)
		}
	}
}

func TestSplitHorizonResolver_CatchAll(t *testing.T) {
	// catch-all view (empty subnets list)
	r := NewSplitHorizonResolver(true, []SplitHorizonView{
		{Name: "internal", Subnets: []*net.IPNet{parseCIDR(t, "192.168.0.0/16")}},
		{Name: "external", Subnets: []*net.IPNet{}}, // catch-all
	})

	// LAN → internal
	if got := r.GetView(net.ParseIP("192.168.1.1")); got != "internal" {
		t.Errorf("LAN: want %q, got %q", "internal", got)
	}
	// Extern → catch-all external
	if got := r.GetView(net.ParseIP("1.2.3.4")); got != "external" {
		t.Errorf("extern: want %q, got %q", "external", got)
	}
}

func TestSplitHorizonResolver_FirstMatchWins(t *testing.T) {
	r := NewSplitHorizonResolver(true, []SplitHorizonView{
		{Name: "first", Subnets: []*net.IPNet{parseCIDR(t, "10.0.0.0/8")}},
		{Name: "second", Subnets: []*net.IPNet{parseCIDR(t, "10.1.0.0/16")}},
	})
	// 10.1.2.3 passt zu beiden, aber first gewinnt
	if got := r.GetView(net.ParseIP("10.1.2.3")); got != "first" {
		t.Errorf("first-match: want %q, got %q", "first", got)
	}
}

func TestSplitHorizonResolver_NilIP(t *testing.T) {
	r := NewSplitHorizonResolver(true, []SplitHorizonView{
		{Name: "internal", Subnets: []*net.IPNet{parseCIDR(t, "192.168.0.0/16")}},
	})
	if got := r.GetView(nil); got != "" {
		t.Errorf("nil IP: want \"\", got %q", got)
	}
}

func TestSplitHorizonResolver_AtomicUpdate(t *testing.T) {
	r := NewSplitHorizonResolver(true, []SplitHorizonView{
		{Name: "v1", Subnets: []*net.IPNet{parseCIDR(t, "192.168.0.0/16")}},
	})

	if got := r.GetView(net.ParseIP("192.168.1.1")); got != "v1" {
		t.Fatalf("before update: want %q, got %q", "v1", got)
	}

	// Konfiguration atomar aktualisieren
	r.Update(true, []SplitHorizonView{
		{Name: "v2", Subnets: []*net.IPNet{parseCIDR(t, "192.168.0.0/16")}},
	})

	if got := r.GetView(net.ParseIP("192.168.1.1")); got != "v2" {
		t.Errorf("after update: want %q, got %q", "v2", got)
	}
}
