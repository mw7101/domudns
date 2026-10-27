package dnsserver

import (
	"testing"

	dnsinternal "github.com/mw7101/domudns/internal/dns"
	mdns "github.com/miekg/dns"
)

// makeZone is a helper constructor for tests.
func makeZone(domain, view, ip string) *dnsinternal.Zone {
	return &dnsinternal.Zone{
		Domain: domain,
		View:   view,
		TTL:    300,
		Records: []dnsinternal.Record{
			{ID: 1, Name: "@", Type: dnsinternal.TypeA, TTL: 300, Value: ip},
		},
	}
}

// loadZonesManually fills the ZoneManager directly (without Store).
func loadZonesManually(zm *ZoneManager, zones ...*dnsinternal.Zone) {
	zm.mu.Lock()
	defer zm.mu.Unlock()
	zm.zones = make(map[string]*dnsinternal.Zone)
	zm.viewZones = make(map[string]map[string]*dnsinternal.Zone)
	for _, z := range zones {
		if z.View != "" {
			if zm.viewZones[z.Domain] == nil {
				zm.viewZones[z.Domain] = make(map[string]*dnsinternal.Zone)
			}
			zm.viewZones[z.Domain][z.View] = z
		} else {
			zm.zones[z.Domain] = z
		}
	}
}

func TestZoneManager_FindZone_DefaultOnly(t *testing.T) {
	zm := NewZoneManager()
	loadZonesManually(zm, makeZone("example.com", "", "1.2.3.4"))

	zone, subdomain := zm.FindZone("", "example.com.")
	if zone == nil {
		t.Fatal("erwartet Default-Zone, got nil")
	}
	if subdomain != "@" {
		t.Errorf("subdomain = %q, want \"@\"", subdomain)
	}
	if zone.Records[0].Value != "1.2.3.4" {
		t.Errorf("wrong IP: %s", zone.Records[0].Value)
	}
}

func TestZoneManager_FindZone_ViewPreferredOverDefault(t *testing.T) {
	zm := NewZoneManager()
	loadZonesManually(zm,
		makeZone("nas.home", "", "10.0.0.1"),
		makeZone("nas.home", "internal", "192.168.1.100"),
	)

	// Interner Client → View-Zone
	zone, _ := zm.FindZone("internal", "nas.home.")
	if zone == nil {
		t.Fatal("erwartet View-Zone, got nil")
	}
	if zone.Records[0].Value != "192.168.1.100" {
		t.Errorf("View-Zone: wrong IP %s, want 192.168.1.100", zone.Records[0].Value)
	}

	// Kein View → Default-Zone
	zone, _ = zm.FindZone("", "nas.home.")
	if zone == nil {
		t.Fatal("erwartet Default-Zone, got nil")
	}
	if zone.Records[0].Value != "10.0.0.1" {
		t.Errorf("Default-Zone: wrong IP %s, want 10.0.0.1", zone.Records[0].Value)
	}
}

func TestZoneManager_FindZone_DefaultFallback(t *testing.T) {
	zm := NewZoneManager()
	// Nur Default-Zone, kein View "external"
	loadZonesManually(zm, makeZone("nas.home", "", "10.0.0.1"))

	// Client hat View "external", aber keine View-Zone → Fallback auf Default
	zone, _ := zm.FindZone("external", "nas.home.")
	if zone == nil {
		t.Fatal("erwartet Default-Fallback, got nil")
	}
	if zone.Records[0].Value != "10.0.0.1" {
		t.Errorf("Default-Fallback: wrong IP %s, want 10.0.0.1", zone.Records[0].Value)
	}
}

func TestZoneManager_FindZone_NoMatch(t *testing.T) {
	zm := NewZoneManager()
	loadZonesManually(zm, makeZone("nas.home", "internal", "192.168.1.100"))

	// Kein View, keine Default-Zone → nil
	zone, subdomain := zm.FindZone("", "nas.home.")
	if zone != nil {
		t.Errorf("erwartet nil, got zone mit View=%q", zone.View)
	}
	if subdomain != "" {
		t.Errorf("subdomain = %q, want \"\"", subdomain)
	}
}

func TestZoneManager_FindZone_SubdomainInViewZone(t *testing.T) {
	zm := NewZoneManager()
	zone := &dnsinternal.Zone{
		Domain: "example.com",
		View:   "internal",
		TTL:    300,
		Records: []dnsinternal.Record{
			{ID: 1, Name: "www", Type: dnsinternal.TypeA, TTL: 300, Value: "192.168.1.200"},
		},
	}
	loadZonesManually(zm, zone)

	z, sub := zm.FindZone("internal", "www.example.com.")
	if z == nil {
		t.Fatal("erwartet View-Zone für www.example.com, got nil")
	}
	if sub != "www" {
		t.Errorf("subdomain = %q, want \"www\"", sub)
	}
}

func TestGenerateResponse_TTLOverride_Applied(t *testing.T) {
	zm := NewZoneManager()
	zone := makeZone("example.com", "", "1.2.3.4")
	zone.TTLOverride = 120
	zone.Records[0].TTL = 3600 // Record-TTL soll ignoriert werden
	loadZonesManually(zm, zone)

	req := new(mdns.Msg)
	req.SetQuestion("example.com.", mdns.TypeA)
	resp := zm.GenerateResponse(req, zone, "@")
	if len(resp.Answer) == 0 {
		t.Fatal("erwartet Antwort, got keine")
	}
	if got := resp.Answer[0].Header().Ttl; got != 120 {
		t.Errorf("TTL = %d, want 120 (ttl_override)", got)
	}
}

func TestGenerateResponse_TTLOverride_Zero_UsesRecordTTL(t *testing.T) {
	zm := NewZoneManager()
	zone := makeZone("example.com", "", "1.2.3.4")
	zone.TTLOverride = 0 // kein Override
	zone.Records[0].TTL = 600
	loadZonesManually(zm, zone)

	req := new(mdns.Msg)
	req.SetQuestion("example.com.", mdns.TypeA)
	resp := zm.GenerateResponse(req, zone, "@")
	if len(resp.Answer) == 0 {
		t.Fatal("erwartet Antwort, got keine")
	}
	if got := resp.Answer[0].Header().Ttl; got != 600 {
		t.Errorf("TTL = %d, want 600 (Record-TTL, kein Override)", got)
	}
}

func TestGenerateResponse_TTLOverride_SOA_NotAffected(t *testing.T) {
	zm := NewZoneManager()
	zone := &dnsinternal.Zone{
		Domain:      "example.com",
		TTL:         3600,
		TTLOverride: 120, // Override gesetzt
		Records: []dnsinternal.Record{
			{ID: 1, Name: "@", Type: dnsinternal.TypeSOA, TTL: 3600,
				Value: "ns1.example.com. hostmaster.example.com. 2024010100 3600 1800 604800 300"},
		},
	}
	loadZonesManually(zm, zone)

	req := new(mdns.Msg)
	req.SetQuestion("example.com.", mdns.TypeSOA)
	resp := zm.GenerateResponse(req, zone, "@")
	if len(resp.Answer) == 0 {
		t.Fatal("erwartet SOA Antwort, got keine")
	}
	// SOA TTL must NOT be overridden by override
	if got := resp.Answer[0].Header().Ttl; got != 3600 {
		t.Errorf("SOA TTL = %d, want 3600 (SOA soll vom Override ausgenommen sein)", got)
	}
}

func TestZoneManager_Stats(t *testing.T) {
	zm := NewZoneManager()
	loadZonesManually(zm,
		makeZone("a.com", "", "1.1.1.1"),
		makeZone("b.com", "", "2.2.2.2"),
		makeZone("b.com", "internal", "192.168.0.1"),
		makeZone("c.com", "external", "3.3.3.3"),
	)

	def, view := zm.Stats()
	if def != 2 {
		t.Errorf("default zones = %d, want 2", def)
	}
	if view != 2 {
		t.Errorf("view zones = %d, want 2", view)
	}
}
