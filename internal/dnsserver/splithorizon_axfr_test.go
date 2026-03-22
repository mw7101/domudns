// internal/dnsserver/splithorizon_axfr_test.go
package dnsserver

import (
	"testing"
)

// TestZoneManager_ViewAware verifies that FindZone correctly isolates
// view-specific zones: only clients assigned to the matching view can
// find the zone; clients with a different view or no view cannot.
func TestZoneManager_ViewAware(t *testing.T) {
	zm := NewZoneManager()

	// Load a zone that is only visible to the "office" view (no default zone).
	loadZonesManually(zm, makeZone("internal.example.com", "office", "10.10.0.1"))

	// 1. A client with view "office" must find the zone.
	zone, subdomain := zm.FindZone("office", "internal.example.com.")
	if zone == nil {
		t.Fatal("office client: expected zone, got nil")
	}
	if subdomain != "@" {
		t.Errorf("office client: subdomain = %q, want \"@\"", subdomain)
	}
	if zone.View != "office" {
		t.Errorf("office client: zone.View = %q, want \"office\"", zone.View)
	}

	// 2. A client with view "home" must NOT find the zone (wrong view, no default).
	zone, _ = zm.FindZone("home", "internal.example.com.")
	if zone != nil {
		t.Errorf("home client: expected nil, got zone with View=%q", zone.View)
	}

	// 3. A client with no view must NOT find the zone (view-only, no default zone).
	zone, _ = zm.FindZone("", "internal.example.com.")
	if zone != nil {
		t.Errorf("default (no-view) client: expected nil, got zone with View=%q", zone.View)
	}
}
