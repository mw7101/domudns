package filestore

import (
	"context"
	"testing"

	"github.com/mw7101/domudns/internal/dns"
)

func TestIsValidViewName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid simple", "internal", true},
		{"valid with hyphen", "my-view", true},
		{"valid with underscore", "my_view", true},
		{"valid alphanumeric", "view1", true},
		{"empty", "", false},
		{"too long", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false}, // 65 chars
		{"uppercase", "Internal", false},
		{"with dot", "my.view", false},
		{"with at", "my@view", false},
		{"with space", "my view", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidViewName(tt.input); got != tt.want {
				t.Errorf("isValidViewName(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestSanitizeZoneFilename(t *testing.T) {
	tests := []struct {
		domain  string
		view    string
		want    string
		wantErr bool
	}{
		{"example.com", "", "example.com", false},
		{"example.com", "internal", "example.com@internal", false},
		{"nas.home", "my-view", "nas.home@my-view", false},
		{"invalid!", "", "", true},
		{"example.com", "Invalid!", "", true},
		{"example.com", "", "example.com", false},
	}
	for _, tt := range tests {
		got, err := sanitizeZoneFilename(tt.domain, tt.view)
		if (err != nil) != tt.wantErr {
			t.Errorf("sanitizeZoneFilename(%q, %q) err=%v, wantErr=%v", tt.domain, tt.view, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("sanitizeZoneFilename(%q, %q) = %q, want %q", tt.domain, tt.view, got, tt.want)
		}
	}
}

func TestSplitZoneKey(t *testing.T) {
	tests := []struct {
		key        string
		wantDomain string
		wantView   string
	}{
		{"example.com", "example.com", ""},
		{"nas.home@internal", "nas.home", "internal"},
		{"a.b.c@my-view", "a.b.c", "my-view"},
	}
	for _, tt := range tests {
		d, v := splitZoneKey(tt.key)
		if d != tt.wantDomain || v != tt.wantView {
			t.Errorf("splitZoneKey(%q) = (%q, %q), want (%q, %q)", tt.key, d, v, tt.wantDomain, tt.wantView)
		}
	}
}

func TestFileStore_ViewZones(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Create default zone
	defaultZone := &dns.Zone{
		Domain: "nas.home",
		TTL:    300,
		Records: []dns.Record{
			{ID: 1, Name: "@", Type: dns.TypeA, TTL: 300, Value: "10.0.0.1"},
		},
	}
	if err := store.PutZone(ctx, defaultZone); err != nil {
		t.Fatal(err)
	}

	// Create view zone
	viewZone := &dns.Zone{
		Domain: "nas.home",
		View:   "internal",
		TTL:    300,
		Records: []dns.Record{
			{ID: 1, Name: "@", Type: dns.TypeA, TTL: 300, Value: "192.168.1.100"},
		},
	}
	if err := store.PutZone(ctx, viewZone); err != nil {
		t.Fatal(err)
	}

	// ListZones must return both
	zones, err := store.ListZones(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 2 {
		t.Fatalf("ListZones: got %d zones, want 2", len(zones))
	}

	// GetZone returns default
	z, err := store.GetZone(ctx, "nas.home")
	if err != nil {
		t.Fatal(err)
	}
	if z.View != "" || z.Records[0].Value != "10.0.0.1" {
		t.Errorf("GetZone: want default zone, got view=%q value=%q", z.View, z.Records[0].Value)
	}

	// GetZoneView returns view zone
	vz, err := store.GetZoneView(ctx, "nas.home", "internal")
	if err != nil {
		t.Fatal(err)
	}
	if vz.View != "internal" || vz.Records[0].Value != "192.168.1.100" {
		t.Errorf("GetZoneView: want view=internal value=192.168.1.100, got view=%q value=%q",
			vz.View, vz.Records[0].Value)
	}

	// DeleteZoneView deletes only the view zone
	if err := store.DeleteZoneView(ctx, "nas.home", "internal"); err != nil {
		t.Fatal(err)
	}

	zones, _ = store.ListZones(ctx)
	if len(zones) != 1 {
		t.Errorf("after DeleteZoneView: got %d zones, want 1", len(zones))
	}

	// Default zone still present
	z, err = store.GetZone(ctx, "nas.home")
	if err != nil || z == nil {
		t.Errorf("default zone disappeared after DeleteZoneView: err=%v", err)
	}

	// GetZoneView for deleted view returns error
	_, err = store.GetZoneView(ctx, "nas.home", "internal")
	if err != dns.ErrZoneNotFound {
		t.Errorf("GetZoneView nach Delete: want ErrZoneNotFound, got %v", err)
	}
}

func TestFileStore_PutRecordInViewZone(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Create view zone
	viewZone := &dns.Zone{
		Domain: "nas.home",
		View:   "internal",
		TTL:    300,
	}
	if err := store.PutZone(ctx, viewZone); err != nil {
		t.Fatal(err)
	}

	// Add record via compound key "nas.home@internal"
	record := &dns.Record{Name: "@", Type: dns.TypeA, TTL: 300, Value: "192.168.1.100"}
	if err := store.PutRecord(ctx, "nas.home@internal", record); err != nil {
		t.Fatal(err)
	}

	// Read record from view zone
	records, err := store.GetRecords(ctx, "nas.home@internal")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Value != "192.168.1.100" {
		t.Errorf("PutRecord in view zone: got %+v", records)
	}

	// Default zone untouched (should not exist)
	_, err = store.GetZone(ctx, "nas.home")
	if err != dns.ErrZoneNotFound {
		t.Errorf("Default zone should not exist, got err=%v", err)
	}
}
