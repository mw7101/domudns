package dhcp

import (
	"context"
	"sync"
	"testing"

	"github.com/mw7101/domudns/internal/dns"
)

// ─── Mocks ───────────────────────────────────────────────────────────────────

type mockParser struct {
	leases []Lease
	err    error
}

func (m *mockParser) Parse(_ context.Context) ([]Lease, error) {
	return m.leases, m.err
}

type mockStore struct {
	mu     sync.Mutex
	zones  map[string]*dns.Zone
	nextID int
}

func newMockStore() *mockStore {
	return &mockStore{
		zones:  make(map[string]*dns.Zone),
		nextID: 1,
	}
}

func (s *mockStore) GetZone(_ context.Context, domain string) (*dns.Zone, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	z, ok := s.zones[domain]
	if !ok {
		return nil, dns.ErrZoneNotFound
	}
	return z, nil
}

func (s *mockStore) PutZone(_ context.Context, zone *dns.Zone) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.zones[zone.Domain]; ok {
		existing.TTL = zone.TTL
		return nil
	}
	z := *zone
	z.Records = make([]dns.Record, 0)
	s.zones[zone.Domain] = &z
	return nil
}

func (s *mockStore) GetRecords(_ context.Context, zoneDomain string) ([]dns.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	z, ok := s.zones[zoneDomain]
	if !ok {
		return nil, dns.ErrZoneNotFound
	}
	return z.Records, nil
}

func (s *mockStore) PutRecord(_ context.Context, zoneDomain string, record *dns.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	z, ok := s.zones[zoneDomain]
	if !ok {
		return dns.ErrZoneNotFound
	}
	record.ID = s.nextID
	s.nextID++
	z.Records = append(z.Records, *record)
	return nil
}

func (s *mockStore) DeleteRecord(_ context.Context, zoneDomain string, recordID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	z, ok := s.zones[zoneDomain]
	if !ok {
		return dns.ErrZoneNotFound
	}
	for i, r := range z.Records {
		if r.ID == recordID {
			z.Records = append(z.Records[:i], z.Records[i+1:]...)
			return nil
		}
	}
	return dns.ErrRecordNotFound
}

// ─── Tests ───────────────────────────────────────────────────────────────────

func TestSyncManager_SyncOnce_NewLeases(t *testing.T) {
	store := newMockStore()
	parser := &mockParser{
		leases: []Lease{
			{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.100.10", Hostname: "laptop"},
			{MAC: "aa:bb:cc:dd:ee:02", IP: "192.168.100.11", Hostname: "server"},
		},
	}

	reloaded := false
	sm, err := NewSyncManager(SyncManagerConfig{
		Parser:       parser,
		Store:        store,
		Zone:         "home.lan",
		TTL:          60,
		AutoCreate:   true,
		ZoneReloader: func() { reloaded = true },
		DataDir:      t.TempDir(),
		Source:       "dnsmasq",
	})
	if err != nil {
		t.Fatal(err)
	}

	sm.syncOnce(context.Background())

	// Verify: forward zone created
	fwdZone, err := store.GetZone(context.Background(), "home.lan")
	if err != nil {
		t.Fatalf("Forward-Zone nicht erstellt: %v", err)
	}
	if len(fwdZone.Records) != 2 {
		t.Errorf("erwartet 2 A-Records, bekommen %d", len(fwdZone.Records))
	}

	// Verify: reverse zone created
	revZone, err := store.GetZone(context.Background(), "100.168.192.in-addr.arpa")
	if err != nil {
		t.Fatalf("Reverse-Zone nicht erstellt: %v", err)
	}
	if len(revZone.Records) != 2 {
		t.Errorf("erwartet 2 PTR-Records, bekommen %d", len(revZone.Records))
	}

	// Verify: zone reload invoked
	if !reloaded {
		t.Error("zoneReloader wurde nicht aufgerufen")
	}

	// Verify: status
	status := sm.GetStatus()
	if status.LeaseCount != 2 {
		t.Errorf("erwartet LeaseCount=2, bekommen %d", status.LeaseCount)
	}
}

func TestSyncManager_SyncOnce_DeletedLeases(t *testing.T) {
	store := newMockStore()
	parser := &mockParser{
		leases: []Lease{
			{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.100.10", Hostname: "laptop"},
		},
	}

	sm, err := NewSyncManager(SyncManagerConfig{
		Parser:     parser,
		Store:      store,
		Zone:       "home.lan",
		TTL:        60,
		AutoCreate: true,
		DataDir:    t.TempDir(),
		Source:     "dnsmasq",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Erster Sync: laptop erstellen
	sm.syncOnce(context.Background())

	leases := sm.GetLeases()
	if len(leases) != 1 {
		t.Fatalf("erwartet 1 Lease nach erstem Sync, bekommen %d", len(leases))
	}

	// Zweiter Sync: kein Lease mehr → laptop loeschen
	parser.leases = nil
	sm.syncOnce(context.Background())

	leases = sm.GetLeases()
	if len(leases) != 0 {
		t.Errorf("erwartet 0 Leases nach Loeschung, bekommen %d", len(leases))
	}

	// Verify: records deleted
	fwdZone, _ := store.GetZone(context.Background(), "home.lan")
	if len(fwdZone.Records) != 0 {
		t.Errorf("erwartet 0 A-Records nach Loeschung, bekommen %d", len(fwdZone.Records))
	}
}

func TestSyncManager_SyncOnce_HostnameChanged(t *testing.T) {
	store := newMockStore()
	parser := &mockParser{
		leases: []Lease{
			{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.100.10", Hostname: "laptop"},
		},
	}

	sm, err := NewSyncManager(SyncManagerConfig{
		Parser:     parser,
		Store:      store,
		Zone:       "home.lan",
		TTL:        60,
		AutoCreate: true,
		DataDir:    t.TempDir(),
		Source:     "dnsmasq",
	})
	if err != nil {
		t.Fatal(err)
	}

	sm.syncOnce(context.Background())

	// Hostname aendern
	parser.leases = []Lease{
		{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.100.10", Hostname: "desktop"},
	}
	sm.syncOnce(context.Background())

	leases := sm.GetLeases()
	if len(leases) != 1 {
		t.Fatalf("erwartet 1 Lease, bekommen %d", len(leases))
	}
	if leases[0].Hostname != "desktop" {
		t.Errorf("erwartet Hostname=desktop, bekommen %s", leases[0].Hostname)
	}

	// Alter Record soll weg sein, neuer da
	fwdZone, _ := store.GetZone(context.Background(), "home.lan")
	if len(fwdZone.Records) != 1 {
		t.Errorf("erwartet 1 A-Record (nach Umbenennung), bekommen %d", len(fwdZone.Records))
	}
	if fwdZone.Records[0].Name != "desktop" {
		t.Errorf("erwartet Record-Name=desktop, bekommen %s", fwdZone.Records[0].Name)
	}
}

func TestSyncManager_SanitizesHostnames(t *testing.T) {
	store := newMockStore()
	parser := &mockParser{
		leases: []Lease{
			{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.100.10", Hostname: "My Laptop!"},
			{MAC: "aa:bb:cc:dd:ee:02", IP: "192.168.100.11", Hostname: "*"},
		},
	}

	sm, err := NewSyncManager(SyncManagerConfig{
		Parser:     parser,
		Store:      store,
		Zone:       "home.lan",
		TTL:        60,
		AutoCreate: true,
		DataDir:    t.TempDir(),
		Source:     "dnsmasq",
	})
	if err != nil {
		t.Fatal(err)
	}

	sm.syncOnce(context.Background())

	leases := sm.GetLeases()
	// "*" is skipped → only 1 lease
	if len(leases) != 1 {
		t.Fatalf("erwartet 1 Lease (Stern uebersprungen), bekommen %d", len(leases))
	}
	if leases[0].Hostname != "my-laptop" {
		t.Errorf("erwartet sanitisierten Hostname 'my-laptop', bekommen '%s'", leases[0].Hostname)
	}
}

func TestAutoReverseZone(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"192.168.100.42", "100.168.192.in-addr.arpa"},
		{"10.0.0.1", "0.0.10.in-addr.arpa"},
		{"172.16.5.100", "5.16.172.in-addr.arpa"},
		{"invalid", ""},
		{"::1", "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"}, // IPv6 jetzt unterstuetzt
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := AutoReverseZone(tt.ip)
			if got != tt.want {
				t.Errorf("autoReverseZone(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestPTRName(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"192.168.100.42", "42"},
		{"10.0.0.1", "1"},
		{"invalid", ""},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := PTRName(tt.ip, "x.in-addr.arpa")
			if got != tt.want {
				t.Errorf("ptrName(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestSyncManager_AutoCreateDisabled(t *testing.T) {
	store := newMockStore()
	parser := &mockParser{
		leases: []Lease{
			{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.100.10", Hostname: "laptop"},
		},
	}

	sm, err := NewSyncManager(SyncManagerConfig{
		Parser:     parser,
		Store:      store,
		Zone:       "home.lan",
		TTL:        60,
		AutoCreate: false, // Zone must already exist
		DataDir:    t.TempDir(),
		Source:     "dnsmasq",
	})
	if err != nil {
		t.Fatal(err)
	}

	sm.syncOnce(context.Background())

	// Status sollte Fehler anzeigen (Zone nicht vorhanden, auto_create_zone: false)
	status := sm.GetStatus()
	if status.LastError == "" {
		t.Error("erwartet Fehler wenn Zone fehlt und AutoCreate deaktiviert")
	}
}
