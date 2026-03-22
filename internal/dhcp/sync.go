package dhcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mw7101/domudns/internal/dns"
	"github.com/rs/zerolog/log"
)

// DHCPStore definiert die Store-Operationen die der SyncManager benoetigt.
type DHCPStore interface {
	GetZone(ctx context.Context, domain string) (*dns.Zone, error)
	PutZone(ctx context.Context, zone *dns.Zone) error
	GetRecords(ctx context.Context, zoneDomain string) ([]dns.Record, error)
	PutRecord(ctx context.Context, zoneDomain string, record *dns.Record) error
	DeleteRecord(ctx context.Context, zoneDomain string, recordID int) error
}

// SyncManagerConfig enthaelt die Konfiguration fuer den SyncManager.
type SyncManagerConfig struct {
	Parser       LeaseParser
	Store        DHCPStore
	Zone         string // Forward-Zone (z.B. "home.lan")
	ReverseZone  string // Reverse-Zone (z.B. "100.168.192.in-addr.arpa"), leer = auto
	TTL          int
	AutoCreate   bool
	ZoneReloader func()
	DataDir      string // directory for dhcp_leases.json
	Source       string // "dnsmasq", "dhcpd", "fritzbox" (for status)
}

// SyncManager synchronizes DHCP leases with DNS records.
type SyncManager struct {
	parser       LeaseParser
	store        DHCPStore
	zone         string
	reverseZone  string
	ttl          int
	autoCreate   bool
	zoneReloader func()
	statePath    string
	source       string

	mu     sync.Mutex
	state  map[string]*TrackedLease // Key: IP
	status SyncStatus
}

// NewSyncManager creates a new SyncManager.
func NewSyncManager(cfg SyncManagerConfig) (*SyncManager, error) {
	if cfg.Zone == "" {
		return nil, fmt.Errorf("dhcp sync: zone ist Pflicht")
	}

	statePath := filepath.Join(cfg.DataDir, "dhcp_leases.json")

	sm := &SyncManager{
		parser:       cfg.Parser,
		store:        cfg.Store,
		zone:         cfg.Zone,
		reverseZone:  cfg.ReverseZone,
		ttl:          cfg.TTL,
		autoCreate:   cfg.AutoCreate,
		zoneReloader: cfg.ZoneReloader,
		statePath:    statePath,
		source:       cfg.Source,
		state:        make(map[string]*TrackedLease),
		status: SyncStatus{
			Enabled: true,
			Source:  cfg.Source,
		},
	}

	// Load existing state
	sm.loadState()

	return sm, nil
}

// Run starts the sync loop (blocks until ctx is cancelled).
func (sm *SyncManager) Run(ctx context.Context, interval time.Duration) error {
	log.Info().
		Str("zone", sm.zone).
		Str("source", sm.source).
		Dur("interval", interval).
		Msg("DHCP-Lease-Sync gestartet")

	// Wait 5s initially
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
	}

	// First synchronization
	sm.syncOnce(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			sm.syncOnce(ctx)
		}
	}
}

// GetStatus returns the current sync status.
func (sm *SyncManager) GetStatus() SyncStatus {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.status
}

// GetLeases returns all currently synchronized leases.
func (sm *SyncManager) GetLeases() []TrackedLease {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	leases := make([]TrackedLease, 0, len(sm.state))
	for _, tl := range sm.state {
		leases = append(leases, *tl)
	}
	return leases
}

func (sm *SyncManager) syncOnce(ctx context.Context) {
	syncCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	leases, err := sm.parser.Parse(syncCtx)
	if err != nil {
		sm.mu.Lock()
		sm.status.LastError = err.Error()
		sm.status.LastSync = time.Now()
		sm.mu.Unlock()
		log.Warn().Err(err).Str("source", sm.source).Msg("dhcp sync: parse fehlgeschlagen")
		return
	}

	// Build new lease map (only with valid hostname)
	newMap := make(map[string]Lease, len(leases))
	for _, l := range leases {
		h := sanitizeHostname(l.Hostname)
		if h == "" {
			continue
		}
		l.Hostname = h
		newMap[l.IP] = l
	}

	sm.mu.Lock()
	oldState := sm.state
	sm.mu.Unlock()

	// Ensure forward zone exists
	if err := sm.ensureZone(syncCtx, sm.zone); err != nil {
		sm.setError(err)
		return
	}

	// Determine and ensure reverse zone
	reverseZone := sm.reverseZone
	if reverseZone == "" && len(newMap) > 0 {
		// Auto-derive from first IP
		for ip := range newMap {
			reverseZone, _ = dns.ReverseZoneForIP(ip)
			break
		}
	}
	if reverseZone != "" {
		if err := sm.ensureZone(syncCtx, reverseZone); err != nil {
			sm.setError(err)
			return
		}
	}

	changed := false

	// Remove deleted leases
	for ip, tracked := range oldState {
		if _, exists := newMap[ip]; !exists {
			sm.deleteTrackedRecords(syncCtx, tracked, reverseZone)
			sm.mu.Lock()
			delete(sm.state, ip)
			sm.mu.Unlock()
			changed = true
		}
	}

	// Process new/changed leases
	for ip, lease := range newMap {
		tracked, exists := oldState[ip]

		if exists && tracked.Hostname == lease.Hostname {
			// No change
			continue
		}

		if exists && tracked.Hostname != lease.Hostname {
			// Hostname changed → delete old records
			sm.deleteTrackedRecords(syncCtx, tracked, reverseZone)
		}

		// Create new records
		newTracked := sm.createRecords(syncCtx, lease, reverseZone)
		if newTracked != nil {
			sm.mu.Lock()
			sm.state[ip] = newTracked
			sm.mu.Unlock()
			changed = true
		}
	}

	// Persist state
	sm.saveState()

	// Reload zone if changes
	if changed && sm.zoneReloader != nil {
		sm.zoneReloader()
		log.Info().
			Int("leases", len(newMap)).
			Str("zone", sm.zone).
			Msg("dhcp sync: Zonen neu geladen")
	}

	// Update status
	sm.mu.Lock()
	sm.status.LastSync = time.Now()
	sm.status.LastError = ""
	sm.status.LeaseCount = len(newMap)
	sm.status.RecordCount = len(sm.state) * 2 // A + PTR
	sm.mu.Unlock()

	log.Debug().
		Int("leases", len(newMap)).
		Int("tracked", len(sm.state)).
		Bool("changed", changed).
		Msg("dhcp sync: Durchlauf abgeschlossen")
}

func (sm *SyncManager) setError(err error) {
	sm.mu.Lock()
	sm.status.LastError = err.Error()
	sm.status.LastSync = time.Now()
	sm.mu.Unlock()
	log.Warn().Err(err).Msg("dhcp sync: Fehler")
}

func (sm *SyncManager) ensureZone(ctx context.Context, domain string) error {
	_, err := sm.store.GetZone(ctx, domain)
	if err == nil {
		return nil
	}

	if !sm.autoCreate {
		return fmt.Errorf("dhcp sync: Zone %q nicht vorhanden (auto_create_zone: false)", domain)
	}

	zone := &dns.Zone{
		Domain: domain,
		TTL:    sm.ttl,
		SOA:    dns.DefaultSOA(domain),
	}

	if err := sm.store.PutZone(ctx, zone); err != nil {
		return fmt.Errorf("dhcp sync: Zone %q erstellen: %w", domain, err)
	}

	log.Info().Str("zone", domain).Msg("dhcp sync: Zone automatisch erstellt")
	return nil
}

func (sm *SyncManager) createRecords(ctx context.Context, lease Lease, reverseZone string) *TrackedLease {
	tracked := &TrackedLease{
		Hostname:  lease.Hostname,
		IP:        lease.IP,
		MAC:       lease.MAC,
		UpdatedAt: time.Now(),
	}

	// Create A record
	aRecord := &dns.Record{
		Name:  lease.Hostname,
		Type:  dns.TypeA,
		TTL:   sm.ttl,
		Value: lease.IP,
	}
	if err := sm.store.PutRecord(ctx, sm.zone, aRecord); err != nil {
		log.Warn().Err(err).
			Str("hostname", lease.Hostname).
			Str("ip", lease.IP).
			Msg("dhcp sync: A-Record erstellen fehlgeschlagen")
		return nil
	}
	tracked.ARecordID = aRecord.ID

	// Create PTR record — compute per-lease reverse zone (supports IPv4 + IPv6)
	ptrZone, ok := dns.ReverseZoneForIP(lease.IP)
	if !ok {
		log.Warn().Str("ip", lease.IP).Msg("dhcp sync: Reverse-Zone fuer IP nicht bestimmbar")
		return tracked
	}
	if err := sm.ensureZone(ctx, ptrZone); err != nil {
		log.Warn().Err(err).Str("zone", ptrZone).Msg("dhcp sync: Reverse-Zone nicht verfuegbar, PTR uebersprungen")
		return tracked
	}
	ptrRecord := &dns.Record{
		Name:  dns.PTRNameForIP(lease.IP),
		Type:  dns.TypePTR,
		TTL:   sm.ttl,
		Value: lease.Hostname + "." + sm.zone,
	}
	if err := sm.store.PutRecord(ctx, ptrZone, ptrRecord); err != nil {
		log.Warn().Err(err).
			Str("hostname", lease.Hostname).
			Str("ip", lease.IP).
			Msg("dhcp sync: PTR-Record erstellen fehlgeschlagen")
	} else {
		tracked.PTRRecordID = ptrRecord.ID
	}

	return tracked
}

func (sm *SyncManager) deleteTrackedRecords(ctx context.Context, tracked *TrackedLease, reverseZone string) {
	if tracked.ARecordID > 0 {
		if err := sm.store.DeleteRecord(ctx, sm.zone, tracked.ARecordID); err != nil {
			log.Debug().Err(err).
				Int("id", tracked.ARecordID).
				Msg("dhcp sync: A-Record loeschen fehlgeschlagen")
		}
	}
	if tracked.PTRRecordID > 0 && reverseZone != "" {
		if err := sm.store.DeleteRecord(ctx, reverseZone, tracked.PTRRecordID); err != nil {
			log.Debug().Err(err).
				Int("id", tracked.PTRRecordID).
				Msg("dhcp sync: PTR-Record loeschen fehlgeschlagen")
		}
	}
}

// loadState loads the persisted state from dhcp_leases.json.
func (sm *SyncManager) loadState() {
	data, err := os.ReadFile(sm.statePath)
	if err != nil {
		return // No state present
	}
	var state map[string]*TrackedLease
	if err := json.Unmarshal(data, &state); err != nil {
		log.Warn().Err(err).Msg("dhcp sync: state laden fehlgeschlagen")
		return
	}
	sm.state = state
}

// saveState persists the state atomically as JSON.
func (sm *SyncManager) saveState() {
	sm.mu.Lock()
	stateCopy := make(map[string]*TrackedLease, len(sm.state))
	for k, v := range sm.state {
		clone := *v
		stateCopy[k] = &clone
	}
	sm.mu.Unlock()

	dir := filepath.Dir(sm.statePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Warn().Err(err).Msg("dhcp sync: state-dir erstellen fehlgeschlagen")
		return
	}

	tmp, err := os.CreateTemp(dir, ".dhcp-state-")
	if err != nil {
		log.Warn().Err(err).Msg("dhcp sync: state temp-file fehlgeschlagen")
		return
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if _, err := os.Stat(tmpPath); err == nil {
			_ = os.Remove(tmpPath)
		}
	}()

	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(stateCopy); err != nil {
		log.Warn().Err(err).Msg("dhcp sync: state encodieren fehlgeschlagen")
		return
	}
	if err := tmp.Sync(); err != nil {
		return
	}
	if err := tmp.Close(); err != nil {
		return
	}
	if err := os.Rename(tmpPath, sm.statePath); err != nil {
		log.Warn().Err(err).Msg("dhcp sync: state rename fehlgeschlagen")
	}
}

// AutoReverseZone is exported for tests — delegates to dns.ReverseZoneForIP.
func AutoReverseZone(ip string) string {
	zone, _ := dns.ReverseZoneForIP(ip)
	return zone
}

// PTRName is exported for tests — delegates to dns.PTRNameForIP.
func PTRName(ip, _ string) string {
	return dns.PTRNameForIP(ip)
}

// SanitizeHostname is the exported version for tests.
func SanitizeHostname(name string) string {
	return sanitizeHostname(name)
}

// ReverseZone returns the configured or auto-determined reverse zone.
func (sm *SyncManager) ReverseZone() string {
	if sm.reverseZone != "" {
		return sm.reverseZone
	}
	// Derive from state
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for ip := range sm.state {
		if !strings.Contains(ip, ":") {
			zone, _ := dns.ReverseZoneForIP(ip)
			return zone
		}
	}
	return ""
}
