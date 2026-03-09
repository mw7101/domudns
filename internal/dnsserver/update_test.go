package dnsserver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/mw7101/domudns/internal/dns"
	"github.com/mw7101/domudns/internal/store"
	miekgdns "github.com/miekg/dns"
)

// --- Mock-Implementierungen ---

type mockDDNSStore struct {
	zones   map[string]*dns.Zone
	records map[string][]dns.Record
	nextID  int
}

func newMockDDNSStore() *mockDDNSStore {
	return &mockDDNSStore{
		zones:   make(map[string]*dns.Zone),
		records: make(map[string][]dns.Record),
		nextID:  1,
	}
}

func (m *mockDDNSStore) GetZone(_ context.Context, domain string) (*dns.Zone, error) {
	z, ok := m.zones[domain]
	if !ok {
		return nil, nil
	}
	return z, nil
}

func (m *mockDDNSStore) GetRecords(_ context.Context, zoneDomain string) ([]dns.Record, error) {
	// Return copy so DeleteRecord does not corrupt the underlying array
	orig := m.records[zoneDomain]
	cp := make([]dns.Record, len(orig))
	copy(cp, orig)
	return cp, nil
}

func (m *mockDDNSStore) PutRecord(_ context.Context, zoneDomain string, record *dns.Record) error {
	if record.ID == 0 {
		record.ID = m.nextID
		m.nextID++
	}
	recs := m.records[zoneDomain]
	for i, r := range recs {
		if r.ID == record.ID {
			recs[i] = *record
			m.records[zoneDomain] = recs
			return nil
		}
	}
	m.records[zoneDomain] = append(recs, *record)
	return nil
}

func (m *mockDDNSStore) DeleteRecord(_ context.Context, zoneDomain string, recordID int) error {
	recs := m.records[zoneDomain]
	filtered := recs[:0]
	for _, r := range recs {
		if r.ID != recordID {
			filtered = append(filtered, r)
		}
	}
	m.records[zoneDomain] = filtered
	return nil
}

// ddnsMockRW is a separate ResponseWriter for DDNS tests with configurable TsigStatus.
type ddnsMockRW struct {
	written    *miekgdns.Msg
	tsigStatus error
}

func newDDNSMockRW() *ddnsMockRW                     { return &ddnsMockRW{} }
func (w *ddnsMockRW) LocalAddr() net.Addr            { return &net.UDPAddr{} }
func (w *ddnsMockRW) RemoteAddr() net.Addr           { return &net.UDPAddr{} }
func (w *ddnsMockRW) WriteMsg(m *miekgdns.Msg) error { w.written = m.Copy(); return nil }
func (w *ddnsMockRW) Write(b []byte) (int, error)    { return len(b), nil }
func (w *ddnsMockRW) Close() error                   { return nil }
func (w *ddnsMockRW) TsigStatus() error              { return w.tsigStatus }
func (w *ddnsMockRW) TsigTimersOnly(b bool)          {}
func (w *ddnsMockRW) Hijack()                        {}

// --- Hilfsfunktionen ---

func buildUpdateMsg(zone string, ns []miekgdns.RR) *miekgdns.Msg {
	m := new(miekgdns.Msg)
	m.SetUpdate(zone)
	m.Ns = ns
	return m
}

func makeATsigMsg(zone, keyName, secret string, ns []miekgdns.RR) *miekgdns.Msg {
	m := buildUpdateMsg(zone, ns)
	m.SetTsig(keyName, miekgdns.HmacSHA256, 300, time.Now().Unix())
	return m
}

// --- Tests ---

func TestDDNS_AddARecord(t *testing.T) {
	st := newMockDDNSStore()
	st.zones["home"] = &dns.Zone{Domain: "home"}

	keyName := "test-key"
	secret := "bXlzZWNyZXRrZXkxMjM0NQ==" // base64("mysecretkey12345")

	reloadCh := make(chan struct{}, 1)
	h := NewDDNSHandler(st, func() { reloadCh <- struct{}{} })
	h.UpdateKeys([]store.TSIGKey{{Name: keyName, Algorithm: "hmac-sha256", Secret: secret}})

	rr := &miekgdns.A{
		Hdr: miekgdns.RR_Header{
			Name:   "laptop.home.",
			Rrtype: miekgdns.TypeA,
			Class:  miekgdns.ClassINET,
			Ttl:    60,
		},
		A: net.ParseIP("192.168.100.42"),
	}

	msg := makeATsigMsg("home.", keyName, secret, []miekgdns.RR{rr})
	w := newDDNSMockRW()

	h.Handle(w, msg)

	if w.written == nil {
		t.Fatal("keine Antwort geschrieben")
	}
	if w.written.Rcode != miekgdns.RcodeSuccess {
		t.Fatalf("erwartet NOERROR, bekam %d", w.written.Rcode)
	}

	records := st.records["home"]
	if len(records) != 1 {
		t.Fatalf("erwartet 1 Record, bekam %d", len(records))
	}
	if records[0].Value != "192.168.100.42" {
		t.Errorf("falsche IP: %s", records[0].Value)
	}

	// ZoneReloader is called in a goroutine — race-free via channel
	select {
	case <-reloadCh:
		// correctly invoked
	case <-time.After(100 * time.Millisecond):
		t.Error("ZoneReloader nicht aufgerufen")
	}
}

func TestDDNS_DeleteARecord_ClassNONE(t *testing.T) {
	st := newMockDDNSStore()
	st.zones["home"] = &dns.Zone{Domain: "home"}
	st.records["home"] = []dns.Record{
		{ID: 1, Name: "laptop", Type: dns.TypeA, TTL: 60, Value: "192.168.100.42"},
	}

	keyName := "test-key"
	secret := "bXlzZWNyZXRrZXkxMjM0NQ=="

	h := NewDDNSHandler(st, nil)
	h.UpdateKeys([]store.TSIGKey{{Name: keyName, Algorithm: "hmac-sha256", Secret: secret}})

	rr := &miekgdns.A{
		Hdr: miekgdns.RR_Header{
			Name:   "laptop.home.",
			Rrtype: miekgdns.TypeA,
			Class:  miekgdns.ClassNONE,
			Ttl:    0,
		},
		A: net.ParseIP("192.168.100.42"),
	}

	msg := makeATsigMsg("home.", keyName, secret, []miekgdns.RR{rr})
	w := newDDNSMockRW()

	h.Handle(w, msg)

	if w.written.Rcode != miekgdns.RcodeSuccess {
		t.Fatalf("erwartet NOERROR, bekam %d", w.written.Rcode)
	}
	if len(st.records["home"]) != 0 {
		t.Error("Record sollte gelöscht sein")
	}
}

func TestDDNS_DeleteAllRecords_ClassANY(t *testing.T) {
	st := newMockDDNSStore()
	st.zones["home"] = &dns.Zone{Domain: "home"}
	st.records["home"] = []dns.Record{
		{ID: 1, Name: "server", Type: dns.TypeA, TTL: 60, Value: "192.168.100.10"},
		{ID: 2, Name: "server", Type: dns.TypeAAAA, TTL: 60, Value: "::1"},
		{ID: 3, Name: "other", Type: dns.TypeA, TTL: 60, Value: "192.168.100.20"},
	}

	keyName := "test-key"
	secret := "bXlzZWNyZXRrZXkxMjM0NQ=="

	h := NewDDNSHandler(st, nil)
	h.UpdateKeys([]store.TSIGKey{{Name: keyName, Algorithm: "hmac-sha256", Secret: secret}})

	rr := &miekgdns.ANY{
		Hdr: miekgdns.RR_Header{
			Name:   "server.home.",
			Rrtype: miekgdns.TypeANY,
			Class:  miekgdns.ClassANY,
		},
	}

	msg := makeATsigMsg("home.", keyName, secret, []miekgdns.RR{rr})
	w := newDDNSMockRW()

	h.Handle(w, msg)

	if w.written.Rcode != miekgdns.RcodeSuccess {
		t.Fatalf("erwartet NOERROR, bekam %d", w.written.Rcode)
	}
	remaining := st.records["home"]
	if len(remaining) != 1 || remaining[0].Name != "other" {
		t.Errorf("nur 'other' sollte übrig bleiben, got: %v", remaining)
	}
}

func TestDDNS_InvalidTSIG_ReturnsNOTAUTH(t *testing.T) {
	st := newMockDDNSStore()
	st.zones["home"] = &dns.Zone{Domain: "home"}

	keyName := "test-key"
	secret := "bXlzZWNyZXRrZXkxMjM0NQ=="

	h := NewDDNSHandler(st, nil)
	h.UpdateKeys([]store.TSIGKey{{Name: keyName, Algorithm: "hmac-sha256", Secret: secret}})

	rr := &miekgdns.A{
		Hdr: miekgdns.RR_Header{Name: "host.home.", Rrtype: miekgdns.TypeA, Class: miekgdns.ClassINET, Ttl: 60},
		A:   net.ParseIP("1.2.3.4"),
	}
	msg := makeATsigMsg("home.", keyName, secret, []miekgdns.RR{rr})
	w := newDDNSMockRW()
	w.tsigStatus = miekgdns.ErrSig // Simuliert: Verifikation fehlgeschlagen

	h.Handle(w, msg)

	if w.written.Rcode != miekgdns.RcodeNotAuth {
		t.Fatalf("erwartet NOTAUTH, bekam %d", w.written.Rcode)
	}
}

func TestDDNS_NoTSIG_WhenKeysConfigured_ReturnsNOTAUTH(t *testing.T) {
	st := newMockDDNSStore()
	st.zones["home"] = &dns.Zone{Domain: "home"}

	h := NewDDNSHandler(st, nil)
	h.UpdateKeys([]store.TSIGKey{{Name: "key", Algorithm: "hmac-sha256", Secret: "secret=="}})

	// Nachricht ohne TSIG
	msg := buildUpdateMsg("home.", nil)
	w := newDDNSMockRW()

	h.Handle(w, msg)

	if w.written.Rcode != miekgdns.RcodeNotAuth {
		t.Fatalf("erwartet NOTAUTH, bekam %d", w.written.Rcode)
	}
}

func TestDDNS_NoKeysConfigured_ReturnsREFUSED(t *testing.T) {
	st := newMockDDNSStore()
	h := NewDDNSHandler(st, nil)
	// Keine Keys konfiguriert

	msg := buildUpdateMsg("home.", nil)
	w := newDDNSMockRW()

	h.Handle(w, msg)

	if w.written.Rcode != miekgdns.RcodeRefused {
		t.Fatalf("erwartet REFUSED, bekam %d", w.written.Rcode)
	}
}

func TestDDNS_UnknownZone_ReturnsNOTZONE(t *testing.T) {
	st := newMockDDNSStore()
	// Keine Zone "unknown" vorhanden

	keyName := "test-key"
	secret := "bXlzZWNyZXRrZXkxMjM0NQ=="

	h := NewDDNSHandler(st, nil)
	h.UpdateKeys([]store.TSIGKey{{Name: keyName, Algorithm: "hmac-sha256", Secret: secret}})

	msg := makeATsigMsg("unknown.", keyName, secret, nil)
	w := newDDNSMockRW()

	h.Handle(w, msg)

	if w.written.Rcode != miekgdns.RcodeNotZone {
		t.Fatalf("erwartet NOTZONE, bekam %d", w.written.Rcode)
	}
}

func TestDDNS_UpdateKeys_LiveReload(t *testing.T) {
	st := newMockDDNSStore()
	st.zones["home"] = &dns.Zone{Domain: "home"}

	h := NewDDNSHandler(st, nil)

	// Zuerst mit altem Key → kein Key konfiguriert → REFUSED
	msg := buildUpdateMsg("home.", nil)
	w := newDDNSMockRW()
	h.Handle(w, msg)
	if w.written.Rcode != miekgdns.RcodeRefused {
		t.Fatal("ohne Keys sollte REFUSED kommen")
	}

	// Add new key
	h.UpdateKeys([]store.TSIGKey{{Name: "new-key", Algorithm: "hmac-sha256", Secret: "c2VjcmV0"}})

	// Jetzt ohne TSIG → NOTAUTH (Keys konfiguriert aber kein TSIG)
	w2 := newDDNSMockRW()
	msg2 := buildUpdateMsg("home.", nil)
	h.Handle(w2, msg2)
	if w2.written.Rcode != miekgdns.RcodeNotAuth {
		t.Fatalf("mit Keys aber ohne TSIG sollte NOTAUTH kommen, bekam %d", w2.written.Rcode)
	}
}

func TestDDNS_Stats_SuccessfulUpdate(t *testing.T) {
	st := newMockDDNSStore()
	st.zones["home"] = &dns.Zone{Domain: "home"}

	h := NewDDNSHandler(st, nil)
	h.UpdateKeys([]store.TSIGKey{{Name: "k", Algorithm: "hmac-sha256", Secret: "bXlzZWNyZXRrZXkxMjM0NQ=="}})

	rr := &miekgdns.A{
		Hdr: miekgdns.RR_Header{Name: "host.home.", Rrtype: miekgdns.TypeA, Class: miekgdns.ClassINET, Ttl: 60},
		A:   net.ParseIP("10.0.0.1"),
	}
	msg := makeATsigMsg("home.", "k", "bXlzZWNyZXRrZXkxMjM0NQ==", []miekgdns.RR{rr})
	w := newDDNSMockRW()
	h.Handle(w, msg)

	stats := h.GetStats()
	if stats.TotalUpdates != 1 {
		t.Errorf("TotalUpdates = %d, want 1", stats.TotalUpdates)
	}
	if stats.TotalFailed != 0 {
		t.Errorf("TotalFailed = %d, want 0", stats.TotalFailed)
	}
	if stats.LastUpdateAt.IsZero() {
		t.Error("LastUpdateAt sollte gesetzt sein")
	}
}

func TestDDNS_Stats_NotZoneRejection(t *testing.T) {
	st := newMockDDNSStore()
	// Zone "missing" existiert nicht

	h := NewDDNSHandler(st, nil)
	h.UpdateKeys([]store.TSIGKey{{Name: "k", Algorithm: "hmac-sha256", Secret: "bXlzZWNyZXRrZXkxMjM0NQ=="}})

	msg := makeATsigMsg("missing.", "k", "bXlzZWNyZXRrZXkxMjM0NQ==", nil)
	w := newDDNSMockRW()
	h.Handle(w, msg)

	if w.written.Rcode != miekgdns.RcodeNotZone {
		t.Fatalf("erwartet NOTZONE, bekam %d", w.written.Rcode)
	}

	stats := h.GetStats()
	if stats.TotalFailed != 1 {
		t.Errorf("TotalFailed = %d, want 1", stats.TotalFailed)
	}
	if stats.TotalUpdates != 0 {
		t.Errorf("TotalUpdates = %d, want 0", stats.TotalUpdates)
	}
	if stats.LastRejectedReason != "NOTZONE: missing" {
		t.Errorf("LastRejectedReason = %q, want %q", stats.LastRejectedReason, "NOTZONE: missing")
	}
	if stats.LastRejectedAt.IsZero() {
		t.Error("LastRejectedAt sollte gesetzt sein")
	}
}

func TestDDNS_Stats_NotAuthRejection(t *testing.T) {
	st := newMockDDNSStore()
	st.zones["home"] = &dns.Zone{Domain: "home"}

	h := NewDDNSHandler(st, nil)
	h.UpdateKeys([]store.TSIGKey{{Name: "k", Algorithm: "hmac-sha256", Secret: "secret=="}})

	rr := &miekgdns.A{
		Hdr: miekgdns.RR_Header{Name: "host.home.", Rrtype: miekgdns.TypeA, Class: miekgdns.ClassINET, Ttl: 60},
		A:   net.ParseIP("10.0.0.1"),
	}
	msg := makeATsigMsg("home.", "k", "secret==", []miekgdns.RR{rr})
	w := newDDNSMockRW()
	w.tsigStatus = miekgdns.ErrSig // TSIG-Verifikation fehlgeschlagen

	h.Handle(w, msg)

	if w.written.Rcode != miekgdns.RcodeNotAuth {
		t.Fatalf("erwartet NOTAUTH, bekam %d", w.written.Rcode)
	}

	stats := h.GetStats()
	if stats.TotalFailed != 1 {
		t.Errorf("TotalFailed = %d, want 1", stats.TotalFailed)
	}
	if stats.LastRejectedReason != "NOTAUTH: TSIG-Verifikation fehlgeschlagen" {
		t.Errorf("LastRejectedReason = %q", stats.LastRejectedReason)
	}
}

func TestDDNS_Stats_AccumulatesAcrossMultipleCalls(t *testing.T) {
	st := newMockDDNSStore()
	st.zones["home"] = &dns.Zone{Domain: "home"}

	h := NewDDNSHandler(st, nil)
	h.UpdateKeys([]store.TSIGKey{{Name: "k", Algorithm: "hmac-sha256", Secret: "bXlzZWNyZXRrZXkxMjM0NQ=="}})

	// 2 erfolgreiche Updates
	for i := 0; i < 2; i++ {
		rr := &miekgdns.A{
			Hdr: miekgdns.RR_Header{Name: "host.home.", Rrtype: miekgdns.TypeA, Class: miekgdns.ClassINET, Ttl: 60},
			A:   net.ParseIP("10.0.0.1"),
		}
		msg := makeATsigMsg("home.", "k", "bXlzZWNyZXRrZXkxMjM0NQ==", []miekgdns.RR{rr})
		h.Handle(newDDNSMockRW(), msg)
	}

	// 1 fehlgeschlagenes Update (falsche Zone)
	msg := makeATsigMsg("unknown.", "k", "bXlzZWNyZXRrZXkxMjM0NQ==", nil)
	h.Handle(newDDNSMockRW(), msg)

	stats := h.GetStats()
	if stats.TotalUpdates != 2 {
		t.Errorf("TotalUpdates = %d, want 2", stats.TotalUpdates)
	}
	if stats.TotalFailed != 1 {
		t.Errorf("TotalFailed = %d, want 1", stats.TotalFailed)
	}
}

// TestDDNS_TsigSecret_TrailingDot stellt sicher, dass GetSecrets() und der
// keyUpdater-Callback die Key-Namen mit Trailing Dot liefern.
// miekg/dns sucht in TsigSecret mit FQDN (z.B. "dhcp-dns."), nicht "dhcp-dns".
// Ohne Trailing Dot schlägt der Lookup fehl → NOTAUTH statt Erfolg.
func TestDDNS_TsigSecret_TrailingDot(t *testing.T) {
	st := newMockDDNSStore()
	h := NewDDNSHandler(st, nil)

	var capturedSecrets map[string]string
	h.keyUpdater = func(s map[string]string) {
		capturedSecrets = s
	}

	h.UpdateKeys([]store.TSIGKey{
		{Name: "dhcp-dns", Algorithm: "hmac-sha256", Secret: "c2VjcmV0"},
		{Name: "already.dot.", Algorithm: "hmac-sha256", Secret: "c2VjcmV0Mg=="},
	})

	// keyUpdater muss trailing dots enthalten
	if _, ok := capturedSecrets["dhcp-dns."]; !ok {
		t.Errorf("TsigSecret: key 'dhcp-dns.' fehlt, bekam: %v", capturedSecrets)
	}
	if _, ok := capturedSecrets["dhcp-dns"]; ok {
		t.Errorf("TsigSecret: key 'dhcp-dns' ohne Trailing Dot sollte nicht vorhanden sein")
	}
	if _, ok := capturedSecrets["already.dot."]; !ok {
		t.Errorf("TsigSecret: key 'already.dot.' fehlt")
	}

	// GetSecrets() muss ebenfalls trailing dots liefern (für initiale TsigSecret-Befüllung)
	secrets := h.GetSecrets()
	if _, ok := secrets["dhcp-dns."]; !ok {
		t.Errorf("GetSecrets: key 'dhcp-dns.' fehlt, bekam: %v", secrets)
	}
	if _, ok := secrets["dhcp-dns"]; ok {
		t.Errorf("GetSecrets: key 'dhcp-dns' ohne Trailing Dot sollte nicht vorhanden sein")
	}
}

func TestNormalizeRRName(t *testing.T) {
	tests := []struct {
		fqdn     string
		zone     string
		expected string
	}{
		{"laptop.home.", "home", "laptop"},
		{"home.", "home", ""},
		{"sub.laptop.home.", "home", "sub.laptop"},
		{"laptop.home.", "home.", "laptop"},
	}
	for _, tt := range tests {
		got := normalizeRRName(tt.fqdn, tt.zone)
		if got != tt.expected {
			t.Errorf("normalizeRRName(%q, %q) = %q, want %q", tt.fqdn, tt.zone, got, tt.expected)
		}
	}
}
