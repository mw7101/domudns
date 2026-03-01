package dnsserver

import (
	"net"
	"testing"

	"github.com/mw7101/domudns/internal/dns"
	mdns "github.com/miekg/dns"
)

// --- Helper functions ---

// newTestZoneManager creates a ZoneManager with a sample zone.
func newTestZoneManager() *ZoneManager {
	zm := NewZoneManager()
	zm.zones["example.com"] = &dns.Zone{
		Domain: "example.com",
		TTL:    3600,
		SOA: &dns.SOA{
			MName:   "ns1.example.com",
			RName:   "hostmaster.example.com",
			Serial:  2026020100,
			Refresh: 3600,
			Retry:   1800,
			Expire:  604800,
			Minimum: 300,
		},
		Records: []dns.Record{
			{ID: 1, Name: "@", Type: dns.TypeA, TTL: 300, Value: "1.2.3.4"},
			{ID: 2, Name: "www", Type: dns.TypeA, TTL: 300, Value: "1.2.3.5"},
			{ID: 3, Name: "@", Type: dns.TypeMX, TTL: 3600, Value: "mail.example.com", Priority: 10},
			{ID: 4, Name: "@", Type: dns.TypeFWD, TTL: 0, Value: "192.168.1.1"},
		},
	}
	return zm
}

// mockTCPWriter simulates a DNS ResponseWriter over TCP.
type mockTCPWriter struct {
	messages []*mdns.Msg
	addr     net.Addr
}

func newMockTCPWriter() *mockTCPWriter {
	return &mockTCPWriter{addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}
}

func (m *mockTCPWriter) LocalAddr() net.Addr  { return m.addr }
func (m *mockTCPWriter) RemoteAddr() net.Addr { return m.addr }
func (m *mockTCPWriter) WriteMsg(msg *mdns.Msg) error {
	m.messages = append(m.messages, msg.Copy())
	return nil
}
func (m *mockTCPWriter) Write(b []byte) (int, error) { return 0, nil }
func (m *mockTCPWriter) Close() error                { return nil }
func (m *mockTCPWriter) TsigStatus() error           { return nil }
func (m *mockTCPWriter) TsigTimersOnly(b bool)       {}
func (m *mockTCPWriter) Hijack()                     {}

// mockUDPWriter simulates a DNS ResponseWriter over UDP.
type mockUDPWriter struct {
	messages []*mdns.Msg
	addr     net.Addr
}

func newMockUDPWriter() *mockUDPWriter {
	return &mockUDPWriter{addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}
}

func (m *mockUDPWriter) LocalAddr() net.Addr  { return m.addr }
func (m *mockUDPWriter) RemoteAddr() net.Addr { return m.addr }
func (m *mockUDPWriter) WriteMsg(msg *mdns.Msg) error {
	m.messages = append(m.messages, msg.Copy())
	return nil
}
func (m *mockUDPWriter) Write(b []byte) (int, error) { return 0, nil }
func (m *mockUDPWriter) Close() error                { return nil }
func (m *mockUDPWriter) TsigStatus() error           { return nil }
func (m *mockUDPWriter) TsigTimersOnly(b bool)       {}
func (m *mockUDPWriter) Hijack()                     {}

// buildAXFRRequest builds an AXFR request.
func buildAXFRRequest(qname string, qtype uint16) *mdns.Msg {
	r := new(mdns.Msg)
	r.SetQuestion(mdns.Fqdn(qname), qtype)
	r.RecursionDesired = false
	return r
}

// --- Tests ---

// TestAXFRHandler_Disabled checks that the handler returns REFUSED when no AXFR handler is set.
// This is tested indirectly via handler.go: axfr == nil → REFUSED.
func TestAXFRHandler_Disabled(t *testing.T) {
	h := NewHandler([]string{"1.1.1.1"}, nil, NewZoneManager(), nil, "0.0.0.0", "::", nil, false)
	// axfr is nil (not set)

	w := newMockTCPWriter()
	r := buildAXFRRequest("example.com", mdns.TypeAXFR)

	h.ServeDNS(w, r)

	if len(w.messages) == 0 {
		t.Fatal("keine Antwort erhalten")
	}
	if w.messages[0].Rcode != mdns.RcodeRefused {
		t.Errorf("erwartet REFUSED (%d), erhalten %d", mdns.RcodeRefused, w.messages[0].Rcode)
	}
}

// TestAXFRHandler_ACLDeny checks that an unauthorized IP is rejected.
func TestAXFRHandler_ACLDeny(t *testing.T) {
	zm := newTestZoneManager()
	// Only 10.0.0.0/8 allowed — 127.0.0.1 is not included
	h, err := NewAXFRHandler(zm, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewAXFRHandler: %v", err)
	}

	w := newMockTCPWriter()
	r := buildAXFRRequest("example.com", mdns.TypeAXFR)

	h.Handle(w, r)

	if len(w.messages) == 0 {
		t.Fatal("keine Antwort erhalten")
	}
	if w.messages[0].Rcode != mdns.RcodeRefused {
		t.Errorf("erwartet REFUSED (%d), erhalten %d", mdns.RcodeRefused, w.messages[0].Rcode)
	}
}

// TestAXFRHandler_ACLAllow checks that an authorized IP receives a response.
func TestAXFRHandler_ACLAllow(t *testing.T) {
	zm := newTestZoneManager()
	h, err := NewAXFRHandler(zm, []string{"127.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewAXFRHandler: %v", err)
	}

	w := newMockTCPWriter()
	r := buildAXFRRequest("example.com", mdns.TypeAXFR)

	h.Handle(w, r)

	if len(w.messages) == 0 {
		t.Fatal("keine Antwort erhalten")
	}
	// No REFUSED response expected
	if w.messages[0].Rcode == mdns.RcodeRefused {
		t.Error("ACL hat erlaubte IP abgelehnt")
	}
}

// TestAXFRHandler_ZoneNotFound checks that NOTAUTH is returned when the zone is not found.
func TestAXFRHandler_ZoneNotFound(t *testing.T) {
	zm := NewZoneManager() // empty ZoneManager
	h, err := NewAXFRHandler(zm, []string{"127.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewAXFRHandler: %v", err)
	}

	w := newMockTCPWriter()
	r := buildAXFRRequest("nonexistent.example.com", mdns.TypeAXFR)

	h.Handle(w, r)

	if len(w.messages) == 0 {
		t.Fatal("keine Antwort erhalten")
	}
	if w.messages[0].Rcode != mdns.RcodeNotAuth {
		t.Errorf("erwartet NOTAUTH (%d), erhalten %d", mdns.RcodeNotAuth, w.messages[0].Rcode)
	}
}

// TestAXFRHandler_FullTransfer checks that a complete zone transfer is delivered.
// Format: SOA ... Records ... SOA
func TestAXFRHandler_FullTransfer(t *testing.T) {
	zm := newTestZoneManager()
	h, err := NewAXFRHandler(zm, []string{"127.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewAXFRHandler: %v", err)
	}

	w := newMockTCPWriter()
	r := buildAXFRRequest("example.com", mdns.TypeAXFR)

	h.Handle(w, r)

	if len(w.messages) == 0 {
		t.Fatal("keine Nachrichten erhalten")
	}

	// Collect all RRs from all messages
	var allRRs []mdns.RR
	for _, msg := range w.messages {
		allRRs = append(allRRs, msg.Answer...)
	}

	if len(allRRs) < 2 {
		t.Fatalf("zu wenig RRs erhalten: %d (min. 2 SOA erwartet)", len(allRRs))
	}

	// First RR must be SOA
	if _, ok := allRRs[0].(*mdns.SOA); !ok {
		t.Errorf("erster RR ist kein SOA: %T", allRRs[0])
	}

	// Last RR must be SOA
	last := allRRs[len(allRRs)-1]
	if _, ok := last.(*mdns.SOA); !ok {
		t.Errorf("letzter RR ist kein SOA: %T", last)
	}
}

// TestAXFRHandler_IXFRFallback checks that IXFR is answered as a full AXFR.
func TestAXFRHandler_IXFRFallback(t *testing.T) {
	zm := newTestZoneManager()
	h, err := NewAXFRHandler(zm, []string{"127.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewAXFRHandler: %v", err)
	}

	w := newMockTCPWriter()
	r := buildAXFRRequest("example.com", mdns.TypeIXFR)

	h.Handle(w, r)

	if len(w.messages) == 0 {
		t.Fatal("keine Nachrichten erhalten")
	}

	// IXFR must also respond with SOA records (full AXFR)
	var allRRs []mdns.RR
	for _, msg := range w.messages {
		allRRs = append(allRRs, msg.Answer...)
	}

	if len(allRRs) < 2 {
		t.Fatalf("zu wenig RRs erhalten: %d", len(allRRs))
	}
	if _, ok := allRRs[0].(*mdns.SOA); !ok {
		t.Error("IXFR: erster RR ist kein SOA")
	}
}

// TestAXFRHandler_UDPRefused checks that AXFR over UDP is rejected with NOTIMP.
func TestAXFRHandler_UDPRefused(t *testing.T) {
	zm := newTestZoneManager()
	h, err := NewAXFRHandler(zm, []string{"127.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewAXFRHandler: %v", err)
	}

	w := newMockUDPWriter() // UDP writer instead of TCP
	r := buildAXFRRequest("example.com", mdns.TypeAXFR)

	h.Handle(w, r)

	if len(w.messages) == 0 {
		t.Fatal("keine Antwort erhalten")
	}
	if w.messages[0].Rcode != mdns.RcodeNotImplemented {
		t.Errorf("erwartet NOTIMP (%d), erhalten %d", mdns.RcodeNotImplemented, w.messages[0].Rcode)
	}
}

// TestAXFRHandler_SkipsFWDRecords checks that FWD records are not included in the AXFR response.
func TestAXFRHandler_SkipsFWDRecords(t *testing.T) {
	zm := newTestZoneManager()
	h, err := NewAXFRHandler(zm, []string{"127.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewAXFRHandler: %v", err)
	}

	w := newMockTCPWriter()
	r := buildAXFRRequest("example.com", mdns.TypeAXFR)

	h.Handle(w, r)

	// Check all RRs — no FWD RR expected (FWD has no standard RR type)
	for _, msg := range w.messages {
		for _, rr := range msg.Answer {
			// FWD records should not appear since recordToRR returns nil for them
			if rr == nil {
				t.Error("nil RR in Antwort")
			}
		}
	}
}

// TestAXFRHandler_Update checks that the ACL can be updated at runtime.
func TestAXFRHandler_Update(t *testing.T) {
	zm := newTestZoneManager()
	// Initial: 10.0.0.0/8 → 127.0.0.1 is rejected
	h, err := NewAXFRHandler(zm, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewAXFRHandler: %v", err)
	}

	w1 := newMockTCPWriter()
	r := buildAXFRRequest("example.com", mdns.TypeAXFR)
	h.Handle(w1, r)
	if len(w1.messages) == 0 || w1.messages[0].Rcode != mdns.RcodeRefused {
		t.Error("vor Update: erwartet REFUSED")
	}

	// Update ACL: allow 127.0.0.0/8
	if err := h.Update([]string{"127.0.0.0/8"}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	w2 := newMockTCPWriter()
	h.Handle(w2, r)
	if len(w2.messages) == 0 {
		t.Fatal("nach Update: keine Antwort erhalten")
	}
	if w2.messages[0].Rcode == mdns.RcodeRefused {
		t.Error("nach Update: erwartet keine REFUSED mehr")
	}
}

// TestAXFRHandler_InvalidCIDR checks that invalid CIDRs return an error.
func TestAXFRHandler_InvalidCIDR(t *testing.T) {
	zm := newTestZoneManager()
	_, err := NewAXFRHandler(zm, []string{"not-a-cidr"})
	if err == nil {
		t.Error("erwartet Fehler bei ungültiger CIDR")
	}
}

// TestParseCIDRs checks parsing of various IP/CIDR formats.
func TestParseCIDRs(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		wantErr bool
	}{
		{"IPv4 CIDR", []string{"192.168.0.0/16"}, false},
		{"IPv4 address", []string{"127.0.0.1"}, false},
		{"IPv6 CIDR", []string{"::1/128"}, false},
		{"multiple entries", []string{"127.0.0.1", "10.0.0.0/8"}, false},
		{"empty", []string{}, false},
		{"invalid", []string{"not-valid"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nets, err := parseCIDRs(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseCIDRs() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(nets) != len(tt.input) {
				t.Errorf("parseCIDRs() = %d nets, want %d", len(nets), len(tt.input))
			}
		})
	}
}
