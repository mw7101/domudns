package dnsserver

import (
	"net"
	"testing"
	"time"

	dnsinternal "github.com/mw7101/domudns/internal/dns"
	"github.com/miekg/dns"
)

// mockResponseWriter is a dns.ResponseWriter for tests.
type mockResponseWriter struct {
	remoteAddr string
	written    *dns.Msg
	writeErr   error
}

func (m *mockResponseWriter) LocalAddr() net.Addr  { return &net.UDPAddr{} }
func (m *mockResponseWriter) RemoteAddr() net.Addr { return &net.UDPAddr{} }
func (m *mockResponseWriter) WriteMsg(msg *dns.Msg) error {
	if m.writeErr != nil {
		return m.writeErr
	}
	m.written = msg.Copy()
	return nil
}
func (m *mockResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockResponseWriter) Close() error                { return nil }
func (m *mockResponseWriter) TsigStatus() error           { return nil }
func (m *mockResponseWriter) TsigTimersOnly(bool)         {}
func (m *mockResponseWriter) Hijack()                     {}

// withRemoteAddr creates a mockResponseWriter with fixed remote address.
func withRemoteAddr(addr string) *mockResponseWriter {
	return &mockResponseWriter{remoteAddr: addr}
}

// Override RemoteAddr for IP tests
type mockRWWithAddr struct {
	mockResponseWriter
	addr net.Addr
}

func (m *mockRWWithAddr) RemoteAddr() net.Addr { return m.addr }

// makeQuery erzeugt eine DNS-Anfrage.
func makeQuery(qname string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	return m
}

// --- Tests ---

func TestHandler_FormatError_NoQuestion(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil, "0.0.0.0", "::", nil, false)

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}
	req := new(dns.Msg)
	req.RecursionDesired = true
	// Keine Question

	h.ServeDNS(rw, req)

	if rw.written == nil {
		t.Fatal("expected error response, got nil")
	}
	if rw.written.Rcode != dns.RcodeFormatError {
		t.Errorf("expected FORMERR, got %d", rw.written.Rcode)
	}
}

func TestHandler_AnyQueryRefused(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil, "0.0.0.0", "::", nil, false)

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}}
	req := makeQuery("example.com", dns.TypeANY)

	h.ServeDNS(rw, req)

	if rw.written == nil {
		t.Fatal("expected REFUSED response, got nil")
	}
	if rw.written.Rcode != dns.RcodeRefused {
		t.Errorf("expected REFUSED for ANY query, got %d", rw.written.Rcode)
	}
}

func TestHandler_BlocklistHit(t *testing.T) {
	bl := NewBlocklistManager()
	bl.mu.Lock()
	bl.domains["ads.evil.com"] = struct{}{}
	bl.mu.Unlock()

	h := NewHandler(nil, bl, nil, nil, "0.0.0.0", "::", nil, false)

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}
	req := makeQuery("ads.evil.com", dns.TypeA)

	h.ServeDNS(rw, req)

	if rw.written == nil {
		t.Fatal("expected blocked response")
	}
	// Blocked Response liefert NOERROR mit 0.0.0.0
	if rw.written.Rcode != dns.RcodeSuccess {
		t.Errorf("expected NOERROR for blocked domain, got %d", rw.written.Rcode)
	}
	if len(rw.written.Answer) == 0 {
		t.Error("expected 0.0.0.0 answer for blocked A query")
	}
	aRec, ok := rw.written.Answer[0].(*dns.A)
	if !ok {
		t.Fatal("expected A record in blocked response")
	}
	if !aRec.A.Equal(net.ParseIP("0.0.0.0")) {
		t.Errorf("expected 0.0.0.0, got %s", aRec.A)
	}
}

func TestHandler_WhitelistBypass(t *testing.T) {
	bl := NewBlocklistManager()
	bl.mu.Lock()
	bl.domains["ads.evil.com"] = struct{}{}
	_, ipNet, _ := net.ParseCIDR("192.168.1.0/24")
	bl.whitelist = []*net.IPNet{ipNet}
	bl.mu.Unlock()

	// No forwarder → SERVFAIL when forwarded, but that's OK for this test.
	// We only verify that whitelist IP bypasses blocklist.
	h := NewHandler([]string{"127.0.0.1:15353"}, bl, nil, nil, "0.0.0.0", "::", nil, false)

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.50"), Port: 1234}}
	req := makeQuery("ads.evil.com", dns.TypeA)

	h.ServeDNS(rw, req)

	if rw.written == nil {
		t.Fatal("expected response")
	}
	// Bei Whitelist-Bypass wird die Domain NICHT blockiert (0.0.0.0).
	// Forwarder fails → SERVFAIL, but no blocked response.
	if rw.written.Rcode == dns.RcodeSuccess && len(rw.written.Answer) > 0 {
		aRec, ok := rw.written.Answer[0].(*dns.A)
		if ok && aRec.A.Equal(net.ParseIP("0.0.0.0")) {
			t.Error("whitelisted IP sollte nicht durch Blocklist blockiert werden")
		}
	}
}

func TestHandler_CacheHit(t *testing.T) {
	cache := NewCacheManager(100, time.Minute, time.Minute)

	// Antwort vorab cachen
	cached := makeResponse("example.com", dns.TypeA, dns.RcodeSuccess, 60)
	cached.Id = 0 // will be overwritten
	cache.Set("example.com.", dns.TypeA, cached)

	h := NewHandler(nil, nil, nil, cache, "0.0.0.0", "::", nil, false)

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}
	req := makeQuery("example.com", dns.TypeA)

	h.ServeDNS(rw, req)

	if rw.written == nil {
		t.Fatal("expected cached response")
	}
	if rw.written.Rcode != dns.RcodeSuccess {
		t.Errorf("expected NOERROR from cache, got %d", rw.written.Rcode)
	}
	// Message ID muss zur Anfrage passen
	if rw.written.Id != req.Id {
		t.Errorf("expected response ID %d, got %d", req.Id, rw.written.Id)
	}
}

func TestHandler_AuthoritativeZone(t *testing.T) {
	zm := NewZoneManager()
	zm.mu.Lock()
	zm.zones["example.com"] = &dnsinternal.Zone{
		Domain: "example.com",
		TTL:    3600,
		Records: []dnsinternal.Record{
			{
				ID:    1,
				Name:  "www",
				Type:  dnsinternal.TypeA,
				TTL:   3600,
				Value: "1.2.3.4",
			},
		},
	}
	zm.mu.Unlock()

	h := NewHandler(nil, nil, zm, nil, "0.0.0.0", "::", nil, false)

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}
	req := makeQuery("www.example.com", dns.TypeA)

	h.ServeDNS(rw, req)

	if rw.written == nil {
		t.Fatal("expected authoritative response")
	}
	if !rw.written.Authoritative {
		t.Error("expected Authoritative flag set")
	}
	if len(rw.written.Answer) == 0 {
		t.Error("expected answer in authoritative response")
	}
	aRec, ok := rw.written.Answer[0].(*dns.A)
	if !ok {
		t.Fatal("expected A record")
	}
	if aRec.A.String() != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %s", aRec.A)
	}
}

func TestHandler_ServfailNotCached(t *testing.T) {
	cache := NewCacheManager(100, time.Minute, time.Minute)

	h := NewHandler([]string{"127.0.0.1:15353"}, nil, nil, cache, "0.0.0.0", "::", nil, false)

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}
	req := makeQuery("example.com", dns.TypeA)

	h.ServeDNS(rw, req)

	// Nach SERVFAIL (Upstream nicht erreichbar) darf nichts im Cache sein
	got := cache.Get("example.com.", dns.TypeA)
	if got != nil {
		t.Errorf("SERVFAIL sollte nicht gecacht werden, aber Cache enthält: %v", got)
	}
}

// --- Block-Mode-Tests ---

func TestHandler_RespondBlocked_ZeroIP(t *testing.T) {
	bl := NewBlocklistManager()
	bl.mu.Lock()
	bl.domains["ads.example.com"] = struct{}{}
	bl.mu.Unlock()

	h := NewHandler(nil, bl, nil, nil, "0.0.0.0", "::", nil, false)
	// zero_ip is the default — no UpdateBlockMode needed

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}

	t.Run("A-Query liefert 0.0.0.0", func(t *testing.T) {
		rw2 := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}
		h.ServeDNS(rw2, makeQuery("ads.example.com", dns.TypeA))
		if rw2.written == nil {
			t.Fatal("kein Response")
		}
		if rw2.written.Rcode != dns.RcodeSuccess {
			t.Errorf("Rcode = %d, want NOERROR", rw2.written.Rcode)
		}
		if len(rw2.written.Answer) == 0 {
			t.Fatal("kein Answer-Record erwartet 0.0.0.0")
		}
		a, ok := rw2.written.Answer[0].(*dns.A)
		if !ok {
			t.Fatal("erwartet A-Record")
		}
		if !a.A.Equal(net.ParseIP("0.0.0.0")) {
			t.Errorf("A = %s, want 0.0.0.0", a.A)
		}
	})

	t.Run("AAAA-Query liefert ::", func(t *testing.T) {
		rw2 := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}
		h.ServeDNS(rw2, makeQuery("ads.example.com", dns.TypeAAAA))
		if rw2.written == nil {
			t.Fatal("kein Response")
		}
		if len(rw2.written.Answer) == 0 {
			t.Fatal("kein AAAA-Record")
		}
		aaaa, ok := rw2.written.Answer[0].(*dns.AAAA)
		if !ok {
			t.Fatal("erwartet AAAA-Record")
		}
		if !aaaa.AAAA.Equal(net.ParseIP("::")) {
			t.Errorf("AAAA = %s, want ::", aaaa.AAAA)
		}
	})
	_ = rw
}

func TestHandler_RespondBlocked_NXDOMAIN(t *testing.T) {
	bl := NewBlocklistManager()
	bl.mu.Lock()
	bl.domains["ads.example.com"] = struct{}{}
	bl.mu.Unlock()

	h := NewHandler(nil, bl, nil, nil, "0.0.0.0", "::", nil, false)
	h.UpdateBlockMode("nxdomain")

	tests := []struct {
		name  string
		qtype uint16
	}{
		{"A-Query → NXDOMAIN", dns.TypeA},
		{"AAAA-Query → NXDOMAIN", dns.TypeAAAA},
		{"MX-Query → NXDOMAIN", dns.TypeMX},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}
			h.ServeDNS(rw, makeQuery("ads.example.com", tt.qtype))
			if rw.written == nil {
				t.Fatal("kein Response")
			}
			if rw.written.Rcode != dns.RcodeNameError {
				t.Errorf("Rcode = %d, want NXDOMAIN (%d)", rw.written.Rcode, dns.RcodeNameError)
			}
			if len(rw.written.Answer) != 0 {
				t.Errorf("erwarte leere Answer-Section, got %d records", len(rw.written.Answer))
			}
		})
	}
}

func TestHandler_UpdateBlockMode_LiveReload(t *testing.T) {
	bl := NewBlocklistManager()
	bl.mu.Lock()
	bl.domains["ads.example.com"] = struct{}{}
	bl.mu.Unlock()

	h := NewHandler(nil, bl, nil, nil, "0.0.0.0", "::", nil, false)

	// Zuerst: zero_ip (Default)
	rw1 := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}
	h.ServeDNS(rw1, makeQuery("ads.example.com", dns.TypeA))
	if rw1.written == nil || rw1.written.Rcode != dns.RcodeSuccess {
		t.Fatalf("erwartet NOERROR im zero_ip-Modus, got %v", rw1.written)
	}

	// Live-Reload auf nxdomain
	h.UpdateBlockMode("nxdomain")

	// Jetzt: NXDOMAIN
	rw2 := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}
	h.ServeDNS(rw2, makeQuery("ads.example.com", dns.TypeA))
	if rw2.written == nil || rw2.written.Rcode != dns.RcodeNameError {
		t.Fatalf("erwartet NXDOMAIN nach UpdateBlockMode, got rcode=%v", rw2.written)
	}

	// Zurück auf zero_ip
	h.UpdateBlockMode("zero_ip")

	rw3 := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}
	h.ServeDNS(rw3, makeQuery("ads.example.com", dns.TypeA))
	if rw3.written == nil || rw3.written.Rcode != dns.RcodeSuccess {
		t.Fatalf("erwartet NOERROR nach Wechsel zurück auf zero_ip, got rcode=%v", rw3.written)
	}
}

func TestHandler_UpdateBlockMode_InvalidFallsBackToZeroIP(t *testing.T) {
	bl := NewBlocklistManager()
	bl.mu.Lock()
	bl.domains["ads.example.com"] = struct{}{}
	bl.mu.Unlock()

	h := NewHandler(nil, bl, nil, nil, "0.0.0.0", "::", nil, false)
	h.UpdateBlockMode("something_invalid") // should fall back to zero_ip

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}
	h.ServeDNS(rw, makeQuery("ads.example.com", dns.TypeA))
	if rw.written == nil || rw.written.Rcode != dns.RcodeSuccess {
		t.Errorf("ungültiger Modus soll auf zero_ip zurückfallen (NOERROR), got %v", rw.written)
	}
}

// --- Split-Horizon-Tests ---

func TestHandler_SplitHorizon_InternalClientGetsViewZone(t *testing.T) {
	zm := NewZoneManager()
	loadZonesManually(zm,
		makeZone("nas.home", "", "10.0.0.1"),
		makeZone("nas.home", "internal", "192.168.1.100"),
	)

	h := NewHandler(nil, nil, zm, nil, "0.0.0.0", "::", nil, false)
	_, ipNet, _ := net.ParseCIDR("192.168.0.0/16")
	resolver := NewSplitHorizonResolver(true, []SplitHorizonView{
		{Name: "internal", Subnets: []*net.IPNet{ipNet}},
	})
	h.SetSplitHorizonResolver(resolver)

	// LAN-Client → soll View-Zone bekommen (192.168.1.100)
	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.50"), Port: 1234}}
	h.ServeDNS(rw, makeQuery("nas.home", dns.TypeA))

	if rw.written == nil {
		t.Fatal("erwartet Response, got nil")
	}
	if rw.written.Rcode != dns.RcodeSuccess {
		t.Fatalf("Rcode = %d, want NOERROR", rw.written.Rcode)
	}
	if len(rw.written.Answer) == 0 {
		t.Fatal("erwartet Answer-Record")
	}
	a, ok := rw.written.Answer[0].(*dns.A)
	if !ok {
		t.Fatal("erwartet A-Record")
	}
	if a.A.String() != "192.168.1.100" {
		t.Errorf("got IP %s, want 192.168.1.100", a.A)
	}
}

func TestHandler_SplitHorizon_ExternalClientGetsDefault(t *testing.T) {
	zm := NewZoneManager()
	loadZonesManually(zm,
		makeZone("nas.home", "", "10.0.0.1"),
		makeZone("nas.home", "internal", "192.168.1.100"),
	)

	h := NewHandler(nil, nil, zm, nil, "0.0.0.0", "::", nil, false)
	_, ipNet, _ := net.ParseCIDR("192.168.0.0/16")
	resolver := NewSplitHorizonResolver(true, []SplitHorizonView{
		{Name: "internal", Subnets: []*net.IPNet{ipNet}},
	})
	h.SetSplitHorizonResolver(resolver)

	// Externer Client → kein View-Match → Default-Zone
	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 1234}}
	h.ServeDNS(rw, makeQuery("nas.home", dns.TypeA))

	if rw.written == nil {
		t.Fatal("erwartet Response, got nil")
	}
	if rw.written.Rcode != dns.RcodeSuccess {
		t.Fatalf("Rcode = %d, want NOERROR", rw.written.Rcode)
	}
	if len(rw.written.Answer) == 0 {
		t.Fatal("erwartet Answer-Record")
	}
	a, ok := rw.written.Answer[0].(*dns.A)
	if !ok {
		t.Fatal("erwartet A-Record")
	}
	if a.A.String() != "10.0.0.1" {
		t.Errorf("got IP %s, want 10.0.0.1", a.A)
	}
}

func TestHandler_SplitHorizon_ExternalClientNoDefaultZone(t *testing.T) {
	zm := NewZoneManager()
	// Nur View-Zone, keine Default-Zone
	loadZonesManually(zm, makeZone("nas.home", "internal", "192.168.1.100"))

	h := NewHandler(nil, nil, zm, nil, "0.0.0.0", "::", nil, false)
	_, ipNet, _ := net.ParseCIDR("192.168.0.0/16")
	resolver := NewSplitHorizonResolver(true, []SplitHorizonView{
		{Name: "internal", Subnets: []*net.IPNet{ipNet}},
	})
	h.SetSplitHorizonResolver(resolver)

	// Externer Client → kein View-Match, keine Default-Zone → kein Hit (Upstream/SERVFAIL)
	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 1234}}
	h.ServeDNS(rw, makeQuery("nas.home", dns.TypeA))

	if rw.written == nil {
		t.Fatal("erwartet Response, got nil")
	}
	// Kein Upstream konfiguriert → SERVFAIL (keine autoritative Zone getroffen)
	if rw.written.Rcode == dns.RcodeSuccess && len(rw.written.Answer) > 0 {
		a, ok := rw.written.Answer[0].(*dns.A)
		if ok && a.A.String() == "192.168.1.100" {
			t.Error("externer Client darf View-Zone nicht sehen")
		}
	}
}

func TestHandler_SplitHorizon_Disabled(t *testing.T) {
	zm := NewZoneManager()
	loadZonesManually(zm,
		makeZone("nas.home", "", "10.0.0.1"),
		makeZone("nas.home", "internal", "192.168.1.100"),
	)

	// Kein SplitHorizonResolver → immer Default-Zone
	h := NewHandler(nil, nil, zm, nil, "0.0.0.0", "::", nil, false)

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.50"), Port: 1234}}
	h.ServeDNS(rw, makeQuery("nas.home", dns.TypeA))

	if rw.written == nil {
		t.Fatal("erwartet Response, got nil")
	}
	if rw.written.Rcode != dns.RcodeSuccess {
		t.Fatalf("Rcode = %d, want NOERROR", rw.written.Rcode)
	}
	if len(rw.written.Answer) == 0 {
		t.Fatal("erwartet Answer-Record")
	}
	a, ok := rw.written.Answer[0].(*dns.A)
	if !ok {
		t.Fatal("erwartet A-Record")
	}
	if a.A.String() != "10.0.0.1" {
		t.Errorf("deaktivierter Split-Horizon: got IP %s, want 10.0.0.1", a.A)
	}
}

func TestHandler_ExtractClientIP_Fallback(t *testing.T) {
	tests := []struct {
		input    string
		wantNil  bool
		wantZero bool
	}{
		{"192.168.1.1:53", false, false},
		{"[::1]:53", false, false},
		{"192.168.1.1", false, false}, // ohne Port (Fallback)
		{"invalid-addr", false, true}, // invalid → IPv4zero
		{"", false, true},             // leer → IPv4zero
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			ip := extractClientIP(tc.input)
			if ip == nil {
				t.Error("extractClientIP darf nie nil zurückgeben")
			}
			if tc.wantZero && !ip.Equal(net.IPv4zero) {
				t.Errorf("expected IPv4zero fallback, got %s", ip)
			}
		})
	}
}
