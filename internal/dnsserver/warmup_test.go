package dnsserver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/mw7101/domudns/internal/querylog"
	"github.com/miekg/dns"
)

// --- Mock QueryLogReader ---

type mockQueryLogReader struct {
	topDomains []querylog.DomainStat
}

func (m *mockQueryLogReader) Stats() querylog.QueryLogStats {
	return querylog.QueryLogStats{
		TopDomains: m.topDomains,
	}
}

// --- Fake-DNS-Server Hilfsfunktion ---

// startFakeUpstreamDNS starts a UDP DNS server on a random port.
// Responds to all A queries with 1.2.3.4 (TTL 300), AAAA without answer.
func startFakeUpstreamDNS(t *testing.T) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("startFakeUpstreamDNS: ListenPacket: %v", err)
	}
	addr := pc.LocalAddr().String()

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.RecursionAvailable = true
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP("1.2.3.4").To4(),
			})
		}
		_ = w.WriteMsg(m)
	})

	srv := &dns.Server{
		PacketConn: pc,
		Net:        "udp",
		Handler:    mux,
	}

	ready := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = srv.ActivateAndServe() }()

	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("startFakeUpstreamDNS: Server nicht rechtzeitig gestartet")
	}

	t.Cleanup(func() { _ = srv.Shutdown() })
	return addr
}

// --- Tests for collectDomains ---

func TestCollectDomains_QueryLogHasPriority(t *testing.T) {
	qlog := &mockQueryLogReader{
		topDomains: []querylog.DomainStat{
			{Domain: "frequent.example.com", Count: 100},
			{Domain: "also-frequent.example.com", Count: 50},
		},
	}
	fallback := []string{"fallback1.com", "fallback2.com", "fallback3.com"}

	result := collectDomains(qlog, fallback, 5)

	// Query-Log domains must appear first
	if len(result) < 2 {
		t.Fatalf("erwartet mindestens 2 Einträge, got %d", len(result))
	}
	if result[0] != "frequent.example.com" {
		t.Errorf("result[0] = %q, want %q", result[0], "frequent.example.com")
	}
	if result[1] != "also-frequent.example.com" {
		t.Errorf("result[1] = %q, want %q", result[1], "also-frequent.example.com")
	}
}

func TestCollectDomains_FallbackFillsUp(t *testing.T) {
	qlog := &mockQueryLogReader{
		topDomains: []querylog.DomainStat{
			{Domain: "from-log.example.com", Count: 10},
		},
	}
	fallback := []string{"fallback1.com", "fallback2.com"}

	result := collectDomains(qlog, fallback, 5)

	if len(result) != 3 {
		t.Fatalf("erwartet 3 Einträge (1 log + 2 fallback), got %d", len(result))
	}
	// Fallback entries must be included
	found := map[string]bool{}
	for _, d := range result {
		found[d] = true
	}
	if !found["fallback1.com"] {
		t.Error("fallback1.com fehlt im Ergebnis")
	}
	if !found["fallback2.com"] {
		t.Error("fallback2.com fehlt im Ergebnis")
	}
}

func TestCollectDomains_DeduplicatesDomains(t *testing.T) {
	qlog := &mockQueryLogReader{
		topDomains: []querylog.DomainStat{
			{Domain: "duplicate.com", Count: 100},
		},
	}
	// Fallback contains same domain as log
	fallback := []string{"duplicate.com", "unique.com"}

	result := collectDomains(qlog, fallback, 10)

	// duplicate.com darf nur einmal vorkommen
	count := 0
	for _, d := range result {
		if d == "duplicate.com" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("duplicate.com erscheint %d mal, erwartet 1", count)
	}
}

func TestCollectDomains_MaxLimitEnforced(t *testing.T) {
	fallback := make([]string, 0, 50)
	for i := 0; i < 50; i++ {
		fallback = append(fallback, "domain"+string(rune('a'+i%26))+".com")
	}

	result := collectDomains(nil, fallback, 10)

	if len(result) > 10 {
		t.Errorf("erwartet max 10 Einträge, got %d", len(result))
	}
}

func TestCollectDomains_NilQueryLog(t *testing.T) {
	fallback := []string{"a.com", "b.com", "c.com"}

	result := collectDomains(nil, fallback, 5)

	if len(result) != 3 {
		t.Fatalf("erwartet 3 Einträge, got %d", len(result))
	}
}

// --- Tests for WarmCache ---

func TestWarmCache_NilCacheNosPanic(t *testing.T) {
	s := &Server{
		upstream: []string{"127.0.0.1:53"},
		cache:    nil,
	}
	// Must run without panic
	s.WarmCache(context.Background(), nil, 5)
}

func TestWarmCache_EmptyUpstreamNosPanic(t *testing.T) {
	cache := NewCacheManager(100, time.Hour, 5*time.Minute)
	s := &Server{
		upstream: []string{},
		cache:    cache,
	}
	// Must run without panic without sending DNS queries
	s.WarmCache(context.Background(), nil, 5)
}

func TestWarmCache_CachesDomainsFromUpstream(t *testing.T) {
	addr := startFakeUpstreamDNS(t)

	cache := NewCacheManager(500, time.Hour, 5*time.Minute)
	s := &Server{
		upstream: []string{addr},
		cache:    cache,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Few domains for quick test
	s.WarmCache(ctx, nil, 3)

	// At least one of the first domains from defaultWarmupDomains must be cached
	found := false
	for _, domain := range defaultWarmupDomains[:3] {
		fqdn := dns.Fqdn(domain)
		if cache.Get(fqdn, dns.TypeA) != nil {
			found = true
			break
		}
	}
	if !found {
		t.Error("kein einziger Domain aus den ersten 3 defaultWarmupDomains wurde gecacht")
	}
}

func TestWarmCache_QueryLogDomainsAreCached(t *testing.T) {
	addr := startFakeUpstreamDNS(t)

	cache := NewCacheManager(100, time.Hour, 5*time.Minute)
	s := &Server{
		upstream: []string{addr},
		cache:    cache,
	}

	qlog := &mockQueryLogReader{
		topDomains: []querylog.DomainStat{
			{Domain: "custom-test-domain.example", Count: 999},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s.WarmCache(ctx, qlog, 2)

	fqdn := dns.Fqdn("custom-test-domain.example")
	if cache.Get(fqdn, dns.TypeA) == nil {
		t.Error("Query-Log-Domain 'custom-test-domain.example' wurde nicht gecacht")
	}
}

func TestWarmCache_SkipsAlreadyCachedDomains(t *testing.T) {
	addr := startFakeUpstreamDNS(t)

	cache := NewCacheManager(100, time.Hour, 5*time.Minute)
	s := &Server{
		upstream: []string{addr},
		cache:    cache,
	}

	// Pre-cache domain with known response
	fqdn := dns.Fqdn(defaultWarmupDomains[0])
	preloaded := new(dns.Msg)
	preloaded.SetQuestion(fqdn, dns.TypeA)
	preloaded.Answer = append(preloaded.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 9999},
		A:   net.ParseIP("9.9.9.9").To4(),
	})
	cache.Set(fqdn, dns.TypeA, preloaded)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s.WarmCache(ctx, nil, 1)

	// Cached entry must not have been overwritten
	resp := cache.Get(fqdn, dns.TypeA)
	if resp == nil {
		t.Fatal("vorgeladerter Eintrag wurde aus dem Cache entfernt")
	}
	if len(resp.Answer) == 0 {
		t.Fatal("Cache-Antwort hat keine Antworten")
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatal("Cache-Antwort ist kein A-Record")
	}
	if !a.A.Equal(net.ParseIP("9.9.9.9")) {
		t.Errorf("vorgeladerter Eintrag wurde überschrieben: got %v, want 9.9.9.9", a.A)
	}
}
