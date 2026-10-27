package dnsserver

import (
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// makeResponse creates a simple DNS response for tests.
func makeResponse(qname string, qtype uint16, rcode int, ttl uint32) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	m.Response = true
	m.Rcode = rcode

	if rcode == dns.RcodeSuccess && ttl > 0 {
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(qname),
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			A: []byte{1, 2, 3, 4},
		})
	}

	return m
}

func TestCacheManager_GetSet(t *testing.T) {
	c := NewCacheManager(100, time.Minute, time.Minute)

	resp := makeResponse("example.com", dns.TypeA, dns.RcodeSuccess, 60)
	c.Set("example.com.", dns.TypeA, resp)

	got := c.Get("example.com.", dns.TypeA)
	if got == nil {
		t.Fatal("expected cached response, got nil")
	}
	if got.Rcode != dns.RcodeSuccess {
		t.Errorf("expected NOERROR, got %d", got.Rcode)
	}
}

func TestCacheManager_GetMiss(t *testing.T) {
	c := NewCacheManager(100, time.Minute, time.Minute)

	got := c.Get("notcached.com.", dns.TypeA)
	if got != nil {
		t.Error("expected nil for cache miss, got response")
	}
}

func TestCacheManager_TTLExpiration(t *testing.T) {
	c := NewCacheManager(100, time.Minute, time.Minute)

	resp := makeResponse("example.com", dns.TypeA, dns.RcodeSuccess, 1)
	c.Set("example.com.", dns.TypeA, resp)

	// Immediately retrievable
	if got := c.Get("example.com.", dns.TypeA); got == nil {
		t.Fatal("expected cached response before expiry")
	}

	// Manually expire the entry
	c.mu.Lock()
	key := cacheKey("example.com.", dns.TypeA)
	c.entries[key].expiresAt = time.Now().Add(-time.Second)
	c.mu.Unlock()

	// After expiry: nil
	if got := c.Get("example.com.", dns.TypeA); got != nil {
		t.Error("expected nil after TTL expiry, got response")
	}
}

func TestCacheManager_NilResponseIgnored(t *testing.T) {
	c := NewCacheManager(100, time.Minute, time.Minute)

	c.Set("example.com.", dns.TypeA, nil)

	if got := c.Get("example.com.", dns.TypeA); got != nil {
		t.Error("expected nil after setting nil response")
	}
}

func TestCacheManager_NegativeCaching_NXDOMAIN(t *testing.T) {
	negativeTTL := 30 * time.Second
	c := NewCacheManager(100, time.Minute, negativeTTL)

	resp := makeResponse("nxdomain.com", dns.TypeA, dns.RcodeNameError, 0)
	c.Set("nxdomain.com.", dns.TypeA, resp)

	got := c.Get("nxdomain.com.", dns.TypeA)
	if got == nil {
		t.Fatal("expected NXDOMAIN to be cached")
	}
	if got.Rcode != dns.RcodeNameError {
		t.Errorf("expected NXDOMAIN rcode, got %d", got.Rcode)
	}
}

func TestCacheManager_DifferentQTypes(t *testing.T) {
	c := NewCacheManager(100, time.Minute, time.Minute)

	respA := makeResponse("example.com", dns.TypeA, dns.RcodeSuccess, 60)
	respAAAA := makeResponse("example.com", dns.TypeAAAA, dns.RcodeSuccess, 60)

	c.Set("example.com.", dns.TypeA, respA)
	c.Set("example.com.", dns.TypeAAAA, respAAAA)

	gotA := c.Get("example.com.", dns.TypeA)
	gotAAAA := c.Get("example.com.", dns.TypeAAAA)

	if gotA == nil || gotAAAA == nil {
		t.Fatal("expected both A and AAAA to be cached")
	}
}

func TestCacheManager_LRUEviction(t *testing.T) {
	// Cache with only 3 entries
	c := NewCacheManager(3, time.Minute, time.Minute)

	c.Set("a.com.", dns.TypeA, makeResponse("a.com", dns.TypeA, dns.RcodeSuccess, 60))
	c.Set("b.com.", dns.TypeA, makeResponse("b.com", dns.TypeA, dns.RcodeSuccess, 60))
	c.Set("c.com.", dns.TypeA, makeResponse("c.com", dns.TypeA, dns.RcodeSuccess, 60))

	// Mark a.com as most recently used
	_ = c.Get("a.com.", dns.TypeA)
	// Also touch b.com
	_ = c.Get("b.com.", dns.TypeA)

	// New entry forces eviction (c.com was least recently used)
	c.Set("d.com.", dns.TypeA, makeResponse("d.com", dns.TypeA, dns.RcodeSuccess, 60))

	if c.Get("d.com.", dns.TypeA) == nil {
		t.Error("newly added entry d.com not in cache")
	}
	// Total entries must not exceed maxEntries
	c.mu.Lock()
	count := len(c.entries)
	c.mu.Unlock()
	if count > 3 {
		t.Errorf("cache has %d entries, expected <= 3", count)
	}
}

func TestCacheManager_Clean(t *testing.T) {
	c := NewCacheManager(100, time.Minute, time.Minute)

	c.Set("fresh.com.", dns.TypeA, makeResponse("fresh.com", dns.TypeA, dns.RcodeSuccess, 60))
	c.Set("stale.com.", dns.TypeA, makeResponse("stale.com", dns.TypeA, dns.RcodeSuccess, 60))

	// Expire stale.com
	c.mu.Lock()
	key := cacheKey("stale.com.", dns.TypeA)
	c.entries[key].expiresAt = time.Now().Add(-time.Second)
	c.mu.Unlock()

	c.Clean()

	if c.Get("fresh.com.", dns.TypeA) == nil {
		t.Error("fresh.com should still be in cache")
	}
	if c.Get("stale.com.", dns.TypeA) != nil {
		t.Error("stale.com should be removed after Clean")
	}
}

func TestCacheManager_Stats(t *testing.T) {
	c := NewCacheManager(100, time.Minute, time.Minute)

	c.Set("example.com.", dns.TypeA, makeResponse("example.com", dns.TypeA, dns.RcodeSuccess, 60))

	_ = c.Get("example.com.", dns.TypeA) // hit
	_ = c.Get("example.com.", dns.TypeA) // hit
	_ = c.Get("missing.com.", dns.TypeA) // miss

	entries, hits, misses, hitRate := c.Stats()

	if entries != 1 {
		t.Errorf("expected 1 entry, got %d", entries)
	}
	if hits != 2 {
		t.Errorf("expected 2 hits, got %d", hits)
	}
	if misses != 1 {
		t.Errorf("expected 1 miss, got %d", misses)
	}
	if hitRate < 66 || hitRate > 67 {
		t.Errorf("expected ~66.67%% hit rate, got %.2f%%", hitRate)
	}
}

func TestCacheManager_ConcurrentAccess(t *testing.T) {
	c := NewCacheManager(1000, time.Minute, time.Minute)
	resp := makeResponse("example.com", dns.TypeA, dns.RcodeSuccess, 60)

	var wg sync.WaitGroup

	// Concurrent writes
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Set("example.com.", dns.TypeA, resp)
		}()
	}

	// Concurrent reads
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = c.Get("example.com.", dns.TypeA)
		}()
	}

	wg.Wait()
}

func TestCacheManager_DetermineTTL_UsesMinimum(t *testing.T) {
	c := NewCacheManager(100, time.Hour, time.Minute)

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Response = true
	m.Rcode = dns.RcodeSuccess
	m.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}},
		&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}},
	}

	ttl := c.determineTTL(m)
	if ttl != 60*time.Second {
		t.Errorf("expected TTL 60s (minimum), got %s", ttl)
	}
}

func TestCacheManager_ResponseIsCopied(t *testing.T) {
	c := NewCacheManager(100, time.Minute, time.Minute)

	resp := makeResponse("example.com", dns.TypeA, dns.RcodeSuccess, 60)
	c.Set("example.com.", dns.TypeA, resp)

	got1 := c.Get("example.com.", dns.TypeA)
	got2 := c.Get("example.com.", dns.TypeA)

	if got1 == got2 {
		t.Error("Get should return copies, not the same reference")
	}
	// Mutating the first copy must not affect the second
	got1.Id = 9999
	if got2.Id == 9999 {
		t.Error("mutating one copy affected the other - not a real copy")
	}
}
