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

// --- TTL decrement tests ---

func TestDecrementTTLs_Basic(t *testing.T) {
	msg := makeResponse("example.com", dns.TypeA, dns.RcodeSuccess, 300)
	original := msg.Answer[0].Header().Ttl

	// Zero elapsed: TTL unchanged, returns copy
	got := decrementTTLs(msg, 0)
	if got == msg {
		t.Error("decrementTTLs with 0 elapsed should still return a copy")
	}
	if got.Answer[0].Header().Ttl != original {
		t.Errorf("zero elapsed: expected TTL=%d, got %d", original, got.Answer[0].Header().Ttl)
	}

	// 100s elapsed: TTL becomes 200
	got = decrementTTLs(msg, 100*time.Second)
	if got.Answer[0].Header().Ttl != 200 {
		t.Errorf("100s elapsed: expected TTL=200, got %d", got.Answer[0].Header().Ttl)
	}

	// 300s elapsed: TTL floors at 1
	got = decrementTTLs(msg, 300*time.Second)
	if got.Answer[0].Header().Ttl != 1 {
		t.Errorf("300s elapsed: expected TTL=1 (floor), got %d", got.Answer[0].Header().Ttl)
	}

	// 500s elapsed: TTL also floors at 1
	got = decrementTTLs(msg, 500*time.Second)
	if got.Answer[0].Header().Ttl != 1 {
		t.Errorf("500s elapsed: expected TTL=1 (floor), got %d", got.Answer[0].Header().Ttl)
	}

	// Original message must not be mutated
	if msg.Answer[0].Header().Ttl != original {
		t.Error("decrementTTLs must not mutate the original message")
	}
}

func TestDecrementTTLs_OPTSkipped(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Response = true
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.Hdr.Ttl = 12345 // extended RCODE + flags, not a real TTL
	msg.Extra = append(msg.Extra, opt)

	got := decrementTTLs(msg, 60*time.Second)
	for _, rr := range got.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			if rr.Header().Ttl != 12345 {
				t.Errorf("OPT TTL must not be decremented: expected 12345, got %d", rr.Header().Ttl)
			}
		}
	}
}

func TestDecrementTTLs_AllSections(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Response = true
	rr := func(name string, rrtype uint16, ttl uint32) dns.RR {
		return &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: rrtype, Class: dns.ClassINET, Ttl: ttl},
			A:   []byte{1, 2, 3, 4},
		}
	}
	msg.Answer = []dns.RR{rr("example.com.", dns.TypeA, 300)}
	msg.Ns = []dns.RR{rr("example.com.", dns.TypeA, 600)}
	msg.Extra = []dns.RR{rr("example.com.", dns.TypeA, 120)}

	got := decrementTTLs(msg, 100*time.Second)

	if got.Answer[0].Header().Ttl != 200 {
		t.Errorf("Answer TTL: expected 200, got %d", got.Answer[0].Header().Ttl)
	}
	if got.Ns[0].Header().Ttl != 500 {
		t.Errorf("Ns TTL: expected 500, got %d", got.Ns[0].Header().Ttl)
	}
	if got.Extra[0].Header().Ttl != 20 {
		t.Errorf("Extra TTL: expected 20, got %d", got.Extra[0].Header().Ttl)
	}
}

func TestCacheManager_Get_TTLDecrement(t *testing.T) {
	c := NewCacheManager(100, time.Minute, time.Minute)

	resp := makeResponse("example.com", dns.TypeA, dns.RcodeSuccess, 300)
	c.Set("example.com.", dns.TypeA, resp)

	// Rewind cachedAt by 100s to simulate time passing
	c.mu.Lock()
	key := cacheKey("example.com.", dns.TypeA)
	c.entries[key].cachedAt = time.Now().Add(-100 * time.Second)
	c.mu.Unlock()

	got := c.Get("example.com.", dns.TypeA)
	if got == nil {
		t.Fatal("expected cached response")
	}
	ttl := got.Answer[0].Header().Ttl
	// Should be approximately 200 (300 - 100), allow ±2s for timing
	if ttl < 198 || ttl > 202 {
		t.Errorf("expected TTL ~200 after 100s elapsed, got %d", ttl)
	}
}

// --- Flush tests ---

func TestCacheManager_Flush(t *testing.T) {
	c := NewCacheManager(100, time.Minute, time.Minute)

	c.Set("a.com.", dns.TypeA, makeResponse("a.com", dns.TypeA, dns.RcodeSuccess, 60))
	c.Set("b.com.", dns.TypeA, makeResponse("b.com", dns.TypeA, dns.RcodeSuccess, 60))
	_ = c.Get("a.com.", dns.TypeA) // register a hit

	c.Flush()

	entries, hits, misses, _ := c.Stats()
	if entries != 0 {
		t.Errorf("after Flush: expected 0 entries, got %d", entries)
	}
	if hits != 0 {
		t.Errorf("after Flush: expected 0 hits, got %d", hits)
	}
	if misses != 0 {
		t.Errorf("after Flush: expected 0 misses, got %d", misses)
	}

	if c.Get("a.com.", dns.TypeA) != nil {
		t.Error("after Flush: a.com should not be in cache")
	}
	if c.Get("b.com.", dns.TypeA) != nil {
		t.Error("after Flush: b.com should not be in cache")
	}
}

// --- Delete tests ---

func TestCacheManager_Delete_Existing(t *testing.T) {
	c := NewCacheManager(100, time.Minute, time.Minute)

	c.Set("example.com.", dns.TypeA, makeResponse("example.com", dns.TypeA, dns.RcodeSuccess, 60))

	deleted := c.Delete("example.com.", dns.TypeA)
	if !deleted {
		t.Error("Delete should return true for existing entry")
	}
	if c.Get("example.com.", dns.TypeA) != nil {
		t.Error("entry should not be in cache after Delete")
	}
}

func TestCacheManager_Delete_NonExistent(t *testing.T) {
	c := NewCacheManager(100, time.Minute, time.Minute)

	deleted := c.Delete("notexist.com.", dns.TypeA)
	if deleted {
		t.Error("Delete should return false for non-existent entry")
	}
}

// --- Entries tests ---

func TestCacheManager_Entries_Limit(t *testing.T) {
	c := NewCacheManager(1000, time.Minute, time.Minute)

	for i := 0; i < 600; i++ {
		name := "host" + string(rune('a'+i%26)) + "x" + string(rune('0'+i/26)) + ".com."
		c.Set(name, dns.TypeA, makeResponse(name, dns.TypeA, dns.RcodeSuccess, 60))
	}

	limited := c.Entries(500)
	if len(limited) != 500 {
		t.Errorf("Entries(500): expected 500, got %d", len(limited))
	}

	all := c.Entries(0)
	if len(all) != 600 {
		t.Errorf("Entries(0): expected 600, got %d", len(all))
	}
}

func TestCacheManager_Entries_SortedByTTL(t *testing.T) {
	c := NewCacheManager(100, time.Minute, time.Minute)

	c.Set("fast.com.", dns.TypeA, makeResponse("fast.com", dns.TypeA, dns.RcodeSuccess, 60))
	c.Set("medium.com.", dns.TypeA, makeResponse("medium.com", dns.TypeA, dns.RcodeSuccess, 60))
	c.Set("slow.com.", dns.TypeA, makeResponse("slow.com", dns.TypeA, dns.RcodeSuccess, 60))

	// Manually set different expiresAt values
	c.mu.Lock()
	now := time.Now()
	c.entries[cacheKey("fast.com.", dns.TypeA)].expiresAt = now.Add(5 * time.Second)
	c.entries[cacheKey("medium.com.", dns.TypeA)].expiresAt = now.Add(30 * time.Second)
	c.entries[cacheKey("slow.com.", dns.TypeA)].expiresAt = now.Add(60 * time.Second)
	c.mu.Unlock()

	infos := c.Entries(0)
	if len(infos) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(infos))
	}
	if infos[0].RemainingTTL > infos[1].RemainingTTL || infos[1].RemainingTTL > infos[2].RemainingTTL {
		t.Errorf("entries not sorted by TTL ascending: %v", []int{infos[0].RemainingTTL, infos[1].RemainingTTL, infos[2].RemainingTTL})
	}
}

func TestCacheManager_Entries_ExcludesExpired(t *testing.T) {
	c := NewCacheManager(100, time.Minute, time.Minute)

	c.Set("fresh.com.", dns.TypeA, makeResponse("fresh.com", dns.TypeA, dns.RcodeSuccess, 60))
	c.Set("expired.com.", dns.TypeA, makeResponse("expired.com", dns.TypeA, dns.RcodeSuccess, 60))

	// Manually expire one entry (without removing it — simulates race with cleanup)
	c.mu.Lock()
	c.entries[cacheKey("expired.com.", dns.TypeA)].expiresAt = time.Now().Add(-time.Second)
	c.mu.Unlock()

	infos := c.Entries(0)
	if len(infos) != 1 {
		t.Errorf("expected 1 non-expired entry, got %d", len(infos))
	}
	if len(infos) > 0 && infos[0].Name != "fresh.com." {
		t.Errorf("expected fresh.com in entries, got %s", infos[0].Name)
	}
}
