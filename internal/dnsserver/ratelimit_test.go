package dnsserver

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

func TestNewQueryRateLimiter_Disabled(t *testing.T) {
	if lim := NewQueryRateLimiter(0, nil); lim != nil {
		t.Fatalf("NewQueryRateLimiter(0) = %v, want nil", lim)
	}
	if lim := NewQueryRateLimiter(-5, nil); lim != nil {
		t.Fatalf("NewQueryRateLimiter(-5) = %v, want nil", lim)
	}
	// A nil limiter must allow everything and Stop must be a no-op.
	var nilLim *QueryRateLimiter
	if !nilLim.Allow(net.ParseIP("192.0.2.1")) {
		t.Error("nil limiter must allow queries")
	}
	nilLim.Stop() // must not panic
}

func TestQueryRateLimiter_AllowsBurstThenRefuses(t *testing.T) {
	lim := NewQueryRateLimiter(3, nil)
	defer lim.Stop()
	ip := net.ParseIP("192.0.2.10")

	for i := 0; i < 3; i++ {
		if !lim.Allow(ip) {
			t.Fatalf("query %d within burst must be allowed", i+1)
		}
	}
	if lim.Allow(ip) {
		t.Fatal("query beyond burst must be refused")
	}
}

func TestQueryRateLimiter_PerClientIsolation(t *testing.T) {
	lim := NewQueryRateLimiter(2, nil)
	defer lim.Stop()

	a := net.ParseIP("192.0.2.1")
	b := net.ParseIP("192.0.2.2")

	first := lim.Allow(a)
	second := lim.Allow(a)
	if !first || !second {
		t.Fatal("first two queries from A must be allowed")
	}
	if lim.Allow(a) {
		t.Fatal("third query from A must be refused")
	}
	// B has its own bucket and must be unaffected.
	if !lim.Allow(b) {
		t.Fatal("query from B must be allowed despite A being limited")
	}
}

func TestQueryRateLimiter_IPv6Key(t *testing.T) {
	lim := NewQueryRateLimiter(1, nil)
	defer lim.Stop()
	ip := net.ParseIP("2001:db8::1")
	if !lim.Allow(ip) {
		t.Fatal("first IPv6 query must be allowed")
	}
	if lim.Allow(ip) {
		t.Fatal("second IPv6 query must be refused")
	}
}

// TestQueryRateLimiter_IPv4MappedIPv6SharedBucket verifies that a client that
// arrives as ::ffff:a.b.c.d and one that arrives as a.b.c.d share one bucket
// (dual-stack listeners may report the mapped form).
func TestQueryRateLimiter_IPv4MappedIPv6SharedBucket(t *testing.T) {
	lim := NewQueryRateLimiter(1, nil)
	defer lim.Stop()

	plain := net.ParseIP("192.0.2.77")
	mapped := net.ParseIP("::ffff:192.0.2.77")
	// Both must normalise to the same string key.
	if plain.String() != mapped.String() {
		t.Fatalf("test premise broken: %q != %q", plain.String(), mapped.String())
	}

	if !lim.Allow(plain) {
		t.Fatal("first query (plain IPv4) must be allowed")
	}
	if lim.Allow(mapped) {
		t.Fatal("second query (IPv4-mapped) must share the bucket and be refused")
	}
}

func TestQueryRateLimiter_ExemptNetworks(t *testing.T) {
	lim := NewQueryRateLimiter(1, []string{"192.168.42.0/24", "203.0.113.5"})
	defer lim.Stop()

	router := net.ParseIP("192.168.42.1") // inside CIDR
	single := net.ParseIP("203.0.113.5")   // bare IP
	other := net.ParseIP("198.51.100.1")   // not exempt

	for i := 0; i < 10; i++ {
		if !lim.Allow(router) {
			t.Fatalf("exempt router (CIDR) query %d must always be allowed", i+1)
		}
		if !lim.Allow(single) {
			t.Fatalf("exempt bare-IP query %d must always be allowed", i+1)
		}
	}
	// Non-exempt client is still limited.
	if !lim.Allow(other) {
		t.Fatal("non-exempt client must be allowed once")
	}
	if lim.Allow(other) {
		t.Fatal("non-exempt client must be refused beyond the bucket")
	}
}

func TestParseNetworks_InvalidEntriesIgnored(t *testing.T) {
	nets := parseNetworks([]string{"", "   ", "not-an-ip", "10.0.0.0/8"}, "test")
	if len(nets) != 1 {
		t.Fatalf("expected only the valid network to survive, got %d", len(nets))
	}
	if !nets[0].Contains(net.ParseIP("10.1.2.3")) {
		t.Error("10.0.0.0/8 must contain 10.1.2.3")
	}
}

func TestQueryRateLimiter_StopIdempotent(t *testing.T) {
	lim := NewQueryRateLimiter(60, nil)
	lim.Stop()
	lim.Stop() // must not panic (sync.Once)

	// Allow must remain functional after Stop (only cleanup stops).
	if !lim.Allow(net.ParseIP("198.51.100.1")) {
		t.Error("Allow must still work after Stop")
	}
}

// TestHandler_RateLimitRefused verifies the end-to-end hook: a client that
// exceeds its allowance gets REFUSED (instead of SERVFAIL from the empty
// forwarder), while a second client remains unaffected.
func TestHandler_RateLimitRefused(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil, "0.0.0.0", "::", nil, false)
	h.SetRateLimiter(NewQueryRateLimiter(2, nil))
	defer h.SetRateLimiter(nil)

	limitedIP := &net.UDPAddr{IP: net.ParseIP("192.0.2.50"), Port: 1234}

	// First two queries pass the limiter → reach the (empty) forwarder → SERVFAIL.
	for i := 0; i < 2; i++ {
		rw := &mockRWWithAddr{addr: limitedIP}
		h.ServeDNS(rw, makeQuery("example.com", dns.TypeA))
		if rw.written == nil {
			t.Fatalf("query %d: expected a response", i+1)
		}
		if rw.written.Rcode == dns.RcodeRefused {
			t.Fatalf("query %d within allowance must not be refused", i+1)
		}
	}

	// Third query exceeds the bucket → REFUSED before reaching the pipeline.
	rw := &mockRWWithAddr{addr: limitedIP}
	h.ServeDNS(rw, makeQuery("example.com", dns.TypeA))
	if rw.written == nil {
		t.Fatal("expected REFUSED response")
	}
	if rw.written.Rcode != dns.RcodeRefused {
		t.Fatalf("expected REFUSED when rate limited, got %d", rw.written.Rcode)
	}

	// A different client must not be affected.
	other := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("192.0.2.51"), Port: 1234}}
	h.ServeDNS(other, makeQuery("example.com", dns.TypeA))
	if other.written == nil || other.written.Rcode == dns.RcodeRefused {
		t.Fatal("unrelated client must not be rate limited")
	}
}

// TestHandler_NoRateLimiterNoRefusal ensures that without a limiter (default)
// the query path is unchanged.
func TestHandler_NoRateLimiterNoRefusal(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil, "0.0.0.0", "::", nil, false)
	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("192.0.2.99"), Port: 1234}}
	h.ServeDNS(rw, makeQuery("example.com", dns.TypeA))
	if rw.written == nil {
		t.Fatal("expected a response")
	}
	if rw.written.Rcode == dns.RcodeRefused {
		t.Fatal("no limiter configured → must not be REFUSED")
	}
}

// TestQueryRateLimiter_Refill verifies tokens are replenished over time. A
// limiter with a 5 ms refill interval is built directly to keep the test fast.
func TestQueryRateLimiter_Refill(t *testing.T) {
	lim := &QueryRateLimiter{
		limiters: make(map[string]*rateLimitEntry),
		qps:      rate.Every(5 * time.Millisecond),
		burst:    1,
		stopCh:   make(chan struct{}),
	}
	defer lim.Stop()
	ip := net.ParseIP("203.0.113.7")

	if !lim.Allow(ip) {
		t.Fatal("first query must be allowed")
	}
	if lim.Allow(ip) {
		t.Fatal("second immediate query must be refused")
	}
	time.Sleep(20 * time.Millisecond)
	if !lim.Allow(ip) {
		t.Fatal("query after refill must be allowed")
	}
}

// TestServer_UpdateRateLimitConcurrent swaps the limiter at runtime while
// queries are served. Run with -race; it must not report a data race.
func TestServer_UpdateRateLimitConcurrent(t *testing.T) {
	srv := New(Config{Listen: "127.0.0.1:0", TCPTimeout: time.Second})
	h := srv.GetHandler()
	defer srv.UpdateRateLimit(false, 0, nil)

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Queries in flight.
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ip := &net.UDPAddr{IP: net.ParseIP("192.0.2." + string(rune('1'+id))), Port: 1234}
			for {
				select {
				case <-stop:
					return
				default:
					h.ServeDNS(&mockRWWithAddr{addr: ip}, makeQuery("example.com", dns.TypeA))
				}
			}
		}(g)
	}

	// Runtime reconfiguration.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			srv.UpdateRateLimit(true, 100, []string{"10.0.0.0/8"})
			srv.UpdateRateLimit(false, 0, nil)
		}
		close(stop)
	}()

	wg.Wait()
}
