package dnsserver

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestNetworkACL_NilAndEmptyAllowAll(t *testing.T) {
	var nilACL *networkACL
	if !nilACL.Allows(net.ParseIP("203.0.113.9")) {
		t.Error("nil ACL must allow every client")
	}
	empty := &networkACL{}
	if !empty.Allows(net.ParseIP("203.0.113.9")) {
		t.Error("empty ACL must allow every client")
	}
}

func TestNetworkACL_AllowsInsideRefusesOutside(t *testing.T) {
	acl := &networkACL{nets: parseNetworks(
		[]string{"192.168.42.0/24", "2001:db8::/32", "203.0.113.5"},
		"test",
	)}

	cases := []struct {
		ip      string
		allowed bool
	}{
		{"192.168.42.10", true},        // inside IPv4 CIDR
		{"192.168.101.10", false},       // outside IPv4 CIDR
		{"2001:db8::1", true},           // inside IPv6 CIDR
		{"2001:dead::1", false},         // outside IPv6 CIDR
		{"203.0.113.5", true},           // bare IPv4
		{"203.0.113.6", false},          // outside bare IPv4
		{"::ffff:192.168.42.10", true}, // IPv4-mapped, same subnet
	}
	for _, c := range cases {
		if got := acl.Allows(net.ParseIP(c.ip)); got != c.allowed {
			t.Errorf("Allows(%s) = %v, want %v", c.ip, got, c.allowed)
		}
	}
}

// TestHandler_AccessControlRefused verifies the end-to-end hook: a client
// outside allowed_networks gets REFUSED, while an allowed client reaches the
// pipeline (SERVFAIL with the empty test forwarder).
func TestHandler_AccessControlRefused(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil, "0.0.0.0", "::", nil, false)
	h.SetAccessControl(parseNetworks([]string{"192.0.2.0/24"}, "test"))

	allowed := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("192.0.2.5"), Port: 1234}}
	h.ServeDNS(allowed, makeQuery("example.com", dns.TypeA))
	if allowed.written == nil {
		t.Fatal("allowed client must get a response")
	}
	if allowed.written.Rcode == dns.RcodeRefused {
		t.Fatal("allowed client must not be refused")
	}

	denied := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("198.51.100.5"), Port: 1234}}
	h.ServeDNS(denied, makeQuery("example.com", dns.TypeA))
	if denied.written == nil {
		t.Fatal("denied client must get a REFUSED response")
	}
	if denied.written.Rcode != dns.RcodeRefused {
		t.Fatalf("expected REFUSED for denied client, got %d", denied.written.Rcode)
	}
}

// TestHandler_AccessControl_ACMEChallengeBypass verifies that an *active* ACME
// DNS-01 challenge is served even to a client outside allowed_networks (the
// certificate authority's public resolvers cannot be allowlisted in advance),
// while every other query from that client stays refused.
func TestHandler_AccessControl_ACMEChallengeBypass(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil, "0.0.0.0", "::", nil, false)
	h.acme = &mockACMEReader{entries: map[string]string{
		"_acme-challenge.example.com.": "TOKEN123",
	}}
	h.SetAccessControl(parseNetworks([]string{"192.0.2.0/24"}, "test"))

	external := func() *mockRWWithAddr {
		return &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 5353}}
	}

	// Active challenge must bypass the ACL.
	w := external()
	h.ServeDNS(w, newQuery("_acme-challenge.example.com.", dns.TypeTXT))
	if w.written == nil || w.written.Rcode != dns.RcodeSuccess || len(w.written.Answer) != 1 {
		t.Fatalf("active ACME challenge must bypass ACL, got %+v", w.written)
	}

	// Unknown challenge name must still be refused (no public open resolver).
	w2 := external()
	h.ServeDNS(w2, newQuery("_acme-challenge.unknown.example.org.", dns.TypeTXT))
	if w2.written == nil || w2.written.Rcode != dns.RcodeRefused {
		t.Fatalf("unknown challenge must be refused, got %+v", w2.written)
	}

	// A normal query must still be refused.
	w3 := external()
	h.ServeDNS(w3, newQuery("example.com.", dns.TypeA))
	if w3.written == nil || w3.written.Rcode != dns.RcodeRefused {
		t.Fatalf("normal query must be refused, got %+v", w3.written)
	}
}

// TestHandler_NoAccessControlAllowsAll ensures the default (no allowlist)
// leaves the query path unchanged.
func TestHandler_NoAccessControlAllowsAll(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil, "0.0.0.0", "::", nil, false)
	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("198.51.100.5"), Port: 1234}}
	h.ServeDNS(rw, makeQuery("example.com", dns.TypeA))
	if rw.written == nil || rw.written.Rcode == dns.RcodeRefused {
		t.Fatal("without allowed_networks the client must not be refused")
	}
}

// TestServer_UpdateAccessControlConcurrent swaps the allowlist at runtime while
// queries are served. Run with -race; it must not report a data race.
func TestServer_UpdateAccessControlConcurrent(t *testing.T) {
	srv := New(Config{Listen: "127.0.0.1:0", TCPTimeout: time.Second})
	h := srv.GetHandler()

	stop := make(chan struct{})
	var wg sync.WaitGroup

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

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			srv.UpdateAccessControl([]string{"192.0.2.0/24"})
			srv.UpdateAccessControl(nil)
		}
		close(stop)
	}()

	wg.Wait()
}
