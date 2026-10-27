package dnsserver

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	dnsinternal "github.com/mw7101/domudns/internal/dns"
	"github.com/miekg/dns"
)

// newCNAMEHandler builds a handler with the given zones loaded and the given
// upstream servers. Tests whose targets are all local pass an unreachable local
// address (127.0.0.1:1) so a regression cannot leak queries to the internet.
func newCNAMEHandler(t *testing.T, upstream []string, zones ...*dnsinternal.Zone) *Handler {
	t.Helper()
	zm := NewZoneManager()
	loadZonesManually(zm, zones...)
	return NewHandler(upstream, nil, zm, nil, "0.0.0.0", "::", nil, false)
}

// fakeUpstream starts a local DNS server answering A queries from answers
// (qname → IP) and counts the queries it received.
func fakeUpstream(t *testing.T, answers map[string]string) (string, *atomic.Int32) {
	t.Helper()
	return startFakeUpstream(t, answers, nil)
}

// startFakeUpstream is fakeUpstream with an optional observer that sees every
// request the server received — used to assert what was actually sent upstream
// (e.g. the DNSSEC DO bit).
func startFakeUpstream(t *testing.T, answers map[string]string, observe func(*dns.Msg)) (string, *atomic.Int32) {
	t.Helper()
	var queries atomic.Int32
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		queries.Add(1)
		if observe != nil {
			observe(r.Copy())
		}
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 {
			q := r.Question[0]
			ip, known := answers[q.Name]
			switch {
			case q.Qtype != dns.TypeA:
				// The fake zone holds A records only: anything else is NODATA.
			case known:
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP(ip),
				})
			default:
				m.Rcode = dns.RcodeNameError
			}
		}
		if err := w.WriteMsg(m); err != nil {
			t.Errorf("fake upstream: write response: %v", err)
		}
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String(), &queries
}

// intAndClnZones mirrors the production layout that triggered the bug: the
// service name lives in example.local as a CNAME into the cln zone.
func intAndClnZones() (*dnsinternal.Zone, *dnsinternal.Zone) {
	intZone := &dnsinternal.Zone{
		Domain: "example.local",
		TTL:    300,
		Records: []dnsinternal.Record{
			{ID: 1, Name: "s3-ext", Type: dnsinternal.TypeCNAME, TTL: 300, Value: "minio.cln.example.local"},
		},
	}
	clnZone := &dnsinternal.Zone{
		Domain: "cln.example.local",
		TTL:    300,
		Records: []dnsinternal.Record{
			{ID: 1, Name: "minio", Type: dnsinternal.TypeA, TTL: 86400, Value: "192.168.101.5"},
		},
	}
	return intZone, clnZone
}

// TestCNAMEPhase_CrossZoneTarget_AppendsTargetA is the regression test for the
// production failure: s3-ext.example.local is a CNAME into the cln zone, so
// the answer used to carry only the CNAME and musl/glibc clients reported
// "bad address". The target's A record must now be appended.
func TestCNAMEPhase_CrossZoneTarget_AppendsTargetA(t *testing.T) {
	intZone, clnZone := intAndClnZones()
	h := newCNAMEHandler(t, []string{"127.0.0.1:1"}, intZone, clnZone)

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("192.168.42.145"), Port: 1234}}
	h.ServeDNS(rw, makeQuery("s3-ext.example.local", dns.TypeA))

	if rw.written == nil {
		t.Fatal("no response written")
	}
	if rw.written.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", rw.written.Rcode)
	}
	if len(rw.written.Answer) != 2 {
		t.Fatalf("answer count = %d, want 2 (CNAME + A): %v", len(rw.written.Answer), rw.written.Answer)
	}
	if _, ok := rw.written.Answer[0].(*dns.CNAME); !ok {
		t.Fatalf("answer[0] type = %T, want *dns.CNAME", rw.written.Answer[0])
	}
	a, ok := rw.written.Answer[1].(*dns.A)
	if !ok {
		t.Fatalf("answer[1] type = %T, want *dns.A", rw.written.Answer[1])
	}
	if a.A.String() != "192.168.101.5" {
		t.Errorf("A = %s, want 192.168.101.5", a.A)
	}
	if a.Hdr.Name != "minio.cln.example.local." {
		t.Errorf("A owner = %q, want the canonical name \"minio.cln.example.local.\"", a.Hdr.Name)
	}
}

// TestCNAMEPhase_ChainAcrossThreeZones verifies that a chain crossing more than
// two local zones is followed to its end.
func TestCNAMEPhase_ChainAcrossThreeZones(t *testing.T) {
	z1 := &dnsinternal.Zone{Domain: "a.example.com", TTL: 300, Records: []dnsinternal.Record{
		{ID: 1, Name: "www", Type: dnsinternal.TypeCNAME, TTL: 300, Value: "hop.b.example.com"},
	}}
	z2 := &dnsinternal.Zone{Domain: "b.example.com", TTL: 300, Records: []dnsinternal.Record{
		{ID: 1, Name: "hop", Type: dnsinternal.TypeCNAME, TTL: 300, Value: "final.c.example.com"},
	}}
	z3 := &dnsinternal.Zone{Domain: "c.example.com", TTL: 300, Records: []dnsinternal.Record{
		{ID: 1, Name: "final", Type: dnsinternal.TypeA, TTL: 300, Value: "10.9.9.9"},
	}}
	h := newCNAMEHandler(t, []string{"127.0.0.1:1"}, z1, z2, z3)

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}
	h.ServeDNS(rw, makeQuery("www.a.example.com", dns.TypeA))

	if rw.written == nil {
		t.Fatal("no response written")
	}
	if len(rw.written.Answer) != 3 {
		t.Fatalf("answer count = %d, want 3 (CNAME, CNAME, A): %v", len(rw.written.Answer), rw.written.Answer)
	}
	a, ok := rw.written.Answer[2].(*dns.A)
	if !ok {
		t.Fatalf("answer[2] type = %T, want *dns.A", rw.written.Answer[2])
	}
	if a.A.String() != "10.9.9.9" {
		t.Errorf("A = %s, want 10.9.9.9", a.A)
	}
}

// TestCNAMEPhase_UpstreamTarget_AppendsUpstreamA verifies the forwarder fallback:
// a target that is in no local zone is resolved upstream, so the client receives
// the address instead of a bare CNAME.
func TestCNAMEPhase_UpstreamTarget_AppendsUpstreamA(t *testing.T) {
	upstream, queries := fakeUpstream(t, map[string]string{"target.external.example.": "203.0.113.7"})
	zone := &dnsinternal.Zone{Domain: "example.com", TTL: 300, Records: []dnsinternal.Record{
		{ID: 1, Name: "alias", Type: dnsinternal.TypeCNAME, TTL: 300, Value: "target.external.example"},
	}}
	h := newCNAMEHandler(t, []string{upstream}, zone)

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}
	h.ServeDNS(rw, makeQuery("alias.example.com", dns.TypeA))

	if rw.written == nil {
		t.Fatal("no response written")
	}
	if len(rw.written.Answer) != 2 {
		t.Fatalf("answer count = %d, want 2 (CNAME + upstream A): %v", len(rw.written.Answer), rw.written.Answer)
	}
	a, ok := rw.written.Answer[1].(*dns.A)
	if !ok {
		t.Fatalf("answer[1] type = %T, want *dns.A", rw.written.Answer[1])
	}
	if a.A.String() != "203.0.113.7" {
		t.Errorf("A = %s, want 203.0.113.7", a.A)
	}
	if got := queries.Load(); got != 1 {
		t.Errorf("upstream queries = %d, want 1", got)
	}
}

// TestCNAMEPhase_UpstreamTarget_NonAddressQuery_NoUpstreamCall verifies that
// non-address queries keep the previous behavior: CNAME returned, no upstream
// query (the client follows the chain itself for TXT/MX/…).
func TestCNAMEPhase_UpstreamTarget_NonAddressQuery_NoUpstreamCall(t *testing.T) {
	upstream, queries := fakeUpstream(t, map[string]string{"target.external.example.": "203.0.113.7"})
	zone := &dnsinternal.Zone{Domain: "example.com", TTL: 300, Records: []dnsinternal.Record{
		{ID: 1, Name: "alias", Type: dnsinternal.TypeCNAME, TTL: 300, Value: "target.external.example"},
	}}
	h := newCNAMEHandler(t, []string{upstream}, zone)

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}
	h.ServeDNS(rw, makeQuery("alias.example.com", dns.TypeTXT))

	if rw.written == nil {
		t.Fatal("no response written")
	}
	if len(rw.written.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1 (CNAME only): %v", len(rw.written.Answer), rw.written.Answer)
	}
	if got := queries.Load(); got != 0 {
		t.Errorf("upstream queries = %d, want 0 for a non-address query", got)
	}
}

// TestCNAMEPhase_CrossZoneLoop_Terminates verifies the loop guard for two zones
// pointing at each other: the response is returned (chain, no address), it does
// not spin and it does not reach the forwarder.
func TestCNAMEPhase_CrossZoneLoop_Terminates(t *testing.T) {
	intZone := &dnsinternal.Zone{Domain: "example.local", TTL: 300, Records: []dnsinternal.Record{
		{ID: 1, Name: "a", Type: dnsinternal.TypeCNAME, TTL: 300, Value: "b.cln.example.local"},
	}}
	clnZone := &dnsinternal.Zone{Domain: "cln.example.local", TTL: 300, Records: []dnsinternal.Record{
		{ID: 1, Name: "b", Type: dnsinternal.TypeCNAME, TTL: 300, Value: "a.example.local"},
	}}
	upstream, queries := fakeUpstream(t, nil)
	h := newCNAMEHandler(t, []string{upstream}, intZone, clnZone)

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}
	h.ServeDNS(rw, makeQuery("a.example.local", dns.TypeA))

	if rw.written == nil {
		t.Fatal("no response written")
	}
	for _, rr := range rw.written.Answer {
		if _, ok := rr.(*dns.A); ok {
			t.Fatalf("CNAME loop must not produce an A record: %v", rw.written.Answer)
		}
	}
	if got := queries.Load(); got != 0 {
		t.Errorf("upstream queries = %d, want 0 (every name is a local zone)", got)
	}
}

// TestCNAMEPhase_UpstreamTarget_RebindingBlocked verifies that a chased upstream
// answer passes phase 5.5: a public canonical name resolving to a private IP is
// blocked with NXDOMAIN, exactly as the plain forward path would block it.
// Without this the CNAME would be a rebinding bypass — the plain query is
// blocked, the chased one is not.
func TestCNAMEPhase_UpstreamTarget_RebindingBlocked(t *testing.T) {
	upstream, _ := fakeUpstream(t, map[string]string{"target.external.example.": "10.0.0.5"})
	zone := &dnsinternal.Zone{Domain: "example.com", TTL: 300, Records: []dnsinternal.Record{
		{ID: 1, Name: "alias", Type: dnsinternal.TypeCNAME, TTL: 300, Value: "target.external.example"},
	}}
	h := newCNAMEHandler(t, []string{upstream}, zone)
	h.rebinding.Update(true, nil)

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}
	h.ServeDNS(rw, makeQuery("alias.example.com", dns.TypeA))

	if rw.written == nil {
		t.Fatal("no response written")
	}
	if rw.written.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN (rebinding blocked)", rw.written.Rcode)
	}
	for _, rr := range rw.written.Answer {
		if _, ok := rr.(*dns.A); ok {
			t.Fatalf("blocked response must not carry the private A record: %v", rw.written.Answer)
		}
	}
}

// TestCNAMEPhase_UpstreamTarget_PrivateIPAllowedWhenProtectionOff pins the
// boundary: with rebinding protection disabled the same answer passes through,
// so the test above really measures the check and not general strictness.
func TestCNAMEPhase_UpstreamTarget_PrivateIPAllowedWhenProtectionOff(t *testing.T) {
	upstream, _ := fakeUpstream(t, map[string]string{"target.external.example.": "10.0.0.5"})
	zone := &dnsinternal.Zone{Domain: "example.com", TTL: 300, Records: []dnsinternal.Record{
		{ID: 1, Name: "alias", Type: dnsinternal.TypeCNAME, TTL: 300, Value: "target.external.example"},
	}}
	h := newCNAMEHandler(t, []string{upstream}, zone)

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}
	h.ServeDNS(rw, makeQuery("alias.example.com", dns.TypeA))

	if rw.written == nil {
		t.Fatal("no response written")
	}
	if rw.written.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", rw.written.Rcode)
	}
	if len(rw.written.Answer) != 2 {
		t.Fatalf("answer count = %d, want 2 (CNAME + A): %v", len(rw.written.Answer), rw.written.Answer)
	}
}

// TestCNAMEPhase_ChainEndingInAlias_SynthesizesAddress verifies that a chain
// ending on an ALIAS record does not dead-end: the ALIAS stays invisible and its
// records are owned by the ALIAS's name, so the chain remains valid for stub
// resolvers (otherwise this is the same "bad address" failure the phase fixes).
func TestCNAMEPhase_ChainEndingInAlias_SynthesizesAddress(t *testing.T) {
	upstream, _ := fakeUpstream(t, map[string]string{"ext.cdn.example.": "203.0.113.9"})
	zone := &dnsinternal.Zone{Domain: "example.com", TTL: 300, Records: []dnsinternal.Record{
		{ID: 1, Name: "www", Type: dnsinternal.TypeCNAME, TTL: 300, Value: "cdn.example.com"},
		{ID: 2, Name: "cdn", Type: dnsinternal.TypeALIAS, TTL: 300, Value: "ext.cdn.example"},
	}}
	h := newCNAMEHandler(t, []string{upstream}, zone)

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}
	h.ServeDNS(rw, makeQuery("www.example.com", dns.TypeA))

	if rw.written == nil {
		t.Fatal("no response written")
	}
	if len(rw.written.Answer) != 2 {
		t.Fatalf("answer count = %d, want 2 (CNAME + synthesized A): %v", len(rw.written.Answer), rw.written.Answer)
	}
	if _, ok := rw.written.Answer[0].(*dns.CNAME); !ok {
		t.Fatalf("answer[0] type = %T, want *dns.CNAME", rw.written.Answer[0])
	}
	a, ok := rw.written.Answer[1].(*dns.A)
	if !ok {
		t.Fatalf("answer[1] type = %T, want *dns.A (synthesized ALIAS record)", rw.written.Answer[1])
	}
	if a.Hdr.Name != "cdn.example.com." {
		t.Errorf("A owner = %q, want the ALIAS's name \"cdn.example.com.\"", a.Hdr.Name)
	}
	if a.A.String() != "203.0.113.9" {
		t.Errorf("A = %s, want 203.0.113.9", a.A)
	}
}

// TestCNAMEPhase_CachesSynthesizedResponse verifies that the completed chain is
// cached under the queried name, like the ALIAS phase does.
func TestCNAMEPhase_CachesSynthesizedResponse(t *testing.T) {
	intZone, clnZone := intAndClnZones()
	zm := NewZoneManager()
	loadZonesManually(zm, intZone, clnZone)
	cm := NewCacheManager(100, 30*time.Second, 10*time.Second)
	h := NewHandler([]string{"127.0.0.1:1"}, nil, zm, cm, "0.0.0.0", "::", nil, false)

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}
	h.ServeDNS(rw, makeQuery("s3-ext.example.local", dns.TypeA))

	if cm.Get("s3-ext.example.local", dns.TypeA) == nil {
		t.Error("expected the synthesized CNAME answer to be cached")
	}
}
