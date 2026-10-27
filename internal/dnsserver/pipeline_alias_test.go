package dnsserver

import (
	"net"
	"sync/atomic"
	"testing"

	dnsinternal "github.com/mw7101/domudns/internal/dns"
	"github.com/miekg/dns"
)

// TestAliasPhase_TargetWithoutQueriedType_IsNODATA is the regression test for the
// failure that survived the CNAME chase fix: an ALIAS whose target has no record
// of the queried type answered SERVFAIL, so `ping`/`busybox nslookup` on Alpine
// (musl asks for A and AAAA in parallel) failed with "bad address" even though
// the A query resolved. RFC 2308 §2.2: the ALIAS name exists, the target has no
// such record → NOERROR with an empty answer.
func TestAliasPhase_TargetWithoutQueriedType_IsNODATA(t *testing.T) {
	upstream, queries := fakeUpstream(t, map[string]string{"ext.cdn.example.": "203.0.113.9"})
	zone := &dnsinternal.Zone{Domain: "example.com", TTL: 300, Records: []dnsinternal.Record{
		{ID: 1, Name: "cdn", Type: dnsinternal.TypeALIAS, TTL: 300, Value: "ext.cdn.example"},
	}}
	h := newCNAMEHandler(t, []string{upstream}, zone)

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}
	h.ServeDNS(rw, makeQuery("cdn.example.com", dns.TypeAAAA))

	if rw.written == nil {
		t.Fatal("no response written")
	}
	if rw.written.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR (NODATA, not SERVFAIL)", rw.written.Rcode)
	}
	if len(rw.written.Answer) != 0 {
		t.Errorf("answer count = %d, want 0 (the target has no AAAA): %v", len(rw.written.Answer), rw.written.Answer)
	}
	if got := queries.Load(); got != 1 {
		t.Errorf("upstream queries = %d, want 1 (target is not in a local zone)", got)
	}
}

// TestAliasPhase_LocalTargetWithoutQueriedType_NoUpstreamQuery verifies that a
// target owned by a local zone is not leaked upstream: an empty authoritative
// answer is final, so no public resolver is asked about an internal name.
func TestAliasPhase_LocalTargetWithoutQueriedType_NoUpstreamQuery(t *testing.T) {
	upstream, queries := fakeUpstream(t, map[string]string{"minio.cln.example.local.": "192.168.101.5"})
	intZone := &dnsinternal.Zone{Domain: "example.local", TTL: 300, Records: []dnsinternal.Record{
		{ID: 1, Name: "s3-ext", Type: dnsinternal.TypeALIAS, TTL: 300, Value: "minio.cln.example.local"},
	}}
	clnZone := &dnsinternal.Zone{Domain: "cln.example.local", TTL: 300, Records: []dnsinternal.Record{
		{ID: 1, Name: "minio", Type: dnsinternal.TypeA, TTL: 86400, Value: "192.168.101.5"},
	}}
	h := newCNAMEHandler(t, []string{upstream}, intZone, clnZone)

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("192.168.42.145"), Port: 1234}}
	h.ServeDNS(rw, makeQuery("s3-ext.example.local", dns.TypeAAAA))

	if rw.written == nil {
		t.Fatal("no response written")
	}
	if rw.written.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR (NODATA)", rw.written.Rcode)
	}
	if len(rw.written.Answer) != 0 {
		t.Errorf("answer count = %d, want 0: %v", len(rw.written.Answer), rw.written.Answer)
	}
	if got := queries.Load(); got != 0 {
		t.Errorf("upstream queries = %d, want 0 (a local zone owns the target)", got)
	}
}

// TestAliasPhase_UnresolvableTarget_IsServfail pins the other side of the
// boundary: when resolution itself fails, SERVFAIL is still the right answer.
func TestAliasPhase_UnresolvableTarget_IsServfail(t *testing.T) {
	zone := &dnsinternal.Zone{Domain: "example.com", TTL: 300, Records: []dnsinternal.Record{
		{ID: 1, Name: "cdn", Type: dnsinternal.TypeALIAS, TTL: 300, Value: "ext.cdn.example"},
	}}
	// Nothing listens on 127.0.0.1:1 — the upstream lookup itself fails.
	h := newCNAMEHandler(t, []string{"127.0.0.1:1"}, zone)

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}
	h.ServeDNS(rw, makeQuery("cdn.example.com", dns.TypeA))

	if rw.written == nil {
		t.Fatal("no response written")
	}
	if rw.written.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %d, want SERVFAIL", rw.written.Rcode)
	}
}

// aliasUpstreamZone is an ALIAS record whose target is in no local zone, so the
// phase has to resolve it upstream.
func aliasUpstreamZone() *dnsinternal.Zone {
	return &dnsinternal.Zone{Domain: "example.com", TTL: 300, Records: []dnsinternal.Record{
		{ID: 1, Name: "cdn", Type: dnsinternal.TypeALIAS, TTL: 300, Value: "ext.cdn.example"},
	}}
}

// TestAliasPhase_UpstreamTarget_RebindingBlocked verifies that an ALIAS whose
// target resolves to a private IP upstream is blocked like any other upstream
// answer (phase 5.5). Before this, the ALIAS path called the forwarder directly,
// so a public target reached through an ALIAS was served while the same name
// queried plainly was blocked — a rebinding bypass.
func TestAliasPhase_UpstreamTarget_RebindingBlocked(t *testing.T) {
	upstream, _ := fakeUpstream(t, map[string]string{"ext.cdn.example.": "10.0.0.5"})
	h := newCNAMEHandler(t, []string{upstream}, aliasUpstreamZone())
	h.rebinding.Update(true, nil)

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}
	h.ServeDNS(rw, makeQuery("cdn.example.com", dns.TypeA))

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

// TestAliasPhase_ChainEndingInAlias_RebindingBlocked covers the same gate on the
// other ALIAS entry point: a CNAME chain that ends in an ALIAS record
// (pipeline_cname.go's appendAliasTarget).
func TestAliasPhase_ChainEndingInAlias_RebindingBlocked(t *testing.T) {
	upstream, _ := fakeUpstream(t, map[string]string{"ext.cdn.example.": "10.0.0.5"})
	zone := &dnsinternal.Zone{Domain: "example.com", TTL: 300, Records: []dnsinternal.Record{
		{ID: 1, Name: "www", Type: dnsinternal.TypeCNAME, TTL: 300, Value: "cdn.example.com"},
		{ID: 2, Name: "cdn", Type: dnsinternal.TypeALIAS, TTL: 300, Value: "ext.cdn.example"},
	}}
	h := newCNAMEHandler(t, []string{upstream}, zone)
	h.rebinding.Update(true, nil)

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}
	h.ServeDNS(rw, makeQuery("www.example.com", dns.TypeA))

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

// TestAliasPhase_UpstreamTarget_PreparesDNSSEC verifies that the ALIAS path uses
// the shared upstream preparation: with DNSSEC enabled the request sent upstream
// carries the DO bit, so the answer can be validated and its AD bit propagated.
func TestAliasPhase_UpstreamTarget_PreparesDNSSEC(t *testing.T) {
	var sawDO atomic.Bool
	upstream, _ := startFakeUpstream(t, map[string]string{"ext.cdn.example.": "203.0.113.9"}, func(req *dns.Msg) {
		if opt := req.IsEdns0(); opt != nil && opt.Do() {
			sawDO.Store(true)
		}
	})
	zm := NewZoneManager()
	loadZonesManually(zm, aliasUpstreamZone())
	h := NewHandler([]string{upstream}, nil, zm, nil, "0.0.0.0", "::", nil, true) // DNSSEC enabled

	rw := &mockRWWithAddr{addr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}}
	h.ServeDNS(rw, makeQuery("cdn.example.com", dns.TypeA))

	if !sawDO.Load() {
		t.Error("upstream request had no DO bit: the ALIAS path skipped DNSSEC preparation")
	}
	if rw.written == nil || len(rw.written.Answer) != 1 {
		t.Fatalf("want the synthesized A record, got %v", rw.written)
	}
}
