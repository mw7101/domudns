package dnsserver

import (
	"net"
	"testing"

	dnsinternal "github.com/mw7101/domudns/internal/dns"
	mdns "github.com/miekg/dns"
)

// makeZone is a helper constructor for tests.
func makeZone(domain, view, ip string) *dnsinternal.Zone {
	return &dnsinternal.Zone{
		Domain: domain,
		View:   view,
		TTL:    300,
		Records: []dnsinternal.Record{
			{ID: 1, Name: "@", Type: dnsinternal.TypeA, TTL: 300, Value: ip},
		},
	}
}

// loadZonesManually fills the ZoneManager directly (without Store).
func loadZonesManually(zm *ZoneManager, zones ...*dnsinternal.Zone) {
	zm.mu.Lock()
	defer zm.mu.Unlock()
	zm.zones = make(map[string]*dnsinternal.Zone)
	zm.viewZones = make(map[string]map[string]*dnsinternal.Zone)
	for _, z := range zones {
		if z.View != "" {
			if zm.viewZones[z.Domain] == nil {
				zm.viewZones[z.Domain] = make(map[string]*dnsinternal.Zone)
			}
			zm.viewZones[z.Domain][z.View] = z
		} else {
			zm.zones[z.Domain] = z
		}
	}
}

func TestZoneManager_FindZone_DefaultOnly(t *testing.T) {
	zm := NewZoneManager()
	loadZonesManually(zm, makeZone("example.com", "", "1.2.3.4"))

	zone, subdomain := zm.FindZone("", "example.com.")
	if zone == nil {
		t.Fatal("erwartet Default-Zone, got nil")
	}
	if subdomain != "@" {
		t.Errorf("subdomain = %q, want \"@\"", subdomain)
	}
	if zone.Records[0].Value != "1.2.3.4" {
		t.Errorf("wrong IP: %s", zone.Records[0].Value)
	}
}

func TestZoneManager_FindZone_ViewPreferredOverDefault(t *testing.T) {
	zm := NewZoneManager()
	loadZonesManually(zm,
		makeZone("nas.home", "", "10.0.0.1"),
		makeZone("nas.home", "internal", "192.168.1.100"),
	)

	// Interner Client → View-Zone
	zone, _ := zm.FindZone("internal", "nas.home.")
	if zone == nil {
		t.Fatal("erwartet View-Zone, got nil")
	}
	if zone.Records[0].Value != "192.168.1.100" {
		t.Errorf("View-Zone: wrong IP %s, want 192.168.1.100", zone.Records[0].Value)
	}

	// Kein View → Default-Zone
	zone, _ = zm.FindZone("", "nas.home.")
	if zone == nil {
		t.Fatal("erwartet Default-Zone, got nil")
	}
	if zone.Records[0].Value != "10.0.0.1" {
		t.Errorf("Default-Zone: wrong IP %s, want 10.0.0.1", zone.Records[0].Value)
	}
}

func TestZoneManager_FindZone_DefaultFallback(t *testing.T) {
	zm := NewZoneManager()
	// Nur Default-Zone, kein View "external"
	loadZonesManually(zm, makeZone("nas.home", "", "10.0.0.1"))

	// Client hat View "external", aber keine View-Zone → Fallback auf Default
	zone, _ := zm.FindZone("external", "nas.home.")
	if zone == nil {
		t.Fatal("erwartet Default-Fallback, got nil")
	}
	if zone.Records[0].Value != "10.0.0.1" {
		t.Errorf("Default-Fallback: wrong IP %s, want 10.0.0.1", zone.Records[0].Value)
	}
}

func TestZoneManager_FindZone_NoMatch(t *testing.T) {
	zm := NewZoneManager()
	loadZonesManually(zm, makeZone("nas.home", "internal", "192.168.1.100"))

	// Kein View, keine Default-Zone → nil
	zone, subdomain := zm.FindZone("", "nas.home.")
	if zone != nil {
		t.Errorf("erwartet nil, got zone mit View=%q", zone.View)
	}
	if subdomain != "" {
		t.Errorf("subdomain = %q, want \"\"", subdomain)
	}
}

func TestZoneManager_FindZone_SubdomainInViewZone(t *testing.T) {
	zm := NewZoneManager()
	zone := &dnsinternal.Zone{
		Domain: "example.com",
		View:   "internal",
		TTL:    300,
		Records: []dnsinternal.Record{
			{ID: 1, Name: "www", Type: dnsinternal.TypeA, TTL: 300, Value: "192.168.1.200"},
		},
	}
	loadZonesManually(zm, zone)

	z, sub := zm.FindZone("internal", "www.example.com.")
	if z == nil {
		t.Fatal("erwartet View-Zone für www.example.com, got nil")
	}
	if sub != "www" {
		t.Errorf("subdomain = %q, want \"www\"", sub)
	}
}

func TestGenerateResponse_TTLOverride_Applied(t *testing.T) {
	zm := NewZoneManager()
	zone := makeZone("example.com", "", "1.2.3.4")
	zone.TTLOverride = 120
	zone.Records[0].TTL = 3600 // Record-TTL soll ignoriert werden
	loadZonesManually(zm, zone)

	req := new(mdns.Msg)
	req.SetQuestion("example.com.", mdns.TypeA)
	resp := zm.GenerateResponse(req, zone, "@").msg
	if len(resp.Answer) == 0 {
		t.Fatal("erwartet Antwort, got keine")
	}
	if got := resp.Answer[0].Header().Ttl; got != 120 {
		t.Errorf("TTL = %d, want 120 (ttl_override)", got)
	}
}

func TestGenerateResponse_TTLOverride_Zero_UsesRecordTTL(t *testing.T) {
	zm := NewZoneManager()
	zone := makeZone("example.com", "", "1.2.3.4")
	zone.TTLOverride = 0 // kein Override
	zone.Records[0].TTL = 600
	loadZonesManually(zm, zone)

	req := new(mdns.Msg)
	req.SetQuestion("example.com.", mdns.TypeA)
	resp := zm.GenerateResponse(req, zone, "@").msg
	if len(resp.Answer) == 0 {
		t.Fatal("erwartet Antwort, got keine")
	}
	if got := resp.Answer[0].Header().Ttl; got != 600 {
		t.Errorf("TTL = %d, want 600 (Record-TTL, kein Override)", got)
	}
}

func TestGenerateResponse_TTLOverride_SOA_NotAffected(t *testing.T) {
	zm := NewZoneManager()
	zone := &dnsinternal.Zone{
		Domain:      "example.com",
		TTL:         3600,
		TTLOverride: 120, // Override gesetzt
		Records: []dnsinternal.Record{
			{ID: 1, Name: "@", Type: dnsinternal.TypeSOA, TTL: 3600,
				Value: "ns1.example.com. hostmaster.example.com. 2024010100 3600 1800 604800 300"},
		},
	}
	loadZonesManually(zm, zone)

	req := new(mdns.Msg)
	req.SetQuestion("example.com.", mdns.TypeSOA)
	resp := zm.GenerateResponse(req, zone, "@").msg
	if len(resp.Answer) == 0 {
		t.Fatal("erwartet SOA Antwort, got keine")
	}
	// SOA TTL must NOT be overridden by override
	if got := resp.Answer[0].Header().Ttl; got != 3600 {
		t.Errorf("SOA TTL = %d, want 3600 (SOA soll vom Override ausgenommen sein)", got)
	}
}

// TestGenerateResponse_CNAME_AQuery verifies RFC 1034 §4.3.2 CNAME chasing:
// an A query for a name that only has a CNAME record must return the CNAME
// plus the A record of the target (if the target is in the same zone).
func TestGenerateResponse_CNAME_AQuery_InZone(t *testing.T) {
	zm := NewZoneManager()
	zone := &dnsinternal.Zone{
		Domain: "example.com",
		TTL:    300,
		Records: []dnsinternal.Record{
			{ID: 1, Name: "homepage", Type: dnsinternal.TypeCNAME, TTL: 300, Value: "npm.example.com"},
			{ID: 2, Name: "npm", Type: dnsinternal.TypeA, TTL: 300, Value: "192.168.1.10"},
		},
	}
	loadZonesManually(zm, zone)

	req := new(mdns.Msg)
	req.SetQuestion("homepage.example.com.", mdns.TypeA)
	resp := zm.GenerateResponse(req, zone, "homepage").msg

	if len(resp.Answer) != 2 {
		t.Fatalf("answer count = %d, want 2 (CNAME + A)", len(resp.Answer))
	}
	cname, ok := resp.Answer[0].(*mdns.CNAME)
	if !ok {
		t.Fatalf("answer[0] type = %T, want *mdns.CNAME", resp.Answer[0])
	}
	if cname.Target != "npm.example.com." {
		t.Errorf("CNAME target = %q, want \"npm.example.com.\"", cname.Target)
	}
	a, ok := resp.Answer[1].(*mdns.A)
	if !ok {
		t.Fatalf("answer[1] type = %T, want *mdns.A", resp.Answer[1])
	}
	if a.A.String() != "192.168.1.10" {
		t.Errorf("A record = %s, want 192.168.1.10", a.A)
	}
}

// TestGenerateResponse_CNAME_AQuery_ExternalTarget verifies that a CNAME pointing
// outside the zone returns the CNAME plus the canonical name left for the pipeline
// (zoneResponse.cnameTarget). The target's records are appended by
// pipeline_cname.go, not by GenerateResponse, because resolving them may need the
// other zones' views or the upstream forwarder.
func TestGenerateResponse_CNAME_AQuery_ExternalTarget(t *testing.T) {
	zm := NewZoneManager()
	zone := &dnsinternal.Zone{
		Domain: "example.com",
		TTL:    300,
		Records: []dnsinternal.Record{
			{ID: 1, Name: "alias", Type: dnsinternal.TypeCNAME, TTL: 300, Value: "target.other.com"},
		},
	}
	loadZonesManually(zm, zone)

	req := new(mdns.Msg)
	req.SetQuestion("alias.example.com.", mdns.TypeA)
	zr := zm.GenerateResponse(req, zone, "alias")

	if len(zr.msg.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1 (CNAME only)", len(zr.msg.Answer))
	}
	if _, ok := zr.msg.Answer[0].(*mdns.CNAME); !ok {
		t.Fatalf("answer[0] type = %T, want *mdns.CNAME", zr.msg.Answer[0])
	}
	if zr.cnameTarget != "target.other.com" {
		t.Errorf("cnameTarget = %q, want \"target.other.com\"", zr.cnameTarget)
	}
}

// TestGenerateResponse_CNAME_AQuery_CrossZoneTarget covers the case that broke
// musl/glibc stub resolvers in production: a CNAME in one zone whose canonical
// name lives in another local zone. GenerateResponse reports the canonical name;
// resolving it is pipeline_cname.go's job (view-aware, may need the forwarder).
func TestGenerateResponse_CNAME_AQuery_CrossZoneTarget(t *testing.T) {
	zm := NewZoneManager()
	intZone := &dnsinternal.Zone{
		Domain: "int.example.com",
		TTL:    300,
		Records: []dnsinternal.Record{
			{ID: 1, Name: "s3-ext", Type: dnsinternal.TypeCNAME, TTL: 300, Value: "minio.cln.int.example.com"},
		},
	}
	clnZone := &dnsinternal.Zone{
		Domain: "cln.int.example.com",
		TTL:    300,
		Records: []dnsinternal.Record{
			{ID: 1, Name: "minio", Type: dnsinternal.TypeA, TTL: 300, Value: "192.168.101.5"},
		},
	}
	loadZonesManually(zm, intZone, clnZone)

	req := new(mdns.Msg)
	req.SetQuestion("s3-ext.int.example.com.", mdns.TypeA)
	zr := zm.GenerateResponse(req, intZone, "s3-ext")

	if len(zr.msg.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1 (only the CNAME comes from GenerateResponse)", len(zr.msg.Answer))
	}
	if zr.cnameTarget != "minio.cln.int.example.com" {
		t.Errorf("cnameTarget = %q, want \"minio.cln.int.example.com\"", zr.cnameTarget)
	}
}

// TestGenerateResponse_CNAME_InZoneChain verifies a multi-hop chain inside one
// zone: every intermediate CNAME plus the final A record (RFC 1034 §4.3.2 step 3a
// — repeat the lookup with the canonical name).
func TestGenerateResponse_CNAME_InZoneChain(t *testing.T) {
	zm := NewZoneManager()
	zone := &dnsinternal.Zone{
		Domain: "example.com",
		TTL:    300,
		Records: []dnsinternal.Record{
			{ID: 1, Name: "a", Type: dnsinternal.TypeCNAME, TTL: 300, Value: "b.example.com"},
			{ID: 2, Name: "b", Type: dnsinternal.TypeCNAME, TTL: 300, Value: "c.example.com"},
			{ID: 3, Name: "c", Type: dnsinternal.TypeA, TTL: 300, Value: "10.0.0.7"},
		},
	}
	loadZonesManually(zm, zone)

	req := new(mdns.Msg)
	req.SetQuestion("a.example.com.", mdns.TypeA)
	zr := zm.GenerateResponse(req, zone, "a")

	if zr.cnameTarget != "" {
		t.Errorf("cnameTarget = %q, want \"\" (chain answered in-zone)", zr.cnameTarget)
	}
	if len(zr.msg.Answer) != 3 {
		t.Fatalf("answer count = %d, want 3 (CNAME, CNAME, A)", len(zr.msg.Answer))
	}
	a, ok := zr.msg.Answer[2].(*mdns.A)
	if !ok {
		t.Fatalf("answer[2] type = %T, want *mdns.A", zr.msg.Answer[2])
	}
	if a.A.String() != "10.0.0.7" {
		t.Errorf("A record = %s, want 10.0.0.7", a.A)
	}
}

// TestGenerateResponse_CNAME_InZoneLoop verifies that a self-referencing chain
// terminates as soon as a name repeats: no A record, and — because the loop is
// detected per name rather than by hitting the depth limit — no duplicate RRs
// (RFC 1035 §3.6.2).
func TestGenerateResponse_CNAME_InZoneLoop(t *testing.T) {
	zm := NewZoneManager()
	zone := &dnsinternal.Zone{
		Domain: "example.com",
		TTL:    300,
		Records: []dnsinternal.Record{
			{ID: 1, Name: "a", Type: dnsinternal.TypeCNAME, TTL: 300, Value: "b.example.com"},
			{ID: 2, Name: "b", Type: dnsinternal.TypeCNAME, TTL: 300, Value: "a.example.com"},
		},
	}
	loadZonesManually(zm, zone)

	req := new(mdns.Msg)
	req.SetQuestion("a.example.com.", mdns.TypeA)
	zr := zm.GenerateResponse(req, zone, "a")

	if zr.cnameTarget == "" {
		t.Error("cnameTarget empty, want the still unresolved canonical name")
	}
	seen := map[string]bool{}
	for _, rr := range zr.msg.Answer {
		if _, ok := rr.(*mdns.A); ok {
			t.Fatal("a CNAME loop must not produce an A record")
		}
		if seen[rr.String()] {
			t.Fatalf("duplicate RR in a CNAME loop answer: %s", rr.String())
		}
		seen[rr.String()] = true
	}
	if len(zr.msg.Answer) != 2 {
		t.Errorf("answer count = %d, want 2 (a→b, b→a, then the loop is cut)", len(zr.msg.Answer))
	}
}

// TestGenerateResponse_CNAME_CNAMEQuery verifies that a direct CNAME query
// returns the CNAME record (existing behavior must not regress).
func TestGenerateResponse_CNAME_CNAMEQuery(t *testing.T) {
	zm := NewZoneManager()
	zone := &dnsinternal.Zone{
		Domain: "example.com",
		TTL:    300,
		Records: []dnsinternal.Record{
			{ID: 1, Name: "alias", Type: dnsinternal.TypeCNAME, TTL: 300, Value: "target.example.com"},
			{ID: 2, Name: "target", Type: dnsinternal.TypeA, TTL: 300, Value: "10.0.0.1"},
		},
	}
	loadZonesManually(zm, zone)

	req := new(mdns.Msg)
	req.SetQuestion("alias.example.com.", mdns.TypeCNAME)
	resp := zm.GenerateResponse(req, zone, "alias").msg

	if len(resp.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1 (CNAME only for CNAME query)", len(resp.Answer))
	}
	if _, ok := resp.Answer[0].(*mdns.CNAME); !ok {
		t.Fatalf("answer[0] type = %T, want *mdns.CNAME", resp.Answer[0])
	}
}

func TestGenerateResponse_ALIAS_NonAB_Query_Returns_NOERROR_Empty(t *testing.T) {
	zm := NewZoneManager()
	zone := &dnsinternal.Zone{
		Domain: "example.com",
		TTL:    300,
		Records: []dnsinternal.Record{
			{ID: 1, Name: "@", Type: dnsinternal.TypeALIAS, TTL: 300, Value: "cdn.example.com"},
		},
	}
	loadZonesManually(zm, zone)

	req := new(mdns.Msg)
	req.SetQuestion("example.com.", mdns.TypeMX)

	zr := zm.GenerateResponse(req, zone, "@")
	if zr.aliasTarget != "" {
		t.Errorf("non-A/AAAA query should not set aliasTarget, got %q", zr.aliasTarget)
	}
	if zr.msg.Rcode != mdns.RcodeSuccess {
		t.Errorf("expected NOERROR, got rcode %d", zr.msg.Rcode)
	}
	if len(zr.msg.Answer) != 0 {
		t.Errorf("expected empty answer, got %d records", len(zr.msg.Answer))
	}
}

func TestGenerateResponse_ALIAS_A_Query_Sets_AliasTarget(t *testing.T) {
	zm := NewZoneManager()
	zone := &dnsinternal.Zone{
		Domain: "example.com",
		TTL:    300,
		Records: []dnsinternal.Record{
			{ID: 1, Name: "@", Type: dnsinternal.TypeALIAS, TTL: 300, Value: "cdn.example.com"},
		},
	}
	loadZonesManually(zm, zone)

	req := new(mdns.Msg)
	req.SetQuestion("example.com.", mdns.TypeA)

	zr := zm.GenerateResponse(req, zone, "@")
	if zr.aliasTarget != "cdn.example.com" {
		t.Errorf("expected aliasTarget %q, got %q", "cdn.example.com", zr.aliasTarget)
	}
	if len(zr.msg.Answer) != 0 {
		t.Errorf("msg shell must have empty answer, got %d", len(zr.msg.Answer))
	}
	if !zr.msg.Authoritative {
		t.Error("msg shell must be Authoritative=true")
	}
}

func TestGenerateResponse_ALIAS_ARecord_Wins_Over_ALIAS(t *testing.T) {
	zm := NewZoneManager()
	zone := &dnsinternal.Zone{
		Domain: "example.com",
		TTL:    300,
		Records: []dnsinternal.Record{
			{ID: 1, Name: "@", Type: dnsinternal.TypeA, TTL: 300, Value: "1.2.3.4"},
			{ID: 2, Name: "@", Type: dnsinternal.TypeALIAS, TTL: 300, Value: "cdn.example.com"},
		},
	}
	loadZonesManually(zm, zone)

	req := new(mdns.Msg)
	req.SetQuestion("example.com.", mdns.TypeA)

	zr := zm.GenerateResponse(req, zone, "@")
	if zr.aliasTarget != "" {
		t.Errorf("A record should win, aliasTarget must be empty, got %q", zr.aliasTarget)
	}
	if len(zr.msg.Answer) != 1 {
		t.Errorf("expected 1 A record, got %d", len(zr.msg.Answer))
	}
}

// TestGenerateResponse_ALIAS_AAAA_Query_Sets_AliasTarget verifies AAAA queries also signal ALIAS.
func TestGenerateResponse_ALIAS_AAAA_Query_Sets_AliasTarget(t *testing.T) {
	zm := NewZoneManager()
	zone := &dnsinternal.Zone{
		Domain: "example.com",
		TTL:    300,
		Records: []dnsinternal.Record{
			{ID: 1, Name: "@", Type: dnsinternal.TypeALIAS, TTL: 300, Value: "cdn.example.com"},
		},
	}
	loadZonesManually(zm, zone)

	req := new(mdns.Msg)
	req.SetQuestion("example.com.", mdns.TypeAAAA)

	zr := zm.GenerateResponse(req, zone, "@")
	if zr.aliasTarget != "cdn.example.com" {
		t.Errorf("AAAA query: expected aliasTarget, got %q", zr.aliasTarget)
	}
}

// TestGenerateResponse_MultiLabelRelativeName verifies that a record whose
// name is a multi-label zone-relative name is answered for that FQDN — the
// ACME DNS-01 case for hosts below the zone apex (record
// "_acme-challenge.pve-node" in zone example.com answers
// "_acme-challenge.pve-node.example.com").
func TestGenerateResponse_MultiLabelRelativeName(t *testing.T) {
	zm := NewZoneManager()
	zone := &dnsinternal.Zone{
		Domain: "example.com",
		TTL:    300,
		Records: []dnsinternal.Record{
			{ID: 1, Name: "_acme-challenge.pve-node", Type: dnsinternal.TypeTXT, TTL: 300, Value: "acme-token"},
		},
	}
	loadZonesManually(zm, zone)

	req := new(mdns.Msg)
	req.SetQuestion("_acme-challenge.pve-node.example.com.", mdns.TypeTXT)
	resp := zm.GenerateResponse(req, zone, "_acme-challenge.pve-node").msg

	if resp.Rcode != mdns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got rcode %d", resp.Rcode)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(resp.Answer))
	}
	txt, ok := resp.Answer[0].(*mdns.TXT)
	if !ok {
		t.Fatalf("answer[0] type = %T, want *mdns.TXT", resp.Answer[0])
	}
	if txt.Hdr.Name != "_acme-challenge.pve-node.example.com." {
		t.Errorf("answer name = %q, want \"_acme-challenge.pve-node.example.com.\"", txt.Hdr.Name)
	}
	if len(txt.Txt) != 1 || txt.Txt[0] != "acme-token" {
		t.Errorf("TXT = %v, want [acme-token]", txt.Txt)
	}
}

func TestZoneManager_Stats(t *testing.T) {
	zm := NewZoneManager()
	loadZonesManually(zm,
		makeZone("a.com", "", "1.1.1.1"),
		makeZone("b.com", "", "2.2.2.2"),
		makeZone("b.com", "internal", "192.168.0.1"),
		makeZone("c.com", "external", "3.3.3.3"),
	)

	def, view := zm.Stats()
	if def != 2 {
		t.Errorf("default zones = %d, want 2", def)
	}
	if view != 2 {
		t.Errorf("view zones = %d, want 2", view)
	}
}

// TestAliasPhase_InZoneResolution tests the aliasPhase via a mock Handler.
func TestAliasPhase_InZoneResolution(t *testing.T) {
	zm := NewZoneManager()
	targetZone := &dnsinternal.Zone{
		Domain: "example.com",
		TTL:    300,
		Records: []dnsinternal.Record{
			{ID: 1, Name: "target", Type: dnsinternal.TypeA, TTL: 600, Value: "5.6.7.8"},
		},
	}
	aliasZone := &dnsinternal.Zone{
		Domain: "alias.test",
		TTL:    300,
		Records: []dnsinternal.Record{
			{ID: 2, Name: "@", Type: dnsinternal.TypeALIAS, TTL: 300, Value: "target.example.com"},
		},
	}
	loadZonesManually(zm, targetZone, aliasZone)

	h := &Handler{zones: zm}

	req := new(mdns.Msg)
	req.SetQuestion("alias.test.", mdns.TypeA)

	shell := new(mdns.Msg)
	shell.SetReply(req)
	shell.Authoritative = true

	zr := zoneResponse{msg: shell, aliasTarget: "target.example.com"}

	// mockResponseWriter is defined in handler_test.go (same package dnsserver).
	w := &mockResponseWriter{}
	ctx := &queryContext{
		req:      req,
		w:        w,
		clientIP: net.ParseIP("127.0.0.1"),
		question: mdns.Question{Name: "alias.test.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET},
	}

	result := h.aliasPhase(ctx, zr, "")
	if !result.done {
		t.Fatal("aliasPhase should return done=true")
	}
	if result.msg == nil || len(result.msg.Answer) == 0 {
		t.Fatal("expected synthesized A record in answer")
	}
	a, ok := result.msg.Answer[0].(*mdns.A)
	if !ok {
		t.Fatalf("expected *mdns.A, got %T", result.msg.Answer[0])
	}
	if a.A.String() != "5.6.7.8" {
		t.Errorf("expected 5.6.7.8, got %s", a.A)
	}
	if a.Hdr.Name != "alias.test." {
		t.Errorf("synthesized RR name must be original query name, got %q", a.Hdr.Name)
	}
	if a.Hdr.Ttl != 600 {
		t.Errorf("expected TTL 600 (from target), got %d", a.Hdr.Ttl)
	}
	if w.written == nil {
		t.Error("aliasPhase must write response via ctx.w.WriteMsg")
	}
}

// ---------------------------------------------------------------------------
// RFC 1034 §4.3.3 — Wildcard record matching
// ---------------------------------------------------------------------------

// makeWildcardZone builds a zone with a wildcard A record and an optional
// exact A record for the given host label.
func makeWildcardZone(domain string, wildcardIP string, exactHost, exactIP string) *dnsinternal.Zone {
	z := &dnsinternal.Zone{
		Domain: domain,
		TTL:    300,
		Records: []dnsinternal.Record{
			{ID: 1, Name: "@", Type: dnsinternal.TypeA, TTL: 300, Value: "10.0.0.1"},
			{ID: 2, Name: "*", Type: dnsinternal.TypeA, TTL: 300, Value: wildcardIP},
		},
	}
	if exactHost != "" && exactIP != "" {
		z.Records = append(z.Records, dnsinternal.Record{
			ID: 3, Name: exactHost, Type: dnsinternal.TypeA, TTL: 300, Value: exactIP,
		})
	}
	return z
}

// TestWildcard_SingleLabelMatch verifies that a "*" record matches a
// single-label subdomain and produces the correct FQDN in the answer.
func TestWildcard_SingleLabelMatch(t *testing.T) {
	zm := NewZoneManager()
	zone := makeWildcardZone("test.servwerk.de", "1.2.3.4", "", "")
	loadZonesManually(zm, zone)

	req := new(mdns.Msg)
	req.SetQuestion("test01.test.servwerk.de.", mdns.TypeA)

	resp := zm.GenerateResponse(req, zone, "test01").msg
	if resp.Rcode != mdns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got rcode %d", resp.Rcode)
	}
	if len(resp.Answer) == 0 {
		t.Fatal("expected at least one answer RR")
	}
	a, ok := resp.Answer[0].(*mdns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", resp.Answer[0])
	}
	if a.A.String() != "1.2.3.4" {
		t.Errorf("expected IP 1.2.3.4, got %s", a.A.String())
	}
	if a.Hdr.Name != "test01.test.servwerk.de." {
		t.Errorf("expected FQDN test01.test.servwerk.de., got %q", a.Hdr.Name)
	}
}

// TestWildcard_MultiLabelNoMatch verifies that a "*" record does NOT match a
// multi-label subdomain (RFC 1034 §4.3.3: only single-label wildcards).
func TestWildcard_MultiLabelNoMatch(t *testing.T) {
	zm := NewZoneManager()
	zone := makeWildcardZone("test.servwerk.de", "1.2.3.4", "", "")
	loadZonesManually(zm, zone)

	req := new(mdns.Msg)
	req.SetQuestion("foo.bar.test.servwerk.de.", mdns.TypeA)

	// subdomain "foo.bar" contains a dot — wildcard must not match.
	resp := zm.GenerateResponse(req, zone, "foo.bar").msg
	if resp.Rcode != mdns.RcodeNameError {
		t.Errorf("expected NXDOMAIN (rcode 3), got rcode %d", resp.Rcode)
	}
}

// TestWildcard_ApexNoMatch verifies that a "*" record does NOT match the zone
// apex itself (subdomain == "@").
func TestWildcard_ApexNoMatch(t *testing.T) {
	zm := NewZoneManager()
	zone := makeWildcardZone("test.servwerk.de", "1.2.3.4", "", "")
	loadZonesManually(zm, zone)

	req := new(mdns.Msg)
	req.SetQuestion("test.servwerk.de.", mdns.TypeA)

	// Apex has an explicit "@" A record (10.0.0.1) — must NOT return 1.2.3.4.
	resp := zm.GenerateResponse(req, zone, "@").msg
	if resp.Rcode != mdns.RcodeSuccess {
		t.Fatalf("expected NOERROR for apex, got rcode %d", resp.Rcode)
	}
	if len(resp.Answer) == 0 {
		t.Fatal("expected apex A record in answer")
	}
	a, ok := resp.Answer[0].(*mdns.A)
	if !ok {
		t.Fatalf("expected A record, got %T", resp.Answer[0])
	}
	if a.A.String() == "1.2.3.4" {
		t.Error("wildcard IP must not appear for apex query")
	}
}

// TestWildcard_ExactRecordTakesPrecedence verifies that an exact match wins
// over the wildcard when both are present in the zone.
func TestWildcard_ExactRecordTakesPrecedence(t *testing.T) {
	zm := NewZoneManager()
	zone := makeWildcardZone("test.servwerk.de", "1.2.3.4", "host", "5.6.7.8")
	loadZonesManually(zm, zone)

	req := new(mdns.Msg)
	req.SetQuestion("host.test.servwerk.de.", mdns.TypeA)

	resp := zm.GenerateResponse(req, zone, "host").msg
	if resp.Rcode != mdns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got rcode %d", resp.Rcode)
	}
	if len(resp.Answer) == 0 {
		t.Fatal("expected at least one answer RR")
	}
	// Must contain exactly the exact record IP, not the wildcard IP.
	for _, rr := range resp.Answer {
		a, ok := rr.(*mdns.A)
		if !ok {
			continue
		}
		if a.A.String() == "1.2.3.4" {
			t.Error("wildcard IP 1.2.3.4 must not appear when exact record exists")
		}
		if a.A.String() != "5.6.7.8" {
			t.Errorf("expected exact IP 5.6.7.8, got %s", a.A.String())
		}
	}
}
