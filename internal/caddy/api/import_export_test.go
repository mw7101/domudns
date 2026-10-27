package api

import (
	"strings"
	"testing"

	"github.com/mw7101/domudns/internal/dns"
	mdns "github.com/miekg/dns"
)

// --- rrToRecord tests ---

func TestRRToRecord_A(t *testing.T) {
	rr := &mdns.A{
		Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
		A:   []byte{192, 168, 1, 1},
	}
	rec, ok := rrToRecord(rr, "example.com")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if rec.Type != dns.TypeA {
		t.Errorf("Type = %v, want A", rec.Type)
	}
	if rec.Value != "192.168.1.1" {
		t.Errorf("Value = %q, want 192.168.1.1", rec.Value)
	}
	if rec.Name != "@" {
		t.Errorf("Name = %q, want @", rec.Name)
	}
}

func TestRRToRecord_ASubdomain(t *testing.T) {
	rr := &mdns.A{
		Hdr: mdns.RR_Header{Name: "www.example.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
		A:   []byte{10, 0, 0, 1},
	}
	rec, ok := rrToRecord(rr, "example.com")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if rec.Name != "www" {
		t.Errorf("Name = %q, want www", rec.Name)
	}
}

func TestRRToRecord_AAAA(t *testing.T) {
	rr := &mdns.AAAA{
		Hdr:  mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeAAAA},
		AAAA: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
	}
	rec, ok := rrToRecord(rr, "example.com")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if rec.Type != dns.TypeAAAA {
		t.Errorf("Type = %v, want AAAA", rec.Type)
	}
}

func TestRRToRecord_CNAME(t *testing.T) {
	rr := &mdns.CNAME{
		Hdr:    mdns.RR_Header{Name: "www.example.com.", Rrtype: mdns.TypeCNAME},
		Target: "example.com.",
	}
	rec, ok := rrToRecord(rr, "example.com")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if rec.Type != dns.TypeCNAME {
		t.Errorf("Type = %v, want CNAME", rec.Type)
	}
	if rec.Value != "example.com" {
		t.Errorf("Value = %q, want example.com (no trailing dot)", rec.Value)
	}
}

func TestRRToRecord_MX(t *testing.T) {
	rr := &mdns.MX{
		Hdr:        mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeMX},
		Preference: 10,
		Mx:         "mail.example.com.",
	}
	rec, ok := rrToRecord(rr, "example.com")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if rec.Type != dns.TypeMX {
		t.Errorf("Type = %v, want MX", rec.Type)
	}
	if rec.Priority != 10 {
		t.Errorf("Priority = %d, want 10", rec.Priority)
	}
	if rec.Value != "mail.example.com" {
		t.Errorf("Value = %q, want mail.example.com", rec.Value)
	}
}

func TestRRToRecord_TXT(t *testing.T) {
	rr := &mdns.TXT{
		Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeTXT},
		Txt: []string{"v=spf1", "include:example.net", "~all"},
	}
	rec, ok := rrToRecord(rr, "example.com")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if !strings.Contains(rec.Value, "v=spf1") {
		t.Errorf("Value %q should contain v=spf1", rec.Value)
	}
}

func TestRRToRecord_NS(t *testing.T) {
	rr := &mdns.NS{
		Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeNS},
		Ns:  "ns1.example.com.",
	}
	rec, ok := rrToRecord(rr, "example.com")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if rec.Type != dns.TypeNS {
		t.Errorf("Type = %v, want NS", rec.Type)
	}
	if rec.Value != "ns1.example.com" {
		t.Errorf("Value = %q, want ns1.example.com", rec.Value)
	}
}

func TestRRToRecord_SRV(t *testing.T) {
	rr := &mdns.SRV{
		Hdr:      mdns.RR_Header{Name: "_sip._tcp.example.com.", Rrtype: mdns.TypeSRV},
		Priority: 10,
		Weight:   20,
		Port:     5060,
		Target:   "sip.example.com.",
	}
	rec, ok := rrToRecord(rr, "example.com")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if rec.Type != dns.TypeSRV {
		t.Errorf("Type = %v, want SRV", rec.Type)
	}
	if rec.Priority != 10 || rec.Weight != 20 || rec.Port != 5060 {
		t.Errorf("Priority/Weight/Port = %d/%d/%d, want 10/20/5060", rec.Priority, rec.Weight, rec.Port)
	}
}

func TestRRToRecord_PTR(t *testing.T) {
	rr := &mdns.PTR{
		Hdr: mdns.RR_Header{Name: "1.1.168.192.in-addr.arpa.", Rrtype: mdns.TypePTR},
		Ptr: "host.example.com.",
	}
	rec, ok := rrToRecord(rr, "1.168.192.in-addr.arpa")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if rec.Type != dns.TypePTR {
		t.Errorf("Type = %v, want PTR", rec.Type)
	}
	if rec.Value != "host.example.com" {
		t.Errorf("Value = %q, want host.example.com", rec.Value)
	}
}

func TestRRToRecord_CAA(t *testing.T) {
	rr := &mdns.CAA{
		Hdr:   mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeCAA},
		Flag:  0,
		Tag:   "issue",
		Value: "letsencrypt.org",
	}
	rec, ok := rrToRecord(rr, "example.com")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if rec.Type != dns.TypeCAA {
		t.Errorf("Type = %v, want CAA", rec.Type)
	}
	if rec.Tag != "issue" {
		t.Errorf("Tag = %q, want issue", rec.Tag)
	}
}

func TestRRToRecord_UnsupportedSkipped(t *testing.T) {
	// DS record — not supported by DomU DNS
	rr := &mdns.DS{
		Hdr:        mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeDS},
		KeyTag:     12345,
		Algorithm:  8,
		DigestType: 2,
		Digest:     "AABBCC",
	}
	_, ok := rrToRecord(rr, "example.com")
	if ok {
		t.Error("expected ok=false for unsupported DS record type")
	}
}

// --- normalizeRecordName tests ---

func TestNormalizeRecordName_Apex(t *testing.T) {
	got := normalizeRecordName("example.com.", "example.com")
	if got != "@" {
		t.Errorf("got %q, want @", got)
	}
}

func TestNormalizeRecordName_Subdomain(t *testing.T) {
	got := normalizeRecordName("www.example.com.", "example.com")
	if got != "www" {
		t.Errorf("got %q, want www", got)
	}
}

func TestNormalizeRecordName_Deep(t *testing.T) {
	got := normalizeRecordName("a.b.example.com.", "example.com")
	if got != "a.b" {
		t.Errorf("got %q, want a.b", got)
	}
}

// --- mergeZones tests ---

func makeZone(domain string, recs ...dns.Record) *dns.Zone {
	for i := range recs {
		recs[i].ID = i + 1
	}
	return &dns.Zone{Domain: domain, TTL: 3600, Records: recs}
}

func TestMergeZones_AddNew(t *testing.T) {
	existing := makeZone("example.com",
		dns.Record{Name: "@", Type: dns.TypeA, Value: "1.2.3.4"},
	)
	imported := makeZone("example.com",
		dns.Record{Name: "www", Type: dns.TypeA, Value: "5.6.7.8"},
	)

	result, merged := mergeZones(existing, imported)

	if merged != 0 {
		t.Errorf("merged = %d, want 0 (www A is new)", merged)
	}
	if len(result.Records) != 2 {
		t.Errorf("len(Records) = %d, want 2", len(result.Records))
	}
}

func TestMergeZones_ReplaceByNameType(t *testing.T) {
	existing := makeZone("example.com",
		dns.Record{Name: "@", Type: dns.TypeA, Value: "1.2.3.4"},
		dns.Record{Name: "@", Type: dns.TypeMX, Value: "mail.old.com"},
	)
	imported := makeZone("example.com",
		dns.Record{Name: "@", Type: dns.TypeA, Value: "9.9.9.9"}, // replaces apex A
	)

	result, merged := mergeZones(existing, imported)

	if merged != 1 {
		t.Errorf("merged = %d, want 1", merged)
	}
	// MX should remain, apex A should be replaced
	var hasNewA, hasMX bool
	for _, rec := range result.Records {
		if rec.Type == dns.TypeA && rec.Value == "9.9.9.9" {
			hasNewA = true
		}
		if rec.Type == dns.TypeMX {
			hasMX = true
		}
	}
	if !hasNewA {
		t.Error("new A record (9.9.9.9) not found in merged zone")
	}
	if !hasMX {
		t.Error("existing MX record should have been kept")
	}
}

func TestMergeZones_KeepUnrelated(t *testing.T) {
	existing := makeZone("example.com",
		dns.Record{Name: "@", Type: dns.TypeA, Value: "1.2.3.4"},
		dns.Record{Name: "ftp", Type: dns.TypeA, Value: "10.0.0.1"},
	)
	imported := makeZone("example.com",
		dns.Record{Name: "@", Type: dns.TypeTXT, Value: "v=spf1 ~all"},
	)

	result, merged := mergeZones(existing, imported)

	if merged != 0 {
		t.Errorf("merged = %d, want 0", merged)
	}
	if len(result.Records) != 3 {
		t.Errorf("len(Records) = %d, want 3 (2 existing + 1 imported TXT)", len(result.Records))
	}
}

func TestMergeZones_IDsReassigned(t *testing.T) {
	existing := makeZone("example.com",
		dns.Record{Name: "@", Type: dns.TypeA, Value: "1.2.3.4"},
		dns.Record{Name: "www", Type: dns.TypeA, Value: "2.3.4.5"},
	)
	imported := makeZone("example.com",
		dns.Record{Name: "@", Type: dns.TypeMX, Value: "mail.example.com"},
	)

	result, _ := mergeZones(existing, imported)

	for i, rec := range result.Records {
		if rec.ID != i+1 {
			t.Errorf("record[%d].ID = %d, want %d", i, rec.ID, i+1)
		}
	}
}

// --- parseZoneFile tests ---

func TestParseZoneFile_Basic(t *testing.T) {
	zoneData := `$ORIGIN example.com.
$TTL 3600
@	IN	SOA	ns1 hostmaster 2024010101 3600 900 604800 300
@	IN	A	192.0.2.1
www	IN	A	192.0.2.2
`
	rrs, err := parseZoneFile(strings.NewReader(zoneData), "example.com.")
	if err != nil {
		t.Fatalf("parseZoneFile error: %v", err)
	}
	if len(rrs) == 0 {
		t.Error("expected at least one RR")
	}
}

func TestParseZoneFile_Invalid(t *testing.T) {
	_, err := parseZoneFile(strings.NewReader("not a valid zone file!!! @@@@"), "example.com.")
	if err == nil {
		t.Error("expected error for invalid zone file")
	}
}

// --- rrsToZone tests ---

func TestRRsToZone_ExtractsSOA(t *testing.T) {
	rrs := []mdns.RR{
		&mdns.SOA{
			Hdr:     mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeSOA, Ttl: 3600},
			Ns:      "ns1.example.com.",
			Mbox:    "hostmaster.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   900,
			Expire:  604800,
			Minttl:  300,
		},
		&mdns.A{
			Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeA, Ttl: 300},
			A:   []byte{192, 0, 2, 1},
		},
	}

	zone := rrsToZone(rrs, "example.com", "")

	if zone.SOA == nil {
		t.Fatal("SOA should be set")
	}
	if zone.SOA.Serial != 2024010101 {
		t.Errorf("SOA.Serial = %d, want 2024010101", zone.SOA.Serial)
	}
	if len(zone.Records) != 1 {
		t.Errorf("len(Records) = %d, want 1 (SOA not counted as record)", len(zone.Records))
	}
}
