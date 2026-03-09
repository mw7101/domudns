package dns

import (
	"testing"
)

var benchRecordA = Record{Name: "@", Type: TypeA, TTL: 3600, Value: "192.168.1.1"}
var benchRecordAAAA = Record{Name: "www", Type: TypeAAAA, TTL: 3600, Value: "::1"}
var benchRecordMX = Record{Name: "@", Type: TypeMX, TTL: 3600, Value: "mail.example.com", Priority: 10}
var benchRecordTXT = Record{Name: "@", Type: TypeTXT, TTL: 3600, Value: "v=spf1 include:_spf.example.com"}
var benchRecordCNAME = Record{Name: "www", Type: TypeCNAME, TTL: 3600, Value: "example.com"}
var benchRecordSRV = Record{Name: "_sip._udp", Type: TypeSRV, TTL: 3600, Value: "sip.example.com", Priority: 0, Weight: 10, Port: 5060}
var benchRecordCAA = Record{Name: "@", Type: TypeCAA, TTL: 3600, Value: "letsencrypt.org", Tag: "issue", Priority: 0}

const benchZoneDomain = "example.com"

func BenchmarkValidateRecord_A(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = ValidateRecord(benchRecordA, benchZoneDomain)
	}
}

func BenchmarkValidateRecord_AAAA(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = ValidateRecord(benchRecordAAAA, benchZoneDomain)
	}
}

func BenchmarkValidateRecord_MX(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = ValidateRecord(benchRecordMX, benchZoneDomain)
	}
}

func BenchmarkValidateRecord_TXT(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = ValidateRecord(benchRecordTXT, benchZoneDomain)
	}
}

func BenchmarkValidateRecord_CNAME(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = ValidateRecord(benchRecordCNAME, benchZoneDomain)
	}
}

func BenchmarkValidateRecord_SRV(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = ValidateRecord(benchRecordSRV, benchZoneDomain)
	}
}

func BenchmarkValidateRecord_CAA(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = ValidateRecord(benchRecordCAA, benchZoneDomain)
	}
}

func BenchmarkIsValidDomain(b *testing.B) {
	domains := []string{"example.com", "www.sub.example.org", "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsValidDomain(domains[i%3])
	}
}

func BenchmarkValidateZone(b *testing.B) {
	zone := &Zone{
		Domain: "example.com",
		TTL:    3600,
		Records: []Record{
			benchRecordA,
			benchRecordAAAA,
			benchRecordMX,
			benchRecordTXT,
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateZone(zone)
	}
}
