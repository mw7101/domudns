package dnsserver

import (
	"testing"

	"github.com/miekg/dns"
)

// --- NewDNSSECValidator ---

func TestNewDNSSECValidator_Disabled(t *testing.T) {
	v := NewDNSSECValidator(false)
	if v == nil {
		t.Fatal("NewDNSSECValidator must not return nil")
	}
	if v.enabled {
		t.Error("enabled should be false")
	}
}

func TestNewDNSSECValidator_Enabled(t *testing.T) {
	v := NewDNSSECValidator(true)
	if !v.enabled {
		t.Error("enabled should be true")
	}
}

// --- PrepareRequest ---

func TestPrepareRequest_DOBitSet(t *testing.T) {
	v := NewDNSSECValidator(true)
	req := makeQuery("example.com", dns.TypeA)
	// Client has not set the DO bit

	out := v.PrepareRequest(req)

	if out == req {
		t.Error("PrepareRequest must return a copy, not the same object")
	}
	opt := out.IsEdns0()
	if opt == nil {
		t.Fatal("PrepareRequest: OPT record missing in copy")
	}
	if !opt.Do() {
		t.Error("PrepareRequest: DO bit must be set in the copy")
	}
}

func TestPrepareRequest_OriginalNotMutated(t *testing.T) {
	v := NewDNSSECValidator(true)

	req := makeQuery("example.com", dns.TypeA)
	req.SetEdns0(512, false) // Client has OPT with DO=false

	_ = v.PrepareRequest(req)

	// Original must not be mutated
	origOpt := req.IsEdns0()
	if origOpt == nil {
		t.Fatal("original OPT record must not be removed")
	}
	if origOpt.Do() {
		t.Error("PrepareRequest set DO bit in original — original must not be mutated")
	}
	if origOpt.UDPSize() != 512 {
		t.Errorf("original UDPSize changed: want 512, got %d", origOpt.UDPSize())
	}
}

func TestPrepareRequest_CDBitPreserved(t *testing.T) {
	v := NewDNSSECValidator(true)

	tests := []struct {
		name  string
		cdBit bool
	}{
		{"CD=true is propagated", true},
		{"CD=false stays false", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := makeQuery("example.com", dns.TypeA)
			req.CheckingDisabled = tt.cdBit

			out := v.PrepareRequest(req)

			if out.CheckingDisabled != tt.cdBit {
				t.Errorf("CD-Bit: want %v, got %v", tt.cdBit, out.CheckingDisabled)
			}
		})
	}
}

func TestPrepareRequest_DisabledIsNoOp(t *testing.T) {
	v := NewDNSSECValidator(false)
	req := makeQuery("example.com", dns.TypeA)

	out := v.PrepareRequest(req)

	if out != req {
		t.Error("disabled DNSSECValidator should return the same object (no copy)")
	}
}

// --- ProcessResponse ---

func TestProcessResponse_ADFlagPropagated(t *testing.T) {
	v := NewDNSSECValidator(true)

	// Client has set the DO bit
	req := makeQuery("example.com", dns.TypeA)
	req.SetEdns0(4096, true)

	resp := makeResponse("example.com", dns.TypeA, dns.RcodeSuccess, 60)
	resp.AuthenticatedData = true

	out := v.ProcessResponse(req, resp)

	if !out.AuthenticatedData {
		t.Error("AD bit must be propagated when upstream set it (client has DO)")
	}
}

func TestProcessResponse_ADFlagStrippedIfClientNoDO(t *testing.T) {
	v := NewDNSSECValidator(true)

	// Client has NO DO bit
	req := makeQuery("example.com", dns.TypeA)

	resp := makeResponse("example.com", dns.TypeA, dns.RcodeSuccess, 60)
	resp.AuthenticatedData = true // upstream set AD

	out := v.ProcessResponse(req, resp)

	if out.AuthenticatedData {
		t.Error("AD bit must be removed when client has not set the DO bit")
	}
}

func TestProcessResponse_DNSSECRRsStripped(t *testing.T) {
	v := NewDNSSECValidator(true)

	// Client has no DO bit
	req := makeQuery("example.com", dns.TypeA)

	resp := makeResponse("example.com", dns.TypeA, dns.RcodeSuccess, 60)
	resp.Answer = append(resp.Answer, &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
	})
	resp.Ns = append(resp.Ns, &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeNSEC,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
	})

	out := v.ProcessResponse(req, resp)

	for _, rr := range out.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			t.Error("RRSIG must not be in Answer when client has not set the DO bit")
		}
	}
	for _, rr := range out.Ns {
		if rr.Header().Rrtype == dns.TypeNSEC {
			t.Error("NSEC must not be in Ns section when client has not set the DO bit")
		}
	}
}

func TestProcessResponse_DNSSECRRsKeptIfClientDO(t *testing.T) {
	v := NewDNSSECValidator(true)

	req := makeQuery("example.com", dns.TypeA)
	req.SetEdns0(4096, true) // DO=true

	resp := makeResponse("example.com", dns.TypeA, dns.RcodeSuccess, 60)
	resp.Answer = append(resp.Answer, &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
	})

	out := v.ProcessResponse(req, resp)

	hasRRSIG := false
	for _, rr := range out.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			hasRRSIG = true
		}
	}
	if !hasRRSIG {
		t.Error("RRSIG must be kept when client has set the DO bit")
	}
}

func TestProcessResponse_OPTRecordKeptInExtra(t *testing.T) {
	v := NewDNSSECValidator(true)

	// Client has no DO bit
	req := makeQuery("example.com", dns.TypeA)

	resp := makeResponse("example.com", dns.TypeA, dns.RcodeSuccess, 60)
	resp.SetEdns0(4096, true) // OPT in Extra der Response

	out := v.ProcessResponse(req, resp)

	hasOPT := false
	for _, rr := range out.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			hasOPT = true
		}
	}
	if !hasOPT {
		t.Error("OPT record must be kept in Extra (even when client has no DO bit)")
	}
}

func TestProcessResponse_NilResponse(t *testing.T) {
	v := NewDNSSECValidator(true)
	req := makeQuery("example.com", dns.TypeA)

	out := v.ProcessResponse(req, nil)

	if out != nil {
		t.Error("ProcessResponse with nil response must return nil")
	}
}

func TestProcessResponse_Disabled(t *testing.T) {
	v := NewDNSSECValidator(false)
	req := makeQuery("example.com", dns.TypeA)

	resp := makeResponse("example.com", dns.TypeA, dns.RcodeSuccess, 60)
	resp.AuthenticatedData = true
	resp.Answer = append(resp.Answer, &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
	})
	origPtr := resp

	out := v.ProcessResponse(req, resp)

	if out != origPtr {
		t.Error("disabled validator must return the same object")
	}
	if !out.AuthenticatedData {
		t.Error("disabled validator must not clear the AD bit")
	}
	hasRRSIG := false
	for _, rr := range out.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			hasRRSIG = true
		}
	}
	if !hasRRSIG {
		t.Error("disabled validator must not remove RRSIG")
	}
}

// --- filterDNSSECRRs (package-internal function) ---

func TestFilterDNSSECRRs_AllTypes(t *testing.T) {
	tests := []struct {
		name   string
		rr     dns.RR
		expect bool // true = RR should be kept
	}{
		{"RRSIG is removed", &dns.RRSIG{Hdr: dns.RR_Header{Rrtype: dns.TypeRRSIG}}, false},
		{"NSEC is removed", &dns.NSEC{Hdr: dns.RR_Header{Rrtype: dns.TypeNSEC}}, false},
		{"NSEC3 is removed", &dns.NSEC3{Hdr: dns.RR_Header{Rrtype: dns.TypeNSEC3}}, false},
		{"DNSKEY is removed", &dns.DNSKEY{Hdr: dns.RR_Header{Rrtype: dns.TypeDNSKEY}}, false},
		{"DS is removed", &dns.DS{Hdr: dns.RR_Header{Rrtype: dns.TypeDS}}, false},
		{"NSEC3PARAM is removed", &dns.NSEC3PARAM{Hdr: dns.RR_Header{Rrtype: dns.TypeNSEC3PARAM}}, false},
		{"CDS is removed", &dns.CDS{DS: dns.DS{Hdr: dns.RR_Header{Rrtype: dns.TypeCDS}}}, false},
		{"CDNSKEY is removed", &dns.CDNSKEY{DNSKEY: dns.DNSKEY{Hdr: dns.RR_Header{Rrtype: dns.TypeCDNSKEY}}}, false},
		{"A record is kept", &dns.A{Hdr: dns.RR_Header{Rrtype: dns.TypeA}}, true},
		{"MX record is kept", &dns.MX{Hdr: dns.RR_Header{Rrtype: dns.TypeMX}}, true},
		{"TXT record is kept", &dns.TXT{Hdr: dns.RR_Header{Rrtype: dns.TypeTXT}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterDNSSECRRs([]dns.RR{tt.rr})
			if tt.expect && len(result) == 0 {
				t.Errorf("RR type %d should be kept but was removed", tt.rr.Header().Rrtype)
			}
			if !tt.expect && len(result) != 0 {
				t.Errorf("RR type %d should be removed but was kept", tt.rr.Header().Rrtype)
			}
		})
	}
}

func TestFilterDNSSECRRs_EmptySlice(t *testing.T) {
	result := filterDNSSECRRs([]dns.RR{})
	if len(result) != 0 {
		t.Error("empty slice should return empty slice")
	}
}

func TestFilterDNSSECRRsKeepOPT_OPTBleibt(t *testing.T) {
	opt := &dns.OPT{Hdr: dns.RR_Header{Rrtype: dns.TypeOPT}}
	rrsig := &dns.RRSIG{Hdr: dns.RR_Header{Rrtype: dns.TypeRRSIG}}

	result := filterDNSSECRRsKeepOPT([]dns.RR{opt, rrsig})

	if len(result) != 1 {
		t.Fatalf("expected 1 RR (OPT), got %d", len(result))
	}
	if result[0].Header().Rrtype != dns.TypeOPT {
		t.Error("OPT record must be kept")
	}
}
