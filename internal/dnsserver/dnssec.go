package dnsserver

import "github.com/miekg/dns"

// DNSSECValidator implements AD-flag delegation for stub resolver mode (RFC 4035).
// No local signature validation is performed — instead the server delegates
// validation to DNSSEC-capable upstream servers (e.g. 1.1.1.1, 8.8.8.8).
//
// Protection principle:
//  1. Set DO bit in upstream requests → upstream validates DNSSEC
//  2. Propagate AD bit from upstream response to client → client knows: response is validated
//  3. Filter DNSSEC RRs when client has not set the DO bit
//
// Identical to the behaviour of systemd-resolved and dnsmasq in forwarding mode.
type DNSSECValidator struct {
	enabled bool
}

// NewDNSSECValidator creates a DNSSECValidator.
// When enabled=false, PrepareRequest and ProcessResponse are no-ops.
func NewDNSSECValidator(enabled bool) *DNSSECValidator {
	return &DNSSECValidator{enabled: enabled}
}

// PrepareRequest creates a deep copy of req with the DO bit set in the OPT record.
// The CD bit (Checking Disabled) is taken from the original request.
// The original req is NOT modified — it is needed for ProcessResponse.
//
// When DNSSEC is disabled, req is returned unchanged (no copy).
func (v *DNSSECValidator) PrepareRequest(req *dns.Msg) *dns.Msg {
	if !v.enabled {
		return req
	}

	out := req.Copy()
	out.CheckingDisabled = req.CheckingDisabled
	// SetEdns0 creates a new OPT record or overwrites the existing one.
	// UDPSize 4096 matches the configured udp_size default.
	out.SetEdns0(4096, true)
	return out
}

// ProcessResponse prepares the upstream response for the client:
//  1. The AD bit (Authenticated Data) from the upstream response is kept
//     if the upstream set it (meaning DNSSEC validation succeeded).
//  2. DNSSEC-specific RRs (RRSIG, NSEC, NSEC3, DNSKEY, DS, NSEC3PARAM, CDS, CDNSKEY)
//     are removed when the client has not set the DO bit — the client did not
//     ask for DNSSEC data.
//
// origReq is the ORIGINAL client request (unmodified, before PrepareRequest).
// resp is modified in-place and returned.
//
// When DNSSEC is disabled or resp is nil, resp is returned unchanged.
func (v *DNSSECValidator) ProcessResponse(origReq, resp *dns.Msg) *dns.Msg {
	if !v.enabled || resp == nil {
		return resp
	}

	// Check whether the original client had the DO bit set
	clientWantsDNSSEC := false
	if opt := origReq.IsEdns0(); opt != nil {
		clientWantsDNSSEC = opt.Do()
	}

	if !clientWantsDNSSEC {
		// Remove DNSSEC RRs — client did not ask for them
		resp.Answer = filterDNSSECRRs(resp.Answer)
		resp.Ns = filterDNSSECRRs(resp.Ns)
		resp.Extra = filterDNSSECRRsKeepOPT(resp.Extra)
		// Also clear the AD bit: it would be meaningless to a client without the DO bit
		resp.AuthenticatedData = false
	}
	// If clientWantsDNSSEC=true: AD bit and DNSSEC RRs remain as set by upstream.

	return resp
}

// filterDNSSECRRs removes DNSSEC-specific resource records from a slice.
// Removed types: RRSIG, NSEC, NSEC3, DNSKEY, DS, NSEC3PARAM, CDS, CDNSKEY.
// Non-DNSSEC RRs (A, AAAA, MX, TXT, etc.) remain unchanged.
func filterDNSSECRRs(rrs []dns.RR) []dns.RR {
	if len(rrs) == 0 {
		return rrs
	}
	out := rrs[:0] // in-place filter on the existing backing array
	for _, rr := range rrs {
		switch rr.Header().Rrtype {
		case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3,
			dns.TypeDNSKEY, dns.TypeDS, dns.TypeNSEC3PARAM,
			dns.TypeCDS, dns.TypeCDNSKEY:
			// DNSSEC RR — skip
		default:
			out = append(out, rr)
		}
	}
	return out
}

// filterDNSSECRRsKeepOPT removes DNSSEC RRs from the Extra section but keeps the OPT record.
// The OPT record (TypeOPT) contains EDNS0 options and must not be removed.
func filterDNSSECRRsKeepOPT(rrs []dns.RR) []dns.RR {
	if len(rrs) == 0 {
		return rrs
	}
	out := rrs[:0]
	for _, rr := range rrs {
		switch rr.Header().Rrtype {
		case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3,
			dns.TypeDNSKEY, dns.TypeDS, dns.TypeNSEC3PARAM,
			dns.TypeCDS, dns.TypeCDNSKEY:
			// DNSSEC RR — skip (OPT is kept via the default branch)
		default:
			out = append(out, rr)
		}
	}
	return out
}
