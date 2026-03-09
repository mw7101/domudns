package dnsserver

import (
	"fmt"
	"net"
	"sync/atomic"

	"github.com/mw7101/domudns/internal/dns"
	mdns "github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// axfrChunkSize is the maximum number of RRs per AXFR response message.
// Smaller chunks reduce memory spikes and improve TCP flow control.
const axfrChunkSize = 100

// AXFRHandler processes AXFR and IXFR requests (RFC 5936 / RFC 1995).
// IXFR is answered as a full AXFR (no change history tracking implemented).
// TCP only; UDP requests receive NOTIMP (RFC 5936 §2.2).
// Access is restricted via IP/CIDR whitelist.
type AXFRHandler struct {
	zones   *ZoneManager
	allowed atomic.Value // *[]*net.IPNet — lock-free live-reload
}

// NewAXFRHandler creates a new AXFRHandler.
// allowedCIDRs is the whitelist of allowed client IPs/CIDRs.
// Empty list = reject all requests.
func NewAXFRHandler(zones *ZoneManager, allowedCIDRs []string) (*AXFRHandler, error) {
	h := &AXFRHandler{zones: zones}
	if err := h.Update(allowedCIDRs); err != nil {
		return nil, err
	}
	return h, nil
}

// Update replaces the allowed CIDRs at runtime (lock-free).
func (h *AXFRHandler) Update(allowedCIDRs []string) error {
	nets, err := parseCIDRs(allowedCIDRs)
	if err != nil {
		return fmt.Errorf("axfr: ungültige allowed_ips: %w", err)
	}
	h.allowed.Store(&nets)
	return nil
}

// parseCIDRs parses a list of IP addresses or CIDR ranges.
func parseCIDRs(cidrs []string) ([]*net.IPNet, error) {
	result := make([]*net.IPNet, 0, len(cidrs))
	for _, s := range cidrs {
		// Try to parse as CIDR
		_, ipNet, err := net.ParseCIDR(s)
		if err == nil {
			result = append(result, ipNet)
			continue
		}
		// Try to parse as single IP → /32 or /128
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("ungültige IP/CIDR: %q", s)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		result = append(result, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return result, nil
}

// isAllowed checks whether the given IP is in the whitelist.
func (h *AXFRHandler) isAllowed(ip net.IP) bool {
	ptr := h.allowed.Load().(*[]*net.IPNet)
	for _, n := range *ptr {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Handle processes AXFR and IXFR requests.
func (h *AXFRHandler) Handle(w mdns.ResponseWriter, r *mdns.Msg) {
	if len(r.Question) == 0 {
		respondErrorAXFR(w, r, mdns.RcodeFormatError)
		return
	}

	q := r.Question[0]
	clientIP := extractClientIP(w.RemoteAddr().String())

	// RFC 5936 §2.2: AXFR is only allowed over TCP
	// The ResponseWriter does not directly expose the network protocol,
	// but miekg/dns sets a *dns.tcp type for TCP connections.
	// Pragmatic test: AXFR over UDP → NOTIMP
	if !isTCPConnection(w) {
		log.Debug().
			Str("client", clientIP.String()).
			Str("qname", q.Name).
			Msg("AXFR über UDP abgelehnt (RFC 5936: nur TCP)")
		respondErrorAXFR(w, r, mdns.RcodeNotImplemented)
		return
	}

	// ACL check
	if !h.isAllowed(clientIP) {
		log.Info().
			Str("client", clientIP.String()).
			Str("qname", q.Name).
			Msg("AXFR verweigert: Client-IP nicht in Whitelist")
		respondErrorAXFR(w, r, mdns.RcodeRefused)
		return
	}

	// Find zone — default zones only (View = ""), no view context for zone transfers
	zone, subdomain := h.zones.FindZone("", q.Name)
	if zone == nil || subdomain != "@" {
		log.Debug().
			Str("client", clientIP.String()).
			Str("qname", q.Name).
			Msg("AXFR: Zone nicht gefunden")
		// NOTAUTH = Rcode 9
		respondErrorAXFR(w, r, mdns.RcodeNotAuth)
		return
	}

	qtypeStr := "AXFR"
	if q.Qtype == mdns.TypeIXFR {
		qtypeStr = "IXFR"
	}
	log.Info().
		Str("client", clientIP.String()).
		Str("zone", zone.Domain).
		Str("type", qtypeStr).
		Msg("Zone Transfer gestartet")

	h.serveAXFR(w, r, zone)
}

// serveAXFR transmits all zone records in RFC 5936-compliant TCP messages.
// Format: SOA → Records (in chunks) → SOA
func (h *AXFRHandler) serveAXFR(w mdns.ResponseWriter, r *mdns.Msg, zone *dns.Zone) {
	soaRR := h.buildSOARR(zone)
	fqdn := mdns.Fqdn(zone.Domain)

	// Convert all non-FWD records to RRs
	var records []mdns.RR
	for _, rec := range zone.Records {
		// Skip FWD records — not a DNS RR
		if rec.Type == dns.TypeFWD {
			continue
		}
		subdomain := rec.Name
		if subdomain == "" || subdomain == "@" {
			subdomain = "@"
		}
		rr := h.zones.recordToRR(zone, rec, subdomain)
		if rr == nil {
			continue
		}
		records = append(records, rr)
	}

	// Split all records into chunks + prepend and append SOA
	// First message: SOA + first chunk
	allRRs := make([]mdns.RR, 0, len(records)+2)
	allRRs = append(allRRs, soaRR)
	allRRs = append(allRRs, records...)
	allRRs = append(allRRs, soaRR)

	// Split into messages of axfrChunkSize RRs each
	for i := 0; i < len(allRRs); i += axfrChunkSize {
		end := i + axfrChunkSize
		if end > len(allRRs) {
			end = len(allRRs)
		}

		msg := new(mdns.Msg)
		msg.SetReply(r)
		msg.Authoritative = true
		msg.Answer = allRRs[i:end]

		// Ensure Question section is set correctly
		if len(msg.Question) == 0 {
			msg.Question = []mdns.Question{{
				Name:   fqdn,
				Qtype:  mdns.TypeAXFR,
				Qclass: mdns.ClassINET,
			}}
		}

		if err := w.WriteMsg(msg); err != nil {
			log.Error().Err(err).
				Str("zone", zone.Domain).
				Msg("AXFR: Fehler beim Schreiben der Antwort")
			return
		}
	}

	log.Info().
		Str("zone", zone.Domain).
		Int("records", len(records)).
		Msg("Zone Transfer abgeschlossen")
}

// buildSOARR builds the SOA RR for a zone.
// Uses zone.SOA if present, otherwise DefaultSOA.
func (h *AXFRHandler) buildSOARR(zone *dns.Zone) *mdns.SOA {
	zone.EnsureSOA()
	soa := zone.SOA
	fqdn := mdns.Fqdn(zone.Domain)

	ttl := uint32(zone.TTL)
	if ttl == 0 {
		ttl = 3600
	}

	return &mdns.SOA{
		Hdr: mdns.RR_Header{
			Name:   fqdn,
			Rrtype: mdns.TypeSOA,
			Class:  mdns.ClassINET,
			Ttl:    ttl,
		},
		Ns:      mdns.Fqdn(soa.MName),
		Mbox:    mdns.Fqdn(soa.RName),
		Serial:  soa.Serial,
		Refresh: uint32(soa.Refresh),
		Retry:   uint32(soa.Retry),
		Expire:  uint32(soa.Expire),
		Minttl:  uint32(soa.Minimum),
	}
}

// isTCPConnection checks whether the connection is over TCP.
// miekg/dns sets RemoteAddr as net.TCPAddr for TCP connections.
func isTCPConnection(w mdns.ResponseWriter) bool {
	if w == nil {
		return false
	}
	addr := w.RemoteAddr()
	if addr == nil {
		return false
	}
	_, ok := addr.(*net.TCPAddr)
	return ok
}

// respondErrorAXFR sends an error response for AXFR/IXFR.
func respondErrorAXFR(w mdns.ResponseWriter, r *mdns.Msg, rcode int) {
	m := new(mdns.Msg)
	m.SetRcode(r, rcode)
	if err := w.WriteMsg(m); err != nil {
		log.Error().Err(err).Msg("axfr: Fehler beim Schreiben der Fehlerantwort")
	}
}
