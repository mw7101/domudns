package dnsserver

import (
	"net"
	"sync/atomic"

	"github.com/mw7101/domudns/internal/querylog"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/singleflight"
)

// upstreamResult is the shared result type used by sfGroup (singleflight).
type upstreamResult struct {
	resp     *dns.Msg
	upstream string
}

// Handler handles DNS queries
type Handler struct {
	forwarder            *Forwarder
	conditionalForwarder *ConditionalForwarder
	blocklist            *BlocklistManager
	zones                *ZoneManager
	cache                *CacheManager
	blockIP4             string
	blockIP6             string
	queryLogger          *querylog.QueryLogger
	// blockMode is atomically readable/writable for live-reload without mutex.
	// Values: "zero_ip" (default) | "nxdomain"
	blockMode atomic.Value
	// dnssec implements AD-flag delegation (stub resolver mode, RFC 4035).
	dnssec *DNSSECValidator
	// rebinding checks upstream responses for DNS rebinding attacks.
	rebinding *RebindingProtector
	// ddns processes RFC 2136 UPDATE messages (nil = disabled).
	ddns *DDNSHandler
	// axfr processes AXFR/IXFR zone transfer requests (nil = disabled).
	axfr *AXFRHandler
	// splitHorizon determines the view name for requesting clients (nil = disabled).
	splitHorizon *SplitHorizonResolver
	// acme serves ACME DNS-01 challenges as TXT records (nil = disabled).
	acme ACMEChallengeReader
	// sfGroup deduplicates concurrent upstream requests for the same domain+type
	// (thundering-herd protection on cache misses).
	sfGroup singleflight.Group
}

// NewHandler creates a new DNS query handler
func NewHandler(upstream []string, blocklist *BlocklistManager, zones *ZoneManager, cache *CacheManager, blockIP4, blockIP6 string, queryLogger *querylog.QueryLogger, dnssecEnabled bool) *Handler {
	h := &Handler{
		forwarder:   NewForwarder(upstream),
		blocklist:   blocklist,
		zones:       zones,
		cache:       cache,
		blockIP4:    blockIP4,
		blockIP6:    blockIP6,
		queryLogger: queryLogger,
		dnssec:      NewDNSSECValidator(dnssecEnabled),
		rebinding:   NewRebindingProtector(false, nil),
	}
	h.blockMode.Store("zero_ip")
	return h
}

// SetDDNSHandler sets the RFC 2136 DDNS handler (nil = disabled).
func (h *Handler) SetDDNSHandler(d *DDNSHandler) {
	h.ddns = d
}

// SetAXFRHandler sets the AXFR/IXFR handler (nil = disabled).
func (h *Handler) SetAXFRHandler(a *AXFRHandler) {
	h.axfr = a
}

// SetSplitHorizonResolver sets the split-horizon resolver (nil = disabled).
func (h *Handler) SetSplitHorizonResolver(r *SplitHorizonResolver) {
	h.splitHorizon = r
}

// SetACMEChallengeReader sets the ACME challenge reader (nil = disabled).
func (h *Handler) SetACMEChallengeReader(r ACMEChallengeReader) {
	h.acme = r
}

// UpdateRebindingProtection updates the rebinding protection configuration at runtime.
func (h *Handler) UpdateRebindingProtection(enabled bool, whitelist []string) {
	h.rebinding.Update(enabled, whitelist)
	log.Info().Bool("enabled", enabled).Msg("rebinding protection updated")
}

// UpdateBlockMode sets the block response mode at runtime (no restart required).
// Valid values: "zero_ip" (default) | "nxdomain"
func (h *Handler) UpdateBlockMode(mode string) {
	if mode != "nxdomain" {
		mode = "zero_ip"
	}
	h.blockMode.Store(mode)
	log.Info().Str("block_mode", mode).Msg("block mode updated")
}

// ServeDNS implements dns.Handler interface
func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	// Validate request
	if len(r.Question) == 0 {
		h.respondError(w, r, dns.RcodeFormatError)
		return
	}

	q := r.Question[0]

	// Block ANY queries to prevent DNS amplification attacks (RFC 8482)
	if q.Qtype == dns.TypeANY {
		clientIP := extractClientIP(w.RemoteAddr().String())
		log.Debug().
			Str("client", clientIP.String()).
			Msg("refused ANY query (amplification protection)")
		h.respondError(w, r, dns.RcodeRefused)
		return
	}

	ctx := &queryContext{
		w:        w,
		req:      r,
		clientIP: extractClientIP(w.RemoteAddr().String()),
		question: q,
		handler:  h,
	}

	// DDNS and AXFR are handled first (before the standard query debug log).
	for _, earlyPhase := range []pipelinePhase{h.ddnsPhase, h.axfrPhase} {
		if result := earlyPhase(ctx); result.done {
			return
		}
	}

	qtype := dns.TypeToString[q.Qtype]
	log.Debug().
		Str("qname", q.Name).
		Str("qtype", qtype).
		Str("client", ctx.clientIP.String()).
		Msg("DNS query")

	phases := []pipelinePhase{
		h.blocklistPhase,
		h.acmePhase,
		h.zonePhase,
		h.cachePhase,
		h.forwardPhase,
	}

	for _, phase := range phases {
		if result := phase(ctx); result.done {
			return
		}
	}

	// No phase handled the query — should not happen since forwardPhase always
	// returns done=true, but as a safety net return SERVFAIL.
	h.respondError(w, r, dns.RcodeServerFailure)
}

// respondError sends an error response
func (h *Handler) respondError(w dns.ResponseWriter, r *dns.Msg, rcode int) {
	m := new(dns.Msg)
	m.SetRcode(r, rcode)
	if err := w.WriteMsg(m); err != nil {
		log.Error().Err(err).Msg("failed to write error response")
	}
}

// respondBlocked sends a blocked response.
// Mode is set via UpdateBlockMode():
//   - "nxdomain": return NXDOMAIN — browser aborts immediately, no TLS timeout
//   - "zero_ip" (default): return 0.0.0.0 (A) or :: (AAAA)
func (h *Handler) respondBlocked(w dns.ResponseWriter, r *dns.Msg, qtype uint16) {
	m := h.buildBlockedResponse(r, qtype)
	if err := w.WriteMsg(m); err != nil {
		log.Error().Err(err).Msg("failed to write blocked response")
	}
}

// buildBlockedResponse creates a blocked response message without writing it.
func (h *Handler) buildBlockedResponse(r *dns.Msg, qtype uint16) *dns.Msg {
	mode, _ := h.blockMode.Load().(string)
	if mode == "nxdomain" {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		return m
	}

	// zero_ip mode: return sink IP
	m := new(dns.Msg)
	m.SetReply(r)

	q := r.Question[0]
	switch qtype {
	case dns.TypeA:
		if h.blockIP4 != "" {
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP(h.blockIP4),
			}
			m.Answer = append(m.Answer, rr)
		}
	case dns.TypeAAAA:
		if h.blockIP6 != "" {
			rr := &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				AAAA: net.ParseIP(h.blockIP6),
			}
			m.Answer = append(m.Answer, rr)
		}
	}
	return m
}

// extractClientIP extracts the IP address from a RemoteAddr string.
// RemoteAddr format: "IP:port" or "[IPv6]:port"
// Returns net.IPv4zero (0.0.0.0) as a safe fallback if the address cannot be parsed.
func extractClientIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// Fallback: try parsing as-is (may be IP without port in tests)
		if ip := net.ParseIP(remoteAddr); ip != nil {
			return ip
		}
		return net.IPv4zero
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}
	return net.IPv4zero
}
