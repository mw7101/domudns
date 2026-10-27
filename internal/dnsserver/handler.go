package dnsserver

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mw7101/domudns/internal/querylog"
	"github.com/mw7101/domudns/pkg/metrics"
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
	start := time.Now()

	// Validate request
	if len(r.Question) == 0 {
		h.respondError(w, r, dns.RcodeFormatError)
		return
	}

	q := r.Question[0]
	qtype := dns.TypeToString[q.Qtype]
	clientIP := extractClientIP(w.RemoteAddr().String())

	// Block ANY queries to prevent DNS amplification attacks (RFC 8482)
	if q.Qtype == dns.TypeANY {
		log.Debug().
			Str("client", clientIP.String()).
			Msg("refused ANY query (amplification protection)")
		h.respondError(w, r, dns.RcodeRefused)
		return
	}

	// Phase 2a: RFC 2136 UPDATE messages (DDNS)
	if r.Opcode == dns.OpcodeUpdate {
		if h.ddns != nil {
			h.ddns.Handle(w, r)
		} else {
			h.respondError(w, r, dns.RcodeRefused)
		}
		return
	}

	// Phase 2a.5: Zone Transfers (AXFR/IXFR, RFC 5936/1995)
	if len(r.Question) > 0 && (r.Question[0].Qtype == dns.TypeAXFR || r.Question[0].Qtype == dns.TypeIXFR) {
		if h.axfr != nil {
			h.axfr.Handle(w, r)
		} else {
			h.respondError(w, r, dns.RcodeRefused)
		}
		return
	}

	log.Debug().
		Str("qname", q.Name).
		Str("qtype", qtype).
		Str("client", clientIP.String()).
		Msg("DNS query")

	// Phase 2: Check blocklist with whitelist bypass
	if h.blocklist != nil {
		// Whitelist bypass: Skip blocklist for whitelisted IPs
		if !h.blocklist.IsWhitelisted(clientIP) {
			// Check if domain is blocked
			if h.blocklist.IsBlocked(q.Name) {
				log.Info().
					Str("domain", q.Name).
					Str("client", clientIP.String()).
					Msg("blocked domain")
				metrics.DNSQueriesTotal.WithLabelValues(qtype, "blocked").Inc()
				metrics.DNSQueryDuration.WithLabelValues("blocked").Observe(time.Since(start).Seconds())
				h.queryLogger.LogQuery(clientIP.String(), q.Name, qtype, querylog.ResultBlocked, "", time.Since(start), dns.RcodeSuccess)
				h.respondBlocked(w, r, q.Qtype)
				return
			}
		} else {
			log.Debug().
				Str("client", clientIP.String()).
				Msg("whitelisted IP, bypassing blocklist")
		}
	}

	// Phase 2.9: ACME DNS-01 challenges (_acme-challenge.* TXT)
	// DNS names are case-insensitive (RFC 1035); miekg/dns preserves original case.
	if h.acme != nil && q.Qtype == dns.TypeTXT && strings.HasPrefix(strings.ToLower(q.Name), "_acme-challenge.") {
		if txtVal, ok := h.acme.GetACMEChallenge(context.Background(), q.Name); ok {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				Txt: []string{txtVal},
			})
			if err := w.WriteMsg(m); err != nil {
				log.Error().Err(err).Msg("failed to write ACME challenge response")
			}
			metrics.DNSQueriesTotal.WithLabelValues(qtype, "authoritative").Inc()
			metrics.DNSQueryDuration.WithLabelValues("authoritative").Observe(time.Since(start).Seconds())
			h.queryLogger.LogQuery(clientIP.String(), q.Name, qtype, querylog.ResultAuthoritative, "", time.Since(start), dns.RcodeSuccess)
			return
		}
	}

	// Phase 3: Check authoritative zones
	// Split-Horizon: determine view name from Client-IP (Phase 3 Pre)
	clientView := ""
	if h.splitHorizon != nil {
		clientView = h.splitHorizon.GetView(clientIP)
	}

	if h.zones != nil {
		zone, subdomain := h.zones.FindZone(clientView, q.Name)
		if zone != nil {
			log.Debug().
				Str("qname", q.Name).
				Str("zone", zone.Domain).
				Str("subdomain", subdomain).
				Msg("authoritative zone match")

			resp := h.zones.GenerateResponse(r, zone, subdomain)

			// Phase 3.5: FWD fallback on NXDOMAIN
			if resp.Rcode == dns.RcodeNameError {
				if fwdServers := h.zones.FindFWDServers(zone); len(fwdServers) > 0 {
					log.Debug().
						Str("qname", q.Name).
						Strs("servers", fwdServers).
						Msg("FWD record: forwarding unresolved subdomain")
					fwdResp, fwdErr := h.forwarder.ForwardToServers(r, fwdServers)
					if fwdErr == nil {
						if h.cache != nil && (fwdResp.Rcode == dns.RcodeSuccess || fwdResp.Rcode == dns.RcodeNameError) {
							h.cache.Set(q.Name, q.Qtype, fwdResp)
						}
						if err := w.WriteMsg(fwdResp); err != nil {
							log.Error().Err(err).Msg("failed to write FWD response")
						}
						metrics.DNSQueriesTotal.WithLabelValues(qtype, "forwarded").Inc()
						metrics.DNSQueryDuration.WithLabelValues("forwarded").Observe(time.Since(start).Seconds())
						h.queryLogger.LogQuery(clientIP.String(), q.Name, qtype, querylog.ResultForwarded, fwdServers[0], time.Since(start), fwdResp.Rcode)
						return
					}
					log.Warn().Err(fwdErr).Str("qname", q.Name).Msg("FWD forward failed, returning NXDOMAIN")
				}
			}

			if err := w.WriteMsg(resp); err != nil {
				log.Error().Err(err).Msg("failed to write authoritative response")
			}
			metrics.DNSQueriesTotal.WithLabelValues(qtype, "authoritative").Inc()
			metrics.DNSQueryDuration.WithLabelValues("authoritative").Observe(time.Since(start).Seconds())
			h.queryLogger.LogQuery(clientIP.String(), q.Name, qtype, querylog.ResultAuthoritative, "", time.Since(start), resp.Rcode)
			return
		}
	}

	// Phase 4: Check cache
	if h.cache != nil {
		if cached := h.cache.Get(q.Name, q.Qtype); cached != nil {
			log.Debug().
				Str("qname", q.Name).
				Str("qtype", qtype).
				Msg("cache hit")

			// Update message ID to match request
			cached.Id = r.Id
			cached = h.dnssec.ProcessResponse(r, cached)
			if err := w.WriteMsg(cached); err != nil {
				log.Error().Err(err).Msg("failed to write cached response")
			}
			metrics.DNSQueriesTotal.WithLabelValues(qtype, "cached").Inc()
			metrics.DNSQueryDuration.WithLabelValues("cached").Observe(time.Since(start).Seconds())
			h.queryLogger.LogQuery(clientIP.String(), q.Name, qtype, querylog.ResultCached, "", time.Since(start), cached.Rcode)
			return
		}
		log.Debug().
			Str("qname", q.Name).
			Str("qtype", qtype).
			Msg("cache miss")
	}

	// Phase 4.5: Conditional Forwarding — domain-specific upstream servers
	if h.conditionalForwarder != nil {
		if servers := h.conditionalForwarder.Match(q.Name); len(servers) > 0 {
			log.Debug().
				Str("qname", q.Name).
				Strs("servers", servers).
				Msg("conditional forward match")
			cfReq := h.dnssec.PrepareRequest(r)
			cfResp, cfErr := h.forwarder.ForwardToServers(cfReq, servers)
			if cfErr != nil {
				log.Error().Err(cfErr).Str("qname", q.Name).Msg("conditional forward error")
				metrics.DNSQueriesTotal.WithLabelValues(qtype, "error").Inc()
				metrics.DNSQueryDuration.WithLabelValues("error").Observe(time.Since(start).Seconds())
				h.queryLogger.LogQuery(clientIP.String(), q.Name, qtype, querylog.ResultError, "", time.Since(start), dns.RcodeServerFailure)
				h.respondError(w, r, dns.RcodeServerFailure)
				return
			}
			if h.cache != nil && (cfResp.Rcode == dns.RcodeSuccess || cfResp.Rcode == dns.RcodeNameError) {
				h.cache.Set(q.Name, q.Qtype, cfResp)
			}
			cfResp = h.dnssec.ProcessResponse(r, cfResp)
			if err := w.WriteMsg(cfResp); err != nil {
				log.Error().Err(err).Msg("failed to write conditional forward response")
			}
			metrics.DNSQueriesTotal.WithLabelValues(qtype, "forwarded").Inc()
			metrics.DNSQueryDuration.WithLabelValues("forwarded").Observe(time.Since(start).Seconds())
			h.queryLogger.LogQuery(clientIP.String(), q.Name, qtype, querylog.ResultForwarded, servers[0], time.Since(start), cfResp.Rcode)
			return
		}
	}

	// Forward to upstream with singleflight deduplication: concurrent cache-miss requests
	// for the same domain+type share one upstream round-trip (thundering-herd protection).
	sfKey := q.Name + "/" + dns.TypeToString[q.Qtype]
	sfVal, sfErr, _ := h.sfGroup.Do(sfKey, func() (interface{}, error) {
		req := h.dnssec.PrepareRequest(r)
		msg, up, err := h.forwarder.ForwardTracked(req)
		if err != nil {
			return nil, err
		}
		return &upstreamResult{resp: msg, upstream: up}, nil
	})
	if sfErr != nil {
		log.Error().Err(sfErr).Str("qname", q.Name).Msg("forward error")
		metrics.DNSQueriesTotal.WithLabelValues(qtype, "error").Inc()
		metrics.DNSQueryDuration.WithLabelValues("error").Observe(time.Since(start).Seconds())
		h.queryLogger.LogQuery(clientIP.String(), q.Name, qtype, querylog.ResultError, "", time.Since(start), dns.RcodeServerFailure)
		h.respondError(w, r, dns.RcodeServerFailure)
		return
	}
	sfResult := sfVal.(*upstreamResult)
	// Copy the shared response so each caller can set its own message ID and process DNSSEC independently.
	resp := sfResult.resp.Copy()
	upstream := sfResult.upstream

	// Phase 5.5: DNS Rebinding Protection
	// Checks upstream responses for rebinding attacks (public domain → private IP).
	// Only check upstream responses — not authoritative zones or cache.
	if h.rebinding.IsRebindingAttack(q.Name, resp) {
		log.Warn().
			Str("domain", q.Name).
			Str("client", clientIP.String()).
			Str("upstream", upstream).
			Msg("DNS-Rebinding-Angriff blockiert: externe Domain löst auf private IP auf")
		metrics.DNSQueriesTotal.WithLabelValues(qtype, "blocked").Inc()
		metrics.DNSQueryDuration.WithLabelValues("blocked").Observe(time.Since(start).Seconds())
		h.queryLogger.LogQuery(clientIP.String(), q.Name, qtype, querylog.ResultBlocked, upstream, time.Since(start), dns.RcodeNameError)
		h.respondError(w, r, dns.RcodeNameError)
		return
	}

	// Cache only successful responses and NXDOMAIN, not transient errors like SERVFAIL
	if h.cache != nil && (resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError) {
		h.cache.Set(q.Name, q.Qtype, resp)
	}

	// DNSSEC: propagate AD-bit, filter DNSSEC RRs when client has no DO-bit (after cache set)
	resp = h.dnssec.ProcessResponse(r, resp)

	metrics.DNSQueriesTotal.WithLabelValues(qtype, "forwarded").Inc()
	metrics.DNSQueryDuration.WithLabelValues("forwarded").Observe(time.Since(start).Seconds())
	h.queryLogger.LogQuery(clientIP.String(), q.Name, qtype, querylog.ResultForwarded, upstream, time.Since(start), resp.Rcode)

	// Write response
	if err := w.WriteMsg(resp); err != nil {
		log.Error().Err(err).Msg("failed to write response")
	}
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
	if h.blockMode.Load().(string) == "nxdomain" {
		h.respondError(w, r, dns.RcodeNameError)
		return
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

	if err := w.WriteMsg(m); err != nil {
		log.Error().Err(err).Msg("failed to write blocked response")
	}
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
