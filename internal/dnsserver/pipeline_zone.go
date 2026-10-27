package dnsserver

import (
	"time"

	"github.com/mw7101/domudns/internal/dns"
	"github.com/mw7101/domudns/internal/querylog"
	"github.com/mw7101/domudns/pkg/metrics"
	mdns "github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// zonePhase checks authoritative zones including FWD fallback.
// Pipeline phase 3 (+ 3.5 FWD fallback).
func (h *Handler) zonePhase(ctx *queryContext) pipelineResult {
	if h.zones == nil {
		return pipelineResult{}
	}

	// Split-Horizon: determine view name from client IP.
	clientView := ""
	if h.splitHorizon != nil {
		clientView = h.splitHorizon.GetView(ctx.clientIP)
	}

	zone, subdomain := h.zones.FindZone(clientView, ctx.question.Name)
	if zone == nil {
		return pipelineResult{}
	}

	qtype := mdns.TypeToString[ctx.question.Qtype]
	start := time.Now()

	log.Debug().
		Str("qname", ctx.question.Name).
		Str("zone", zone.Domain).
		Str("subdomain", subdomain).
		Msg("authoritative zone match")

	zr := h.zones.GenerateResponse(ctx.req, zone, subdomain)

	// ALIAS branch: delegate to aliasPhase for transparent A/AAAA resolution.
	if zr.aliasTarget != "" {
		log.Debug().
			Str("qname", ctx.question.Name).
			Str("alias_target", zr.aliasTarget).
			Msg("ALIAS record: delegating to aliasPhase")
		return h.aliasPhase(ctx, zr, clientView)
	}

	// CNAME branch: the chain's canonical name lies outside this zone — continue
	// the lookup in the other local zones (RFC 1034 §4.3.2).
	if zr.cnameTarget != "" {
		log.Debug().
			Str("qname", ctx.question.Name).
			Str("cname_target", zr.cnameTarget).
			Msg("CNAME with out-of-zone target: delegating to cnamePhase")
		return h.cnamePhase(ctx, zr, clientView)
	}

	resp := zr.msg

	// Phase 3.5: FWD fallback on NXDOMAIN.
	if resp.Rcode == mdns.RcodeNameError {
		if result, ok := h.tryFWDFallback(ctx, zone, qtype, start); ok {
			return result
		}
	}

	if err := ctx.w.WriteMsg(resp); err != nil {
		log.Error().Err(err).Msg("failed to write authoritative response")
	}
	metrics.DNSQueriesTotal.WithLabelValues(qtype, "authoritative").Inc()
	metrics.DNSQueryDuration.WithLabelValues("authoritative").Observe(time.Since(start).Seconds())
	h.queryLogger.LogQuery(ctx.clientIP.String(), ctx.question.Name, qtype, querylog.ResultAuthoritative, "", time.Since(start), resp.Rcode)
	return pipelineResult{msg: resp, done: true}
}

// tryFWDFallback implements phase 3.5: when authoritative lookup returned
// NXDOMAIN, forward to the zone's FWD servers (if any) instead. ok=false
// means no FWD servers are configured, or forwarding failed — the caller
// falls back to returning the original NXDOMAIN.
func (h *Handler) tryFWDFallback(ctx *queryContext, zone *dns.Zone, qtype string, start time.Time) (pipelineResult, bool) {
	fwdServers := h.zones.FindFWDServers(zone)
	if len(fwdServers) == 0 {
		return pipelineResult{}, false
	}
	log.Debug().
		Str("qname", ctx.question.Name).
		Strs("servers", fwdServers).
		Msg("FWD record: forwarding unresolved subdomain")
	fwdResp, fwdErr := h.forwarder.ForwardToServers(ctx.req, fwdServers)
	if fwdErr != nil {
		log.Warn().Err(fwdErr).Str("qname", ctx.question.Name).Msg("FWD forward failed, returning NXDOMAIN")
		return pipelineResult{}, false
	}
	if h.cache != nil && (fwdResp.Rcode == mdns.RcodeSuccess || fwdResp.Rcode == mdns.RcodeNameError) {
		h.cache.Set(ctx.question.Name, ctx.question.Qtype, fwdResp)
	}
	if err := ctx.w.WriteMsg(fwdResp); err != nil {
		log.Error().Err(err).Msg("failed to write FWD response")
	}
	metrics.DNSQueriesTotal.WithLabelValues(qtype, "forwarded").Inc()
	metrics.DNSQueryDuration.WithLabelValues("forwarded").Observe(time.Since(start).Seconds())
	h.queryLogger.LogQuery(ctx.clientIP.String(), ctx.question.Name, qtype, querylog.ResultForwarded, fwdServers[0], time.Since(start), fwdResp.Rcode)
	return pipelineResult{msg: fwdResp, done: true}, true
}
