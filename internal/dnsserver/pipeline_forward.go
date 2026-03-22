package dnsserver

import (
	"time"

	"github.com/mw7101/domudns/internal/querylog"
	"github.com/mw7101/domudns/pkg/metrics"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// forwardPhase handles conditional forwarding and upstream forwarding with singleflight.
// Pipeline phases 4.5 + 5.
func (h *Handler) forwardPhase(ctx *queryContext) pipelineResult {
	qtype := dns.TypeToString[ctx.question.Qtype]
	start := time.Now()

	// Phase 4.5: Conditional Forwarding — domain-specific upstream servers.
	if h.conditionalForwarder != nil {
		if servers := h.conditionalForwarder.Match(ctx.question.Name); len(servers) > 0 {
			log.Debug().
				Str("qname", ctx.question.Name).
				Strs("servers", servers).
				Msg("conditional forward match")
			cfReq := h.dnssec.PrepareRequest(ctx.req)
			cfResp, cfErr := h.forwarder.ForwardToServers(cfReq, servers)
			if cfErr != nil {
				log.Error().Err(cfErr).Str("qname", ctx.question.Name).Msg("conditional forward error")
				metrics.DNSQueriesTotal.WithLabelValues(qtype, "error").Inc()
				metrics.DNSQueryDuration.WithLabelValues("error").Observe(time.Since(start).Seconds())
				h.queryLogger.LogQuery(ctx.clientIP.String(), ctx.question.Name, qtype, querylog.ResultError, "", time.Since(start), dns.RcodeServerFailure)
				h.respondError(ctx.w, ctx.req, dns.RcodeServerFailure)
				return pipelineResult{done: true}
			}
			if h.cache != nil && (cfResp.Rcode == dns.RcodeSuccess || cfResp.Rcode == dns.RcodeNameError) {
				h.cache.Set(ctx.question.Name, ctx.question.Qtype, cfResp)
			}
			cfResp = h.dnssec.ProcessResponse(ctx.req, cfResp)
			if err := ctx.w.WriteMsg(cfResp); err != nil {
				log.Error().Err(err).Msg("failed to write conditional forward response")
			}
			metrics.DNSQueriesTotal.WithLabelValues(qtype, "forwarded").Inc()
			metrics.DNSQueryDuration.WithLabelValues("forwarded").Observe(time.Since(start).Seconds())
			h.queryLogger.LogQuery(ctx.clientIP.String(), ctx.question.Name, qtype, querylog.ResultForwarded, servers[0], time.Since(start), cfResp.Rcode)
			return pipelineResult{msg: cfResp, done: true}
		}
	}

	// Phase 5: Upstream forwarding with singleflight deduplication.
	sfKey := ctx.question.Name + "/" + dns.TypeToString[ctx.question.Qtype]
	sfVal, sfErr, _ := h.sfGroup.Do(sfKey, func() (interface{}, error) {
		req := h.dnssec.PrepareRequest(ctx.req)
		msg, up, err := h.forwarder.ForwardTracked(req)
		if err != nil {
			return nil, err
		}
		return &upstreamResult{resp: msg, upstream: up}, nil
	})
	if sfErr != nil {
		log.Error().Err(sfErr).Str("qname", ctx.question.Name).Msg("forward error")
		metrics.DNSQueriesTotal.WithLabelValues(qtype, "error").Inc()
		metrics.DNSQueryDuration.WithLabelValues("error").Observe(time.Since(start).Seconds())
		h.queryLogger.LogQuery(ctx.clientIP.String(), ctx.question.Name, qtype, querylog.ResultError, "", time.Since(start), dns.RcodeServerFailure)
		h.respondError(ctx.w, ctx.req, dns.RcodeServerFailure)
		return pipelineResult{done: true}
	}
	sfResult := sfVal.(*upstreamResult)
	// Copy the shared response so each caller can set its own message ID.
	resp := sfResult.resp.Copy()
	upstream := sfResult.upstream

	// Phase 5.5: DNS Rebinding Protection
	// Check upstream responses for rebinding attacks (public domain → private IP).
	if h.checkRebinding(ctx, resp, upstream) {
		return pipelineResult{done: true}
	}

	// Cache only successful responses and NXDOMAIN, not transient errors like SERVFAIL.
	if h.cache != nil && (resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError) {
		h.cache.Set(ctx.question.Name, ctx.question.Qtype, resp)
	}

	// DNSSEC: propagate AD-bit, filter DNSSEC RRs when client has no DO-bit.
	resp = h.dnssec.ProcessResponse(ctx.req, resp)

	metrics.DNSQueriesTotal.WithLabelValues(qtype, "forwarded").Inc()
	metrics.DNSQueryDuration.WithLabelValues("forwarded").Observe(time.Since(start).Seconds())
	h.queryLogger.LogQuery(ctx.clientIP.String(), ctx.question.Name, qtype, querylog.ResultForwarded, upstream, time.Since(start), resp.Rcode)

	if err := ctx.w.WriteMsg(resp); err != nil {
		log.Error().Err(err).Msg("failed to write response")
	}
	return pipelineResult{msg: resp, done: true}
}
