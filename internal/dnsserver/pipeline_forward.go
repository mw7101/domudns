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
	if result, matched := h.conditionalForwardPhase(ctx); matched {
		return result
	}
	return h.upstreamForwardPhase(ctx)
}

// conditionalForwardPhase implements phase 4.5: domain-specific upstream
// servers. matched=false means no rule applied the caller falls through to
// phase 5 (plain upstream forwarding); matched=true means result is final
// (already written) regardless of whether it succeeded.
func (h *Handler) conditionalForwardPhase(ctx *queryContext) (pipelineResult, bool) {
	if h.conditionalForwarder == nil {
		return pipelineResult{}, false
	}
	servers := h.conditionalForwarder.Match(ctx.question.Name)
	if len(servers) == 0 {
		return pipelineResult{}, false
	}

	qtype := dns.TypeToString[ctx.question.Qtype]
	start := time.Now()
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
		return pipelineResult{done: true}, true
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
	return pipelineResult{msg: cfResp, done: true}, true
}

// upstreamForwardPhase implements phase 5 (upstream forwarding with
// singleflight deduplication) and phase 5.5 (rebinding protection on the
// upstream response). Invariant: 5.5 must run after 5, before the response
// is cached or written — see internal/CLAUDE.md.
func (h *Handler) upstreamForwardPhase(ctx *queryContext) pipelineResult {
	qtype := dns.TypeToString[ctx.question.Qtype]
	start := time.Now()

	resp, upstream, err := h.forwardUpstreamDeduped(ctx)
	if err != nil {
		log.Error().Err(err).Str("qname", ctx.question.Name).Msg("forward error")
		metrics.DNSQueriesTotal.WithLabelValues(qtype, "error").Inc()
		metrics.DNSQueryDuration.WithLabelValues("error").Observe(time.Since(start).Seconds())
		h.queryLogger.LogQuery(ctx.clientIP.String(), ctx.question.Name, qtype, querylog.ResultError, "", time.Since(start), dns.RcodeServerFailure)
		h.respondError(ctx.w, ctx.req, dns.RcodeServerFailure)
		return pipelineResult{done: true}
	}

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

// forwardUpstreamDeduped forwards ctx.req upstream, deduplicating identical
// concurrent queries via singleflight, and returns a fresh copy of the
// shared response so each caller can set its own message ID.
func (h *Handler) forwardUpstreamDeduped(ctx *queryContext) (resp *dns.Msg, upstream string, err error) {
	return h.forwardRequestDeduped(ctx.req, ctx.question.Name, ctx.question.Qtype)
}

// forwardRequestDeduped is the single upstream code path: DNSSEC preparation,
// singleflight deduplication, and a fresh copy of the shared response.
// qname/qtype form the dedup key and normally mirror req's question;
// pipeline_cname.go passes the canonical name of a CNAME chain so that a
// chased lookup is deduplicated against plain queries for the same name.
func (h *Handler) forwardRequestDeduped(req *dns.Msg, qname string, qtype uint16) (resp *dns.Msg, upstream string, err error) {
	sfKey := qname + "/" + dns.TypeToString[qtype]
	sfVal, sfErr, _ := h.sfGroup.Do(sfKey, func() (interface{}, error) {
		prepared := h.dnssec.PrepareRequest(req)
		msg, up, err := h.forwarder.ForwardTracked(prepared)
		if err != nil {
			return nil, err
		}
		return &upstreamResult{resp: msg, upstream: up}, nil
	})
	if sfErr != nil {
		return nil, "", sfErr
	}
	sfResult := sfVal.(*upstreamResult)
	return sfResult.resp.Copy(), sfResult.upstream, nil
}
