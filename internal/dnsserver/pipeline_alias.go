package dnsserver

import (
	"time"

	"github.com/mw7101/domudns/internal/querylog"
	"github.com/mw7101/domudns/pkg/metrics"
	mdns "github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// aliasPhase resolves an ALIAS record target and synthesizes A/AAAA records.
// Called from zonePhase when zoneResponse.aliasTarget != "".
// Pipeline phase 3 (ALIAS branch).
//
// Resolution order (R4):
//  1. In-zone: ZoneManager.FindZone → GenerateResponse
//  2. Upstream: h.forwarder.ForwardTracked
//
// The ALIAS record itself is never included in the response (R8).
// Synthesized records carry Authoritative=true (R10) and target TTL (R5).
// Known limitation: rebinding protection does not apply (v1).
func (h *Handler) aliasPhase(ctx *queryContext, zr zoneResponse, clientView string) pipelineResult {
	start := time.Now()
	qtype := mdns.TypeToString[ctx.question.Qtype]

	// Build a synthetic request for the target FQDN with the same query type.
	targetReq := new(mdns.Msg)
	targetReq.SetQuestion(mdns.Fqdn(zr.aliasTarget), ctx.question.Qtype)

	var sourceRRs []mdns.RR

	// Step 1: in-zone resolution.
	if h.zones != nil {
		targetZone, targetSub := h.zones.FindZone(clientView, mdns.Fqdn(zr.aliasTarget))
		if targetZone != nil {
			targetZR := h.zones.GenerateResponse(targetReq, targetZone, targetSub)
			if targetZR.aliasTarget != "" {
				// Chained ALIAS — not supported in v1. Fall through to upstream.
				log.Warn().
					Str("alias_target", zr.aliasTarget).
					Msg("ALIAS: chained ALIAS not supported in v1, falling back to upstream")
			} else {
				sourceRRs = targetZR.msg.Answer
			}
		}
	}

	// Step 2: upstream resolution if in-zone produced no records.
	// ForwardTracked uses its own 2s per-call timeout internally.
	if len(sourceRRs) == 0 {
		if h.forwarder == nil {
			log.Warn().Str("alias_target", zr.aliasTarget).Msg("ALIAS: no forwarder configured, returning SERVFAIL")
			return h.aliasServfail(ctx, zr.msg, start, qtype)
		}

		// ForwardTracked returns (*dns.Msg, string, error) — second value is the server that responded.
		upstreamResp, _, err := h.forwarder.ForwardTracked(targetReq)
		if err != nil || upstreamResp == nil || upstreamResp.Rcode == mdns.RcodeServerFailure {
			log.Warn().
				Err(err).
				Str("alias_target", zr.aliasTarget).
				Msg("ALIAS: upstream resolution failed, returning SERVFAIL")
			return h.aliasServfail(ctx, zr.msg, start, qtype)
		}
		sourceRRs = upstreamResp.Answer
	}

	// Step 3: synthesize response — replace qname with original query name.
	resp := zr.msg // NOERROR shell, Authoritative=true
	origName := mdns.Fqdn(ctx.question.Name)
	for _, rr := range sourceRRs {
		// Clone and rewrite the owner name to the original query name.
		clone := mdns.Copy(rr)
		clone.Header().Name = origName
		resp.Answer = append(resp.Answer, clone)
	}

	if len(resp.Answer) == 0 {
		// Target resolved but returned no A/AAAA — treat as SERVFAIL.
		return h.aliasServfail(ctx, resp, start, qtype)
	}

	// Step 4: write response.
	if err := ctx.w.WriteMsg(resp); err != nil {
		log.Error().Err(err).Msg("ALIAS: failed to write response")
	}

	// Step 5: cache synthesized response.
	if h.cache != nil {
		h.cache.Set(ctx.question.Name, ctx.question.Qtype, resp)
	}

	metrics.DNSQueriesTotal.WithLabelValues(qtype, "authoritative").Inc()
	metrics.DNSQueryDuration.WithLabelValues("authoritative").Observe(time.Since(start).Seconds())
	if h.queryLogger != nil {
		h.queryLogger.LogQuery(ctx.clientIP.String(), ctx.question.Name, qtype, querylog.ResultAuthoritative, "", time.Since(start), resp.Rcode)
	}

	return pipelineResult{msg: resp, done: true}
}

func (h *Handler) aliasServfail(ctx *queryContext, shell *mdns.Msg, start time.Time, qtype string) pipelineResult {
	shell.Rcode = mdns.RcodeServerFailure
	if err := ctx.w.WriteMsg(shell); err != nil {
		log.Error().Err(err).Msg("ALIAS: failed to write SERVFAIL")
	}
	metrics.DNSQueriesTotal.WithLabelValues(qtype, "servfail").Inc()
	metrics.DNSQueryDuration.WithLabelValues("authoritative").Observe(time.Since(start).Seconds())
	return pipelineResult{msg: shell, done: true}
}
