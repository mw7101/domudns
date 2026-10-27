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
//  2. Upstream: the shared forward path (DNSSEC preparation, singleflight dedup)
//
// The ALIAS record itself is never included in the response (R8).
// Synthesized records carry Authoritative=true (R10) and target TTL (R5).
// Upstream answers pass the same gates as the plain forward phase: rebinding
// protection (phase 5.5) and DNSSEC processing — see resolveAliasUpstream.
func (h *Handler) aliasPhase(ctx *queryContext, zr zoneResponse, clientView string) pipelineResult {
	start := time.Now()
	qtype := mdns.TypeToString[ctx.question.Qtype]

	// Steps 1+2: in-zone resolution, then upstream if that produced nothing.
	sourceRRs, ok, blocked := h.resolveAliasRRs(ctx, clientView, zr.aliasTarget, ctx.question.Qtype)
	if blocked {
		// Rebinding attack: blockRebinding already answered NXDOMAIN.
		return pipelineResult{done: true}
	}
	if !ok {
		return h.aliasServfail(ctx, zr.msg, start, qtype)
	}

	// Step 3: synthesize response — replace qname with original query name.
	// An empty answer here is NODATA, not SERVFAIL: the target resolved, it
	// simply has no records of the queried type (RFC 2308 §2.2), and the ALIAS
	// name itself exists. It has to be NOERROR, because stub resolvers query A
	// and AAAA in parallel: a SERVFAIL for the AAAA half made `ping`/`nslookup`
	// fail for names whose A record resolved fine.
	resp := buildAliasResponse(zr.msg, ctx.question.Name, sourceRRs) // NOERROR shell, Authoritative=true

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

// resolveAliasInZone attempts in-zone ALIAS resolution (R4 step 1): look up
// aliasTarget in the zone store and return its answer records. authoritative
// reports that a local zone owns the target, so the caller must not ask
// upstream: an empty answer is then the authoritative NODATA answer, not a
// reason to leak the name to a public resolver. A chained ALIAS (the target
// itself being an ALIAS) is not supported in v1: authoritative=false, so the
// caller falls back to upstream resolution.
func (h *Handler) resolveAliasInZone(clientView, aliasTarget string, targetReq *mdns.Msg) ([]mdns.RR, bool) {
	if h.zones == nil {
		return nil, false
	}
	targetZone, targetSub := h.zones.FindZone(clientView, mdns.Fqdn(aliasTarget))
	if targetZone == nil {
		return nil, false
	}
	targetZR := h.zones.GenerateResponse(targetReq, targetZone, targetSub)
	if targetZR.aliasTarget != "" {
		log.Warn().
			Str("alias_target", aliasTarget).
			Msg("ALIAS: chained ALIAS not supported in v1, falling back to upstream")
		return nil, false
	}
	return targetZR.msg.Answer, true
}

// resolveAliasUpstream attempts upstream ALIAS resolution (R4 step 2), used
// when in-zone resolution produced nothing. It goes through the shared upstream
// path (forwardRequestDeduped: DNSSEC preparation + singleflight dedup, which
// uses its own per-call timeout internally) and applies the same gates as the
// plain forward phase to the answer: rebinding protection (phase 5.5) and
// DNSSEC processing. blocked=true means the caller must stop — the NXDOMAIN
// answer has already been written. ok=false means the caller must SERVFAIL.
func (h *Handler) resolveAliasUpstream(ctx *queryContext, targetReq *mdns.Msg, aliasTarget string, qtype uint16) (rrs []mdns.RR, ok bool, blocked bool) {
	if h.forwarder == nil {
		log.Warn().Str("alias_target", aliasTarget).Msg("ALIAS: no forwarder configured, returning SERVFAIL")
		return nil, false, false
	}
	upstreamResp, upstream, err := h.forwardRequestDeduped(targetReq, aliasTarget, qtype)
	if err != nil || upstreamResp == nil || upstreamResp.Rcode == mdns.RcodeServerFailure {
		log.Warn().
			Err(err).
			Str("alias_target", aliasTarget).
			Msg("ALIAS: upstream resolution failed, returning SERVFAIL")
		return nil, false, false
	}
	// Phase 5.5: the upstream answer is synthesized into the client's answer, so
	// a public target resolving to a private IP must be blocked here too — the
	// plain forward path is never reached for an ALIAS query.
	if h.rebinding.IsRebindingAttack(aliasTarget, upstreamResp) {
		h.blockRebinding(ctx, aliasTarget, upstream)
		return nil, false, true
	}
	// Same DNSSEC handling as phase 5: propagate the AD bit, filter DNSSEC RRs
	// when the client sent no DO bit.
	upstreamResp = h.dnssec.ProcessResponse(ctx.req, upstreamResp)
	return upstreamResp.Answer, true, false
}

// resolveAliasRRs resolves an ALIAS target to its A/AAAA records: in-zone first
// (step 1), then via the upstream forwarder (step 2). ok=false means the target
// could not be resolved at all; blocked=true means the upstream answer was
// blocked as a rebinding attack and the response has already been written.
// Shared by aliasPhase and by pipeline_cname.go, which reaches an ALIAS record
// through a CNAME chain.
func (h *Handler) resolveAliasRRs(ctx *queryContext, clientView, aliasTarget string, qtype uint16) (rrs []mdns.RR, ok bool, blocked bool) {
	targetReq := new(mdns.Msg)
	targetReq.SetQuestion(mdns.Fqdn(aliasTarget), qtype)

	// A local zone owns the target: its answer is final, even when empty (the
	// target simply has no record of qtype). Only a target outside every local
	// zone is resolved upstream.
	if localRRs, authoritative := h.resolveAliasInZone(clientView, aliasTarget, targetReq); authoritative {
		return localRRs, true, false
	}
	return h.resolveAliasUpstream(ctx, targetReq, aliasTarget, qtype)
}

// buildAliasResponse clones sourceRRs into shell.Answer, rewriting each
// owner name to origName. shell is the NOERROR/Authoritative response
// shell from GenerateResponse; the ALIAS record itself is never included
// (R8).
func buildAliasResponse(shell *mdns.Msg, origName string, sourceRRs []mdns.RR) *mdns.Msg {
	shell.Answer = append(shell.Answer, synthesizeAliasRRs(origName, sourceRRs)...)
	return shell
}

// synthesizeAliasRRs returns copies of sourceRRs owned by origName. The ALIAS
// record itself never reaches the client (R8): either the queried name is
// rewritten onto the target's records (aliasPhase), or — for a CNAME chain
// ending in an ALIAS — the ALIAS owner name is, so the CNAME chain stays valid.
func synthesizeAliasRRs(origName string, sourceRRs []mdns.RR) []mdns.RR {
	origFQDN := mdns.Fqdn(origName)
	synthesized := make([]mdns.RR, 0, len(sourceRRs))
	for _, rr := range sourceRRs {
		clone := mdns.Copy(rr)
		clone.Header().Name = origFQDN
		synthesized = append(synthesized, clone)
	}
	return synthesized
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
