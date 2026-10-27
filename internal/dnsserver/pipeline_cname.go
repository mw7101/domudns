package dnsserver

import (
	"strings"
	"time"

	"github.com/mw7101/domudns/internal/querylog"
	"github.com/mw7101/domudns/pkg/metrics"
	mdns "github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// cnamePhase follows a CNAME chain whose canonical name lies outside the queried
// zone (RFC 1034 §4.3.2, pipeline phase 3.4). Called from zonePhase when
// GenerateResponse reports zoneResponse.cnameTarget.
//
// DomU DNS is authoritative *and* a forwarder, so it can complete the chain for
// the client: musl (Alpine) and glibc getaddrinfo do not follow CNAMEs on their
// own and fail with EAI_NONAME ("bad address") when the answer carries only the
// CNAME. That is exactly what a record in one local zone pointing into another
// (e.g. s3-ext.example.local → minio.cln.example.local) produced.
//
// Resolution order:
//  1. Other local authoritative zones, view-aware and recursively — a chain may
//     cross more than two zones. A name whose zone holds an ALIAS record is
//     synthesized here too, so the chain does not dead-end on it.
//  2. Upstream forwarder, for A/AAAA only (address lookups are what getaddrinfo
//     needs; other query types keep the previous CNAME-only behavior).
//
// The CNAME RRs stay in the answer (unlike ALIAS, which clients never see) and
// the appended records keep their canonical owner names. A chain that cannot be
// completed is returned as-is (NOERROR + CNAME): that is what a plain
// authoritative server answers, so no client that copes with CNAMEs regresses.
//
// Upstream answers pass the same gates as the plain forward path (phase 5):
// singleflight deduplication, DNSSEC preparation/processing and rebinding
// protection — otherwise a chased lookup would bypass phase 5.5.
func (h *Handler) cnamePhase(ctx *queryContext, zr zoneResponse, clientView string) pipelineResult {
	start := time.Now()
	qtype := mdns.TypeToString[ctx.question.Qtype]

	resp := zr.msg
	target := zr.cnameTarget
	seen := map[string]bool{
		strings.ToLower(strings.TrimSuffix(ctx.question.Name, ".")): true,
	}

	for depth := 0; depth < maxCNAMEChainDepth && target != ""; depth++ {
		key := strings.ToLower(strings.TrimSuffix(target, "."))
		if seen[key] {
			log.Warn().
				Str("qname", ctx.question.Name).
				Str("canonical", key).
				Msg("CNAME chase: loop detected, returning the chain as-is")
			break
		}
		seen[key] = true

		targetReq := new(mdns.Msg)
		targetReq.SetQuestion(mdns.Fqdn(target), ctx.question.Qtype)

		// Step 1: another local authoritative zone (view-aware).
		if targetZone, targetSub := h.zones.FindZone(clientView, mdns.Fqdn(target)); targetZone != nil {
			targetZR := h.zones.GenerateResponse(targetReq, targetZone, targetSub)
			resp.Answer = append(resp.Answer, targetZR.msg.Answer...)

			if targetZR.aliasTarget != "" {
				if h.appendAliasTarget(ctx, resp, clientView, target, targetZR.aliasTarget) {
					// Rebinding attack: blockRebinding already answered NXDOMAIN.
					return pipelineResult{done: true}
				}
				break
			}
			target = targetZR.cnameTarget
			continue
		}

		// Step 2: the target is in no local zone — ask the upstream forwarder.
		// Only address queries: for other types the client can follow the CNAME
		// itself, and the ALIAS phase restricts itself the same way.
		if ctx.question.Qtype != mdns.TypeA && ctx.question.Qtype != mdns.TypeAAAA {
			break
		}
		if h.forwarder == nil {
			break
		}
		upstreamResp, upstream, err := h.forwardRequestDeduped(targetReq, target, ctx.question.Qtype)
		if err != nil || upstreamResp == nil || upstreamResp.Rcode == mdns.RcodeServerFailure {
			log.Warn().
				Err(err).
				Str("qname", ctx.question.Name).
				Str("canonical", target).
				Msg("CNAME chase: upstream resolution failed, returning the chain as-is")
			break
		}
		// Phase 5.5: the upstream answer is about to reach the client, so a
		// public canonical name resolving to a private IP must be blocked here
		// as well — the plain path is never reached for this query.
		if h.rebinding.IsRebindingAttack(target, upstreamResp) {
			h.blockRebinding(ctx, target, upstream)
			return pipelineResult{done: true}
		}
		// Same DNSSEC handling as phase 5: propagate the AD bit, filter DNSSEC
		// RRs when the client sent no DO bit.
		upstreamResp = h.dnssec.ProcessResponse(ctx.req, upstreamResp)

		log.Debug().
			Str("qname", ctx.question.Name).
			Str("canonical", target).
			Str("upstream", upstream).
			Msg("CNAME chase: canonical name resolved upstream")
		resp.Answer = append(resp.Answer, upstreamResp.Answer...)
		break
	}

	if err := ctx.w.WriteMsg(resp); err != nil {
		log.Error().Err(err).Msg("CNAME chase: failed to write response")
	}
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

// appendAliasTarget synthesizes the A/AAAA records of an ALIAS record that a
// CNAME chain ended on. The ALIAS itself stays invisible (R8), so the records
// are owned by the ALIAS's name — the canonical name the chain reached — which
// keeps the chain valid for stub resolvers. It reports whether the upstream
// answer was a rebinding attack (the response has then already been written as
// NXDOMAIN and the caller must stop).
func (h *Handler) appendAliasTarget(ctx *queryContext, resp *mdns.Msg, clientView, aliasOwner, aliasTarget string) bool {
	rrs, ok, blocked := h.resolveAliasRRs(ctx, clientView, aliasTarget, ctx.question.Qtype)
	if blocked {
		return true
	}
	if !ok {
		log.Warn().
			Str("qname", ctx.question.Name).
			Str("alias_owner", aliasOwner).
			Str("alias_target", aliasTarget).
			Msg("CNAME chase: chain ends in an unresolvable ALIAS record")
		return false
	}
	resp.Answer = append(resp.Answer, synthesizeAliasRRs(aliasOwner, rrs)...)
	return false
}
