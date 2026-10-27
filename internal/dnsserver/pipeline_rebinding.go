package dnsserver

import (
	"time"

	"github.com/mw7101/domudns/internal/querylog"
	"github.com/mw7101/domudns/pkg/metrics"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// rebindingPhase checks upstream responses for DNS rebinding attacks.
// Pipeline phase 5.5.
// NOTE: This phase runs AFTER forwardPhase. It is only meaningful when
// forwardPhase stores the upstream response in queryContext instead of
// writing it directly. In the current pipeline design, forwardPhase
// always returns done=true, so this phase is a no-op safety net.
// It is kept for future refactoring where forward may pass results down.
func (h *Handler) rebindingPhase(ctx *queryContext) pipelineResult {
	// In the current design, rebinding protection is integrated into
	// forwardPhase. This phase exists as a pipeline placeholder.
	_ = ctx
	return pipelineResult{}
}

// checkRebinding is called from forwardPhase to check an upstream response.
// Returns true if the response should be blocked as a rebinding attack.
func (h *Handler) checkRebinding(ctx *queryContext, resp *dns.Msg, upstream string) bool {
	if !h.rebinding.IsRebindingAttack(ctx.question.Name, resp) {
		return false
	}

	qtype := dns.TypeToString[ctx.question.Qtype]
	start := time.Now()

	log.Warn().
		Str("domain", ctx.question.Name).
		Str("client", ctx.clientIP.String()).
		Str("upstream", upstream).
		Msg("DNS rebinding attack blocked: external domain resolves to private IP")
	metrics.DNSQueriesTotal.WithLabelValues(qtype, "blocked").Inc()
	metrics.DNSQueryDuration.WithLabelValues("blocked").Observe(time.Since(start).Seconds())
	h.queryLogger.LogQuery(ctx.clientIP.String(), ctx.question.Name, qtype, querylog.ResultBlocked, upstream, time.Since(start), dns.RcodeNameError)
	h.respondError(ctx.w, ctx.req, dns.RcodeNameError)
	return true
}
