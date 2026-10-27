package dnsserver

import (
	"time"

	"github.com/mw7101/domudns/internal/querylog"
	"github.com/mw7101/domudns/pkg/metrics"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// checkRebinding is called from forwardPhase to check an upstream response.
// Pipeline phase 5.5: rebinding protection is integrated directly into
// forwardPhase (there is no separate pipeline stage) because it must run
// on the upstream response before that phase writes it to the client.
// Returns true if the response should be blocked as a rebinding attack.
func (h *Handler) checkRebinding(ctx *queryContext, resp *dns.Msg, upstream string) bool {
	if !h.rebinding.IsRebindingAttack(ctx.question.Name, resp) {
		return false
	}

	h.blockRebinding(ctx, ctx.question.Name, upstream)
	return true
}

// blockRebinding logs a blocked rebinding attack, counts it and answers
// NXDOMAIN. domain is the name the upstream answer was fetched for: the
// original question, or the canonical name of a CNAME chain (pipeline_cname.go
// resolves those itself, so the check has to run there too).
func (h *Handler) blockRebinding(ctx *queryContext, domain, upstream string) {
	qtype := dns.TypeToString[ctx.question.Qtype]
	start := time.Now()

	log.Warn().
		Str("domain", domain).
		Str("client", ctx.clientIP.String()).
		Str("upstream", upstream).
		Msg("DNS rebinding attack blocked: external domain resolves to private IP")
	metrics.DNSQueriesTotal.WithLabelValues(qtype, "blocked").Inc()
	metrics.DNSQueryDuration.WithLabelValues("blocked").Observe(time.Since(start).Seconds())
	h.queryLogger.LogQuery(ctx.clientIP.String(), domain, qtype, querylog.ResultBlocked, upstream, time.Since(start), dns.RcodeNameError)
	h.respondError(ctx.w, ctx.req, dns.RcodeNameError)
}
