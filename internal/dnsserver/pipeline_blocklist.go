package dnsserver

import (
	"time"

	"github.com/mw7101/domudns/internal/querylog"
	"github.com/mw7101/domudns/pkg/metrics"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// blocklistPhase checks domain against the blocklist (with whitelist bypass).
// Pipeline phase 2.
func (h *Handler) blocklistPhase(ctx *queryContext) pipelineResult {
	if h.blocklist == nil {
		return pipelineResult{}
	}

	// Whitelist bypass: skip blocklist for whitelisted IPs.
	if h.blocklist.IsWhitelisted(ctx.clientIP) {
		log.Debug().
			Str("client", ctx.clientIP.String()).
			Msg("whitelisted IP, bypassing blocklist")
		return pipelineResult{}
	}

	// Check if domain is blocked.
	if !h.blocklist.IsBlocked(ctx.question.Name) {
		return pipelineResult{}
	}

	qtype := dns.TypeToString[ctx.question.Qtype]
	start := time.Now()

	log.Info().
		Str("domain", ctx.question.Name).
		Str("client", ctx.clientIP.String()).
		Msg("blocked domain")
	metrics.DNSQueriesTotal.WithLabelValues(qtype, "blocked").Inc()
	metrics.DNSQueryDuration.WithLabelValues("blocked").Observe(time.Since(start).Seconds())
	h.queryLogger.LogQuery(ctx.clientIP.String(), ctx.question.Name, qtype, querylog.ResultBlocked, "", time.Since(start), dns.RcodeSuccess)

	m := h.buildBlockedResponse(ctx.req, ctx.question.Qtype)
	if ctx.w != nil {
		if err := ctx.w.WriteMsg(m); err != nil {
			log.Error().Err(err).Msg("failed to write blocked response")
		}
	}
	return pipelineResult{msg: m, done: true}
}
