package dnsserver

import (
	"time"

	"github.com/mw7101/domudns/internal/querylog"
	"github.com/mw7101/domudns/pkg/metrics"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// cachePhase checks the LRU cache for a cached response.
// Pipeline phase 4.
func (h *Handler) cachePhase(ctx *queryContext) pipelineResult {
	if h.cache == nil {
		return pipelineResult{}
	}

	cached := h.cache.Get(ctx.question.Name, ctx.question.Qtype)
	if cached == nil {
		log.Debug().
			Str("qname", ctx.question.Name).
			Str("qtype", dns.TypeToString[ctx.question.Qtype]).
			Msg("cache miss")
		return pipelineResult{}
	}

	qtype := dns.TypeToString[ctx.question.Qtype]
	start := time.Now()

	log.Debug().
		Str("qname", ctx.question.Name).
		Str("qtype", qtype).
		Msg("cache hit")

	// Update message ID to match request.
	cached.Id = ctx.req.Id
	cached = h.dnssec.ProcessResponse(ctx.req, cached)
	if err := ctx.w.WriteMsg(cached); err != nil {
		log.Error().Err(err).Msg("failed to write cached response")
	}
	metrics.DNSQueriesTotal.WithLabelValues(qtype, "cached").Inc()
	metrics.DNSQueryDuration.WithLabelValues("cached").Observe(time.Since(start).Seconds())
	h.queryLogger.LogQuery(ctx.clientIP.String(), ctx.question.Name, qtype, querylog.ResultCached, "", time.Since(start), cached.Rcode)
	return pipelineResult{msg: cached, done: true, cached: true}
}
