package dnsserver

import (
	"context"
	"strings"
	"time"

	"github.com/mw7101/domudns/internal/querylog"
	"github.com/mw7101/domudns/pkg/metrics"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// acmePhase serves ACME DNS-01 challenge TXT records.
// Pipeline phase 2.9.
func (h *Handler) acmePhase(ctx *queryContext) pipelineResult {
	if h.acme == nil {
		return pipelineResult{}
	}
	if ctx.question.Qtype != dns.TypeTXT {
		return pipelineResult{}
	}
	// DNS names are case-insensitive (RFC 1035); miekg/dns preserves original case.
	if !strings.HasPrefix(strings.ToLower(ctx.question.Name), "_acme-challenge.") {
		return pipelineResult{}
	}

	txtVal, ok := h.acme.GetACMEChallenge(context.Background(), ctx.question.Name)
	if !ok {
		return pipelineResult{}
	}

	qtype := dns.TypeToString[ctx.question.Qtype]
	start := time.Now()

	m := new(dns.Msg)
	m.SetReply(ctx.req)
	m.Authoritative = true
	m.Answer = append(m.Answer, &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   ctx.question.Name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		Txt: []string{txtVal},
	})

	metrics.DNSQueriesTotal.WithLabelValues(qtype, "authoritative").Inc()
	metrics.DNSQueryDuration.WithLabelValues("authoritative").Observe(time.Since(start).Seconds())
	h.queryLogger.LogQuery(ctx.clientIP.String(), ctx.question.Name, qtype, querylog.ResultAuthoritative, "", time.Since(start), dns.RcodeSuccess)

	if err := ctx.w.WriteMsg(m); err != nil {
		log.Error().Err(err).Msg("failed to write ACME challenge response")
	}
	return pipelineResult{msg: m, done: true}
}
