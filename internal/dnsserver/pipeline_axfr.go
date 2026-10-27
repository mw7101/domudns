package dnsserver

import (
	"github.com/miekg/dns"
)

// axfrPhase handles AXFR/IXFR zone transfer requests.
// Pipeline phase 2a.5.
func (h *Handler) axfrPhase(ctx *queryContext) pipelineResult {
	if ctx.question.Qtype != dns.TypeAXFR && ctx.question.Qtype != dns.TypeIXFR {
		return pipelineResult{}
	}

	if h.axfr != nil {
		h.axfr.Handle(ctx.w, ctx.req)
	} else {
		h.respondError(ctx.w, ctx.req, dns.RcodeRefused)
	}
	return pipelineResult{done: true}
}
