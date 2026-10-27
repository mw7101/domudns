package dnsserver

import (
	"github.com/miekg/dns"
)

// ddnsPhase handles RFC 2136 UPDATE messages.
// Pipeline phase 2a.
func (h *Handler) ddnsPhase(ctx *queryContext) pipelineResult {
	if ctx.req.Opcode != dns.OpcodeUpdate {
		return pipelineResult{}
	}

	if h.ddns != nil {
		h.ddns.Handle(ctx.w, ctx.req)
	} else {
		h.respondError(ctx.w, ctx.req, dns.RcodeRefused)
	}
	return pipelineResult{done: true}
}
