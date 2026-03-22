package dnsserver

import (
	"net"

	"github.com/miekg/dns"
)

// pipelineResult is returned by each phase.
// done=true means the answer is complete and the pipeline stops.
type pipelineResult struct {
	msg    *dns.Msg
	done   bool
	cached bool
}

// pipelinePhase is the function signature for a DNS pipeline phase.
type pipelinePhase func(ctx *queryContext) pipelineResult

// queryContext carries all per-request state through the pipeline.
type queryContext struct {
	w        dns.ResponseWriter
	req      *dns.Msg
	clientIP net.IP
	question dns.Question // req.Question[0]
	handler  *Handler     // access to sfGroup, blockMode, blocklist, cache, etc.
}
