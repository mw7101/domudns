package dnsserver

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// ConditionalForwardRule maps a DNS domain to specific upstream servers.
type ConditionalForwardRule struct {
	Domain  string
	Servers []string
}

// ConditionalForwarder matches DNS queries against domain-specific forwarding rules.
// Rules are matched by longest suffix: "fritz.box" matches "mydevice.fritz.box" and "fritz.box".
type ConditionalForwarder struct {
	mu    sync.RWMutex
	rules []ConditionalForwardRule
}

// NewConditionalForwarder creates a ConditionalForwarder with the given rules.
func NewConditionalForwarder(rules []ConditionalForwardRule) *ConditionalForwarder {
	normalized := normalizeRules(rules)
	return &ConditionalForwarder{rules: normalized}
}

// Match returns the servers for the most specific matching rule, or nil if no rule matches.
func (cf *ConditionalForwarder) Match(qname string) []string {
	name := strings.ToLower(strings.TrimSuffix(qname, "."))
	cf.mu.RLock()
	rules := cf.rules
	cf.mu.RUnlock()

	var best *ConditionalForwardRule
	for i := range rules {
		r := &rules[i]
		if name == r.Domain || strings.HasSuffix(name, "."+r.Domain) {
			if best == nil || len(r.Domain) > len(best.Domain) {
				best = r
			}
		}
	}
	if best != nil {
		return best.Servers
	}
	return nil
}

// UpdateRules replaces the forwarding rules at runtime (thread-safe).
func (cf *ConditionalForwarder) UpdateRules(rules []ConditionalForwardRule) {
	normalized := normalizeRules(rules)
	cf.mu.Lock()
	cf.rules = normalized
	cf.mu.Unlock()
}

func normalizeRules(rules []ConditionalForwardRule) []ConditionalForwardRule {
	out := make([]ConditionalForwardRule, len(rules))
	for i, r := range rules {
		servers := make([]string, len(r.Servers))
		for j, s := range r.Servers {
			if _, _, err := net.SplitHostPort(s); err != nil {
				servers[j] = s + ":53"
			} else {
				servers[j] = s
			}
		}
		out[i] = ConditionalForwardRule{
			Domain:  strings.ToLower(strings.TrimSuffix(r.Domain, ".")),
			Servers: servers,
		}
	}
	return out
}

// Forwarder forwards DNS queries to upstream servers
type Forwarder struct {
	mu       sync.RWMutex
	upstream []string
	client   *dns.Client
	counter  uint32 // for round-robin
}

// NewForwarder creates a new upstream forwarder
func NewForwarder(upstream []string) *Forwarder {
	if len(upstream) == 0 {
		upstream = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}

	// Ensure :53 port for all upstreams
	for i, u := range upstream {
		if _, _, err := net.SplitHostPort(u); err != nil {
			upstream[i] = u + ":53"
		}
	}

	return &Forwarder{
		upstream: upstream,
		client: &dns.Client{
			Timeout: 2 * time.Second,
			Net:     "udp",
		},
	}
}

// UpdateUpstream replaces the upstream server list at runtime (thread-safe).
// The provided slice is defensively copied so that later changes to the
// caller's slice do not affect the internal state.
func (f *Forwarder) UpdateUpstream(upstream []string) {
	normalized := make([]string, len(upstream))
	for i, u := range upstream {
		if _, _, err := net.SplitHostPort(u); err != nil {
			normalized[i] = u + ":53"
		} else {
			normalized[i] = u
		}
	}
	f.mu.Lock()
	f.upstream = normalized
	f.mu.Unlock()
}

// ForwardToServers forwards a DNS query to a specific set of servers (FWD record support).
func (f *Forwarder) ForwardToServers(req *dns.Msg, servers []string) (*dns.Msg, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("no FWD servers configured")
	}
	idx := atomic.AddUint32(&f.counter, 1) % uint32(len(servers))
	server := servers[idx]

	resp, _, err := f.client.Exchange(req, server)
	if err == nil && !resp.Truncated {
		return resp, nil
	}
	tcpClient := &dns.Client{Timeout: 2 * time.Second, Net: "tcp"}
	resp, _, err = tcpClient.Exchange(req, server)
	if err != nil && len(servers) > 1 {
		fallback := servers[(int(idx)+1)%len(servers)]
		resp, _, err = f.client.Exchange(req, fallback)
	}
	return resp, err
}

// ForwardTracked forwards a DNS query to upstream servers and returns which server responded.
func (f *Forwarder) ForwardTracked(req *dns.Msg) (*dns.Msg, string, error) {
	f.mu.RLock()
	upstream := f.upstream
	f.mu.RUnlock()

	idx := atomic.AddUint32(&f.counter, 1) % uint32(len(upstream))
	server := upstream[idx]

	resp, _, err := f.client.Exchange(req, server)
	if err == nil && !resp.Truncated {
		return resp, server, nil
	}

	tcpClient := &dns.Client{Timeout: 2 * time.Second, Net: "tcp"}
	resp, _, err = tcpClient.Exchange(req, server)
	if err != nil {
		if len(upstream) > 1 {
			fallbackIdx := (idx + 1) % uint32(len(upstream))
			fallback := upstream[fallbackIdx]
			resp, _, err = f.client.Exchange(req, fallback)
			if err != nil {
				return nil, "", fmt.Errorf("all upstreams failed: %w", err)
			}
			return resp, fallback, nil
		}
		return nil, "", fmt.Errorf("upstream %s: %w", server, err)
	}
	return resp, server, nil
}

// Forward forwards a DNS query to upstream servers
func (f *Forwarder) Forward(req *dns.Msg) (*dns.Msg, error) {
	// Read upstream list thread-safely
	f.mu.RLock()
	upstream := f.upstream
	f.mu.RUnlock()

	// Round-robin upstream selection
	idx := atomic.AddUint32(&f.counter, 1) % uint32(len(upstream))
	server := upstream[idx]

	// Try UDP first
	resp, _, err := f.client.Exchange(req, server)
	if err == nil && !resp.Truncated {
		return resp, nil
	}

	// If truncated or UDP failed, try TCP
	tcpClient := &dns.Client{
		Timeout: 2 * time.Second,
		Net:     "tcp",
	}
	resp, _, err = tcpClient.Exchange(req, server)
	if err != nil {
		// Try fallback upstream
		if len(upstream) > 1 {
			fallbackIdx := (idx + 1) % uint32(len(upstream))
			fallback := upstream[fallbackIdx]
			resp, _, err = f.client.Exchange(req, fallback)
			if err != nil {
				return nil, fmt.Errorf("all upstreams failed: %w", err)
			}
		} else {
			return nil, fmt.Errorf("upstream %s: %w", server, err)
		}
	}

	return resp, nil
}
