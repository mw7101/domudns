package dnsserver

import (
	"fmt"
	"net"
	"sync/atomic"

	"github.com/mw7101/domudns/internal/dns"
)

// ClientGroupResolver maps client IPs to active blocklist categories.
// Uses atomic.Value for lock-free reads — analogous to SplitHorizonResolver.
type ClientGroupResolver struct {
	groups atomic.Value // stores []resolvedGroup
}

type resolvedGroup struct {
	name       string
	nets       []*net.IPNet
	categories []string
}

// NewClientGroupResolver creates a resolver with no groups (returns DefaultCategories for all IPs).
func NewClientGroupResolver() *ClientGroupResolver {
	r := &ClientGroupResolver{}
	r.groups.Store([]resolvedGroup{})
	return r
}

// Update parses the CIDRs and atomically replaces the group list.
// Returns an error if any CIDR is invalid; no partial update on error.
func (r *ClientGroupResolver) Update(groups []*dns.ClientGroup) error {
	resolved := make([]resolvedGroup, 0, len(groups))
	for _, g := range groups {
		nets := make([]*net.IPNet, 0, len(g.CIDRs))
		for _, cidr := range g.CIDRs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("client group %q: invalid CIDR %q: %w", g.Name, cidr, err)
			}
			nets = append(nets, ipNet)
		}
		cats := make([]string, len(g.Categories))
		copy(cats, g.Categories)
		resolved = append(resolved, resolvedGroup{
			name:       g.Name,
			nets:       nets,
			categories: cats,
		})
	}
	r.groups.Store(resolved)
	return nil
}

// GetCategories returns the enabled blocklist categories for the given client IP.
// First-match-wins. Returns dns.DefaultCategories() if no group matches or list is empty.
func (r *ClientGroupResolver) GetCategories(clientIP net.IP) []string {
	groups := r.groups.Load().([]resolvedGroup)
	for _, g := range groups {
		for _, ipNet := range g.nets {
			if ipNet.Contains(clientIP) {
				out := make([]string, len(g.categories))
				copy(out, g.categories)
				return out
			}
		}
	}
	return dns.DefaultCategories()
}
