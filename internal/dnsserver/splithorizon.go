package dnsserver

import (
	"net"
	"sync/atomic"
)

// SplitHorizonView maps a view name to parsed CIDR ranges.
// Used by SplitHorizonResolver for CIDR matching.
type SplitHorizonView struct {
	Name    string
	Subnets []*net.IPNet // already parsed CIDRs
}

// splitHorizonConfig holds the active configuration.
// Swapped atomically as pointer for lock-free live-reload.
type splitHorizonConfig struct {
	enabled bool
	views   []SplitHorizonView
}

// SplitHorizonResolver determines the view name for a client IP.
// Thread-safe via atomic.Value (pointer swap, no mutex needed).
//
// Split-Horizon: Different clients get different answers for the same domain
// (e.g. LAN → 192.168.1.100, external → NXDOMAIN).
type SplitHorizonResolver struct {
	cfg atomic.Value // stores *splitHorizonConfig
}

// NewSplitHorizonResolver creates a new SplitHorizonResolver.
func NewSplitHorizonResolver(enabled bool, views []SplitHorizonView) *SplitHorizonResolver {
	r := &SplitHorizonResolver{}
	r.cfg.Store(&splitHorizonConfig{enabled: enabled, views: views})
	return r
}

// Update replaces the configuration at runtime (thread-safe, no restart needed).
func (r *SplitHorizonResolver) Update(enabled bool, views []SplitHorizonView) {
	r.cfg.Store(&splitHorizonConfig{enabled: enabled, views: views})
}

// GetView determines the view name for a client IP.
// Returns "" if split-horizon is disabled or no view matches.
// First-match-wins: the first view with matching subnet wins.
// A view with empty subnets is a catch-all (matches always).
func (r *SplitHorizonResolver) GetView(clientIP net.IP) string {
	cfg := r.cfg.Load().(*splitHorizonConfig)
	if !cfg.enabled || clientIP == nil {
		return ""
	}
	for _, view := range cfg.views {
		if len(view.Subnets) == 0 {
			// catch-all View
			return view.Name
		}
		for _, subnet := range view.Subnets {
			if subnet.Contains(clientIP) {
				return view.Name
			}
		}
	}
	return ""
}
