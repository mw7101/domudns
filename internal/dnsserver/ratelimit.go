package dnsserver

import (
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/time/rate"
)

const (
	// dnsRateLimitCleanupInterval is how often idle client entries are evicted.
	dnsRateLimitCleanupInterval = 5 * time.Minute
	// dnsRateLimitIdleTTL is how long a client entry survives without queries.
	dnsRateLimitIdleTTL = 10 * time.Minute
	// maxDNSRateLimitEntries caps the number of tracked client IPs so a flood
	// of spoofed/rotating source addresses cannot exhaust memory (1 GB RAM
	// target hardware). When the cap is reached, new clients fail open
	// (allowed but untracked) rather than growing the map further.
	maxDNSRateLimitEntries = 50_000
)

// rateLimitEntry holds one client's token bucket and its last-access time.
type rateLimitEntry struct {
	limiter  *rate.Limiter
	lastUsed time.Time
}

// QueryRateLimiter limits DNS queries per client IP using a token bucket.
// It is safe for concurrent use. A nil *QueryRateLimiter is valid and allows
// every query, so callers do not need nil checks.
//
// Semantics: sustained queriesPerMinute per client IP, with an initial burst
// equal to queriesPerMinute (same model as the HTTP API RateLimitMiddleware).
type QueryRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rateLimitEntry
	qps      rate.Limit
	burst    int
	// exempt holds networks whose clients are never rate limited (e.g. the
	// upstream router that forwards the whole LAN's queries from one IP).
	exempt   []*net.IPNet
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewQueryRateLimiter creates a per-IP DNS query limiter.
// exemptNetworks is a list of CIDRs or bare IPs that bypass limiting
// entirely (empty = no exemptions). Returns nil when queriesPerMinute <= 0
// (rate limiting disabled).
func NewQueryRateLimiter(queriesPerMinute int, exemptNetworks []string) *QueryRateLimiter {
	if queriesPerMinute <= 0 {
		return nil
	}
	l := &QueryRateLimiter{
		limiters: make(map[string]*rateLimitEntry),
		qps:      rate.Every(time.Minute / time.Duration(queriesPerMinute)),
		burst:    queriesPerMinute,
		exempt:   parseNetworks(exemptNetworks, "rate_limit.exempt_networks"),
		stopCh:   make(chan struct{}),
	}
	if len(l.exempt) > 0 {
		log.Info().Int("networks", len(l.exempt)).Msg("DNS rate limit exemptions active")
	}
	go l.cleanupLoop()
	return l
}

// isExempt reports whether ip belongs to a configured exempt network.
func (l *QueryRateLimiter) isExempt(ip net.IP) bool {
	for _, n := range l.exempt {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// cleanupLoop periodically evicts clients that have been idle beyond
// dnsRateLimitIdleTTL. It stops when Stop is called.
func (l *QueryRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(dnsRateLimitCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-l.stopCh:
			return
		case <-ticker.C:
			l.mu.Lock()
			cutoff := time.Now().Add(-dnsRateLimitIdleTTL)
			for ip, ent := range l.limiters {
				if ent.lastUsed.Before(cutoff) {
					delete(l.limiters, ip)
				}
			}
			l.mu.Unlock()
		}
	}
}

// Allow reports whether a query from ip is permitted. A nil limiter allows all.
func (l *QueryRateLimiter) Allow(ip net.IP) bool {
	if l == nil {
		return true
	}
	if l.isExempt(ip) {
		return true
	}
	key := ip.String()

	l.mu.Lock()
	ent, ok := l.limiters[key]
	if !ok {
		if len(l.limiters) >= maxDNSRateLimitEntries {
			// Fail open instead of evicting live entries or growing unbounded.
			l.mu.Unlock()
			return true
		}
		ent = &rateLimitEntry{
			limiter:  rate.NewLimiter(l.qps, l.burst),
			lastUsed: time.Now(),
		}
		l.limiters[key] = ent
	}
	ent.lastUsed = time.Now()
	lim := ent.limiter
	l.mu.Unlock()

	return lim.Allow()
}

// Stop terminates the cleanup goroutine. Safe to call multiple times and on
// a nil receiver.
func (l *QueryRateLimiter) Stop() {
	if l == nil {
		return
	}
	l.stopOnce.Do(func() { close(l.stopCh) })
}
