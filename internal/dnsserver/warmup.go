package dnsserver

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mw7101/domudns/internal/querylog"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// QueryLogReader is the minimal interface WarmCache needs from the query logger.
type QueryLogReader interface {
	Stats() querylog.QueryLogStats
}

// WarmCache preloads popular domains asynchron into the LRU cache.
// Data source: Query-Log top domains (priority 1) + defaultWarmupDomains as fallback.
// Does not block server start — must be called as goroutine.
func (s *Server) WarmCache(ctx context.Context, qlog QueryLogReader, count int) {
	if s.cache == nil {
		return
	}
	if count <= 0 {
		count = 200
	}

	domains := collectDomains(qlog, defaultWarmupDomains, count)
	if len(domains) == 0 {
		return
	}

	upstream := s.upstream
	if len(upstream) == 0 {
		log.Debug().Msg("cache warmup: keine upstream-Server konfiguriert, übersprungen")
		return
	}

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	var warmed atomic.Int64

	warmupCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	for _, domain := range domains {
		wg.Add(1)
		sem <- struct{}{}
		go func(d string) {
			defer wg.Done()
			defer func() { <-sem }()
			fqdn := dns.Fqdn(d)
			for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
				if s.cache.Get(fqdn, qtype) != nil {
					continue // already cached
				}
				if warmAndStore(warmupCtx, s.cache, upstream, fqdn, qtype) {
					warmed.Add(1)
				}
			}
		}(domain)
	}

	wg.Wait()
	log.Info().
		Int64("warmed", warmed.Load()).
		Int("domains", len(domains)).
		Msg("cache warmup abgeschlossen")
}

// collectDomains merges Query-Log top domains (priority 1) with the fallback list,
// deduplicates entries and limits to max entries.
func collectDomains(qlog QueryLogReader, fallback []string, max int) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, max)

	if qlog != nil {
		for _, d := range qlog.Stats().TopDomains {
			if len(result) >= max {
				break
			}
			if _, ok := seen[d.Domain]; !ok {
				seen[d.Domain] = struct{}{}
				result = append(result, d.Domain)
			}
		}
	}

	for _, d := range fallback {
		if len(result) >= max {
			break
		}
		if _, ok := seen[d]; !ok {
			seen[d] = struct{}{}
			result = append(result, d)
		}
	}

	return result
}

// warmAndStore resolves a single domain/type at the first available upstream
// and stores the response in the cache. Returns true if successfully cached.
func warmAndStore(ctx context.Context, cache *CacheManager, upstream []string, fqdn string, qtype uint16) bool {
	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	req := new(dns.Msg)
	req.SetQuestion(fqdn, qtype)
	req.RecursionDesired = true

	for _, srv := range upstream {
		if _, _, err := net.SplitHostPort(srv); err != nil {
			srv += ":53"
		}
		resp, _, err := c.ExchangeContext(ctx, req, srv)
		if err != nil || resp == nil {
			continue
		}
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
			// NXDOMAIN or empty response — no further upstream attempt
			break
		}
		cache.Set(fqdn, qtype, resp)
		return true
	}
	return false
}
