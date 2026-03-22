package dnsserver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// stubBlocklistProvider implements BlocklistProvider for testing.
type stubBlocklistProvider struct {
	domains   []string
	wildcards []string
	regexps   []string
	whitelist []string
}

func (s *stubBlocklistProvider) GetBlockedDomains(_ context.Context) ([]string, error) {
	return s.domains, nil
}
func (s *stubBlocklistProvider) GetWhitelistIPs(_ context.Context) ([]string, error) {
	return s.whitelist, nil
}
func (s *stubBlocklistProvider) GetBlocklistPatterns(_ context.Context) ([]string, []string, error) {
	return s.wildcards, s.regexps, nil
}

func seedBlocklistManager(t *testing.T, domains []string) *BlocklistManager {
	t.Helper()
	bm := NewBlocklistManager()
	stub := &stubBlocklistProvider{domains: domains}
	if err := bm.Load(context.Background(), stub); err != nil {
		t.Fatalf("BlocklistManager.Load: %v", err)
	}
	return bm
}

func makeQueryCtx(h *Handler, qname string, qtype uint16, clientIP string) *queryContext {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(qname), qtype)
	return &queryContext{
		req:      req,
		clientIP: net.ParseIP(clientIP),
		question: req.Question[0],
		handler:  h,
	}
}

func TestBlocklistPhase_BlockedDomain(t *testing.T) {
	h := &Handler{
		blocklist: seedBlocklistManager(t, []string{"ads.example.com"}),
	}
	ctx := makeQueryCtx(h, "ads.example.com", dns.TypeA, "10.0.0.1")
	result := h.blocklistPhase(ctx)
	if !result.done {
		t.Fatal("expected pipeline to stop on blocked domain")
	}
}

func TestBlocklistPhase_AllowedDomain(t *testing.T) {
	h := &Handler{
		blocklist: seedBlocklistManager(t, []string{"ads.example.com"}),
	}
	ctx := makeQueryCtx(h, "safe.example.com", dns.TypeA, "10.0.0.1")
	result := h.blocklistPhase(ctx)
	if result.done {
		t.Fatal("expected pipeline to continue for non-blocked domain")
	}
}

func TestCachePhase_CacheMiss(t *testing.T) {
	cm := NewCacheManager(100, 30*time.Second, 10*time.Second)
	h := &Handler{cache: cm}
	ctx := makeQueryCtx(h, "miss.example.com", dns.TypeA, "10.0.0.1")
	result := h.cachePhase(ctx)
	if result.done {
		t.Fatal("expected cache miss to continue pipeline")
	}
}
