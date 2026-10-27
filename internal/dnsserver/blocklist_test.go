package dnsserver

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/mw7101/domudns/internal/store"
)

// mockBlocklistStore implements BlocklistProvider for tests.
type mockBlocklistStore struct {
	domains   []string // returned as manual domains
	cidrs     []string
	domainErr error
	cidrErr   error
}

func (m *mockBlocklistStore) GetBlocklistURLSets(_ context.Context) ([]store.URLDomainSet, error) {
	return nil, nil
}
func (m *mockBlocklistStore) GetManualBlockedDomains(_ context.Context) ([]string, error) {
	return m.domains, m.domainErr
}
func (m *mockBlocklistStore) GetAllowedBlockedDomains(_ context.Context) ([]string, error) {
	return nil, nil
}
func (m *mockBlocklistStore) GetWhitelistIPs(_ context.Context) ([]string, error) {
	return m.cidrs, m.cidrErr
}
func (m *mockBlocklistStore) GetBlocklistPatterns(_ context.Context) (wildcards []string, regexps []string, err error) {
	return nil, nil, nil
}

func TestBlocklistManager_IsBlocked(t *testing.T) {
	bl := NewBlocklistManager()
	bl.mu.Lock()
	bl.uncatDomains["ads.evil.com"] = struct{}{}
	bl.uncatDomains["tracker.net"] = struct{}{}
	bl.mu.Unlock()

	tests := []struct {
		domain  string
		blocked bool
	}{
		{"ads.evil.com", true},
		{"ads.evil.com.", true}, // trailing dot
		{"ADS.EVIL.COM", true},  // case insensitive
		{"tracker.net", true},
		{"safe.example.com", false},
		{"", false},
	}

	for _, tc := range tests {
		t.Run(tc.domain, func(t *testing.T) {
			got := bl.IsBlocked(tc.domain, []string{})
			if got != tc.blocked {
				t.Errorf("IsBlocked(%q) = %v, want %v", tc.domain, got, tc.blocked)
			}
		})
	}
}

func TestBlocklistManager_IsWhitelisted(t *testing.T) {
	bl := NewBlocklistManager()
	bl.mu.Lock()
	_, net1, _ := net.ParseCIDR("192.168.1.0/24")
	_, net2, _ := net.ParseCIDR("10.0.0.1/32")
	bl.whitelist = []*net.IPNet{net1, net2}
	bl.mu.Unlock()

	tests := []struct {
		ip          string
		whitelisted bool
	}{
		{"192.168.1.100", true},
		{"192.168.1.1", true},
		{"192.168.2.1", false}, // different /24
		{"10.0.0.1", true},
		{"10.0.0.2", false},
		{"8.8.8.8", false},
	}

	for _, tc := range tests {
		t.Run(tc.ip, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			got := bl.IsWhitelisted(ip)
			if got != tc.whitelisted {
				t.Errorf("IsWhitelisted(%s) = %v, want %v", tc.ip, got, tc.whitelisted)
			}
		})
	}
}

func TestBlocklistManager_IsWhitelisted_NilIP(t *testing.T) {
	bl := NewBlocklistManager()
	bl.mu.Lock()
	_, ipNet, _ := net.ParseCIDR("192.168.0.0/16")
	bl.whitelist = []*net.IPNet{ipNet}
	bl.mu.Unlock()

	// nil IP must not cause a panic → must return false
	got := bl.IsWhitelisted(nil)
	if got {
		t.Error("nil IP sollte nicht als whitelisted gelten")
	}
}

func TestBlocklistManager_Load(t *testing.T) {
	store := &mockBlocklistStore{
		domains: []string{"ads.com", "tracker.net", "MALWARE.ORG"},
		cidrs:   []string{"10.0.0.0/8", "192.168.0.0/16"},
	}

	bl := NewBlocklistManager()
	err := bl.Load(context.Background(), store)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if !bl.IsBlocked("ads.com", []string{}) {
		t.Error("ads.com sollte geblockt sein")
	}
	if !bl.IsBlocked("malware.org", []string{}) {
		t.Error("MALWARE.ORG should be blocked after normalization")
	}
	if !bl.IsWhitelisted(net.ParseIP("10.1.2.3")) {
		t.Error("10.1.2.3 sollte whitelisted sein")
	}
	if !bl.IsWhitelisted(net.ParseIP("192.168.42.1")) {
		t.Error("192.168.42.1 sollte whitelisted sein")
	}
	if bl.IsWhitelisted(net.ParseIP("8.8.8.8")) {
		t.Error("8.8.8.8 sollte nicht whitelisted sein")
	}
}

func TestBlocklistManager_Load_InvalidCIDR(t *testing.T) {
	store := &mockBlocklistStore{
		domains: []string{"bad.com"},
		cidrs:   []string{"not-a-cidr", "192.168.1.0/24"},
	}

	bl := NewBlocklistManager()
	// Invalid CIDR should be logged and skipped, not cause an error
	err := bl.Load(context.Background(), store)
	if err != nil {
		t.Fatalf("Load() should not fail for invalid CIDR, got: %v", err)
	}

	// Valid CIDR should still be loaded
	if !bl.IsWhitelisted(net.ParseIP("192.168.1.50")) {
		t.Error("valid CIDR after invalid one should still be loaded")
	}
}

func TestBlocklistManager_Stats(t *testing.T) {
	bl := NewBlocklistManager()
	bl.mu.Lock()
	bl.uncatDomains["a.com"] = struct{}{}
	bl.uncatDomains["b.com"] = struct{}{}
	_, n1, _ := net.ParseCIDR("10.0.0.0/8")
	bl.whitelist = []*net.IPNet{n1}
	bl.mu.Unlock()

	domains, wildcards, regexps, ips := bl.Stats()
	if domains != 2 {
		t.Errorf("expected 2 blocked domains, got %d", domains)
	}
	if wildcards != 0 {
		t.Errorf("expected 0 wildcards, got %d", wildcards)
	}
	if regexps != 0 {
		t.Errorf("expected 0 regexps, got %d", regexps)
	}
	if ips != 1 {
		t.Errorf("expected 1 whitelist IP, got %d", ips)
	}
}

func TestBlocklistManager_WildcardBlocking(t *testing.T) {
	bl := NewBlocklistManager()
	bl.mu.Lock()
	bl.wildcards = []string{"doubleclick.net", "ads.example.com"}
	bl.mu.Unlock()

	tests := []struct {
		domain  string
		blocked bool
	}{
		{"foo.doubleclick.net", true},
		{"doubleclick.net", true},         // exact match on suffix
		{"sub.foo.doubleclick.net", true}, // deeper subdomain
		{"notdoubleclick.net", false},     // no suffix match
		{"foo.ads.example.com", true},
		{"ads.example.com", true},
		{"example.com", false},
	}

	for _, tc := range tests {
		t.Run(tc.domain, func(t *testing.T) {
			got := bl.IsBlocked(tc.domain, []string{})
			if got != tc.blocked {
				t.Errorf("IsBlocked(%q) = %v, want %v", tc.domain, got, tc.blocked)
			}
		})
	}
}

func TestBlocklistManager_RegexBlocking(t *testing.T) {
	bl := NewBlocklistManager()
	re := compileRegexps([]string{`/^ads[0-9]+\.example\.com$/`})
	bl.mu.Lock()
	bl.regexps = re
	bl.mu.Unlock()

	tests := []struct {
		domain  string
		blocked bool
	}{
		{"ads1.example.com", true},
		{"ads123.example.com", true},
		{"ads.example.com", false},   // no numeric suffix
		{"xads1.example.com", false}, // no 'ads' prefix
	}

	for _, tc := range tests {
		t.Run(tc.domain, func(t *testing.T) {
			got := bl.IsBlocked(tc.domain, []string{})
			if got != tc.blocked {
				t.Errorf("IsBlocked(%q) = %v, want %v", tc.domain, got, tc.blocked)
			}
		})
	}
}

func TestParseWildcards(t *testing.T) {
	patterns := []string{"*.doubleclick.net", "*.ads.com", "invalid-no-star"}
	result := parseWildcards(patterns)
	if len(result) != 2 {
		t.Fatalf("expected 2 wildcards, got %d", len(result))
	}
	if result[0] != "doubleclick.net" {
		t.Errorf("expected doubleclick.net, got %q", result[0])
	}
	if result[1] != "ads.com" {
		t.Errorf("expected ads.com, got %q", result[1])
	}
}

func TestCompileRegexps(t *testing.T) {
	// Valid patterns — with and without / delimiter
	result := compileRegexps([]string{`/^ads\.com$/`, `tracker\.net`})
	if len(result) != 2 {
		t.Fatalf("expected 2 regexps, got %d", len(result))
	}

	// Invalid pattern is skipped
	result2 := compileRegexps([]string{`[invalid`})
	if len(result2) != 0 {
		t.Errorf("expected 0 compiled regexps for invalid pattern, got %d", len(result2))
	}
}

func TestBlocklistManager_Load_WithPatterns(t *testing.T) {
	store := &mockBlocklistStoreWithPatterns{
		domains:   []string{"exact.com"},
		wildcards: []string{"*.wildcard.net"},
		regexps:   []string{`/^re[0-9]\.test\.com$/`},
	}

	bl := NewBlocklistManager()
	if err := bl.Load(context.Background(), store); err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if !bl.IsBlocked("exact.com", []string{}) {
		t.Error("exact.com sollte geblockt sein")
	}
	if !bl.IsBlocked("sub.wildcard.net", []string{}) {
		t.Error("sub.wildcard.net should be blocked via wildcard")
	}
	if !bl.IsBlocked("re5.test.com", []string{}) {
		t.Error("re5.test.com should be blocked via regex")
	}
	if bl.IsBlocked("re.test.com", []string{}) {
		t.Error("re.test.com should not be blocked (no numeric suffix)")
	}
}

type mockBlocklistStoreWithPatterns struct {
	domains   []string
	wildcards []string
	regexps   []string
}

func (m *mockBlocklistStoreWithPatterns) GetBlocklistURLSets(_ context.Context) ([]store.URLDomainSet, error) {
	return nil, nil
}
func (m *mockBlocklistStoreWithPatterns) GetManualBlockedDomains(_ context.Context) ([]string, error) {
	return m.domains, nil
}
func (m *mockBlocklistStoreWithPatterns) GetAllowedBlockedDomains(_ context.Context) ([]string, error) {
	return nil, nil
}
func (m *mockBlocklistStoreWithPatterns) GetWhitelistIPs(_ context.Context) ([]string, error) {
	return nil, nil
}
func (m *mockBlocklistStoreWithPatterns) GetBlocklistPatterns(_ context.Context) (wildcards []string, regexps []string, err error) {
	return m.wildcards, m.regexps, nil
}

func TestBlocklistManager_ConcurrentAccess(t *testing.T) {
	bl := NewBlocklistManager()
	bl.mu.Lock()
	bl.uncatDomains["concurrent.com"] = struct{}{}
	bl.mu.Unlock()

	var wg sync.WaitGroup

	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = bl.IsBlocked("concurrent.com", []string{})
		}()
	}

	// Concurrent whitelist checks
	ip := net.ParseIP("192.168.1.1")
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = bl.IsWhitelisted(ip)
		}()
	}

	wg.Wait()
}

func TestIsBlockedWithCategories(t *testing.T) {
	b := NewBlocklistManager()
	ctx := context.Background()

	mockStore := &mockBlocklistStoreCategories{
		urlSets: []store.URLDomainSet{
			{URLID: 1, Category: "ads", Domains: []string{"ads.example.com"}},
			{URLID: 2, Category: "malware", Domains: []string{"malware.example.com"}},
		},
		manual: []string{"always.example.com"},
	}
	if err := b.Load(ctx, mockStore); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Uncategorized domain always blocked
	if !b.IsBlocked("always.example.com", []string{}) {
		t.Error("uncategorized domain should always be blocked")
	}

	// Categorized domain blocked only when category is enabled
	if !b.IsBlocked("ads.example.com", []string{"ads"}) {
		t.Error("ads domain should be blocked when ads is enabled")
	}
	if b.IsBlocked("ads.example.com", []string{"malware"}) {
		t.Error("ads domain should NOT be blocked when only malware is enabled")
	}
	if b.IsBlocked("ads.example.com", []string{}) {
		t.Error("ads domain should NOT be blocked with empty categories")
	}

	// Malware blocked with malware category
	if !b.IsBlocked("malware.example.com", []string{"malware"}) {
		t.Error("malware domain should be blocked with malware enabled")
	}
}

func TestStatsWithCategories(t *testing.T) {
	b := NewBlocklistManager()
	ctx := context.Background()
	mockStore := &mockBlocklistStoreCategories{
		urlSets: []store.URLDomainSet{
			{URLID: 1, Category: "ads", Domains: []string{"a.com"}},
			{URLID: 2, Category: "malware", Domains: []string{"c.com"}},
		},
		manual: []string{"b.com"},
	}
	if err := b.Load(ctx, mockStore); err != nil {
		t.Fatalf("Load: %v", err)
	}
	total, _, _, _ := b.Stats()
	if total != 3 {
		t.Errorf("expected Stats total=3, got %d", total)
	}
}

// mockBlocklistStoreCategories expresses categorized domains via URL sets.
type mockBlocklistStoreCategories struct {
	urlSets []store.URLDomainSet
	manual  []string
}

func (m *mockBlocklistStoreCategories) GetBlocklistURLSets(_ context.Context) ([]store.URLDomainSet, error) {
	return m.urlSets, nil
}
func (m *mockBlocklistStoreCategories) GetManualBlockedDomains(_ context.Context) ([]string, error) {
	return m.manual, nil
}
func (m *mockBlocklistStoreCategories) GetAllowedBlockedDomains(_ context.Context) ([]string, error) {
	return nil, nil
}
func (m *mockBlocklistStoreCategories) GetWhitelistIPs(_ context.Context) ([]string, error) {
	return nil, nil
}
func (m *mockBlocklistStoreCategories) GetBlocklistPatterns(_ context.Context) ([]string, []string, error) {
	return nil, nil, nil
}

func TestBlocklistManager_ApplyURLDomains_Basic(t *testing.T) {
	bl := NewBlocklistManager()

	bl.ApplyURLDomains(1, "", []string{"ads.com", "tracker.net"})

	if !bl.IsBlocked("ads.com", []string{}) {
		t.Error("ads.com should be blocked after ApplyURLDomains")
	}
	if !bl.IsBlocked("tracker.net", []string{}) {
		t.Error("tracker.net should be blocked after ApplyURLDomains")
	}
	if bl.IsBlocked("safe.example.com", []string{}) {
		t.Error("safe.example.com should not be blocked")
	}
}

func TestBlocklistManager_ApplyURLDomains_Categorized(t *testing.T) {
	bl := NewBlocklistManager()

	bl.ApplyURLDomains(1, "ads", []string{"ads.example.com"})
	bl.ApplyURLDomains(2, "malware", []string{"malware.example.com"})

	if !bl.IsBlocked("ads.example.com", []string{"ads"}) {
		t.Error("ads domain should be blocked with ads category")
	}
	if bl.IsBlocked("ads.example.com", []string{"malware"}) {
		t.Error("ads domain should NOT be blocked with only malware category")
	}
	if !bl.IsBlocked("malware.example.com", []string{"malware"}) {
		t.Error("malware domain should be blocked with malware category")
	}
}

func TestBlocklistManager_ApplyURLDomains_Update(t *testing.T) {
	bl := NewBlocklistManager()

	bl.ApplyURLDomains(1, "", []string{"old-ads.com"})
	if !bl.IsBlocked("old-ads.com", []string{}) {
		t.Fatal("old-ads.com should be blocked initially")
	}

	bl.ApplyURLDomains(1, "", []string{"new-ads.com"})
	if bl.IsBlocked("old-ads.com", []string{}) {
		t.Error("old-ads.com should no longer be blocked after URL update")
	}
	if !bl.IsBlocked("new-ads.com", []string{}) {
		t.Error("new-ads.com should be blocked after URL update")
	}
}

func TestBlocklistManager_ApplyURLDomains_PreservesOtherURLs(t *testing.T) {
	bl := NewBlocklistManager()

	bl.ApplyURLDomains(1, "", []string{"url1.com"})
	bl.ApplyURLDomains(2, "", []string{"url2.com"})

	bl.ApplyURLDomains(1, "", []string{"url1-updated.com"})

	if bl.IsBlocked("url1.com", []string{}) {
		t.Error("url1.com should no longer be blocked")
	}
	if !bl.IsBlocked("url1-updated.com", []string{}) {
		t.Error("url1-updated.com should be blocked")
	}
	if !bl.IsBlocked("url2.com", []string{}) {
		t.Error("url2.com from URL 2 should still be blocked")
	}
}

func TestBlocklistManager_ApplyURLDomains_RespectsAllowedDomains(t *testing.T) {
	bl := NewBlocklistManager()

	bl.mu.Lock()
	bl.allowedDomains["exempt.com"] = struct{}{}
	bl.mu.Unlock()

	bl.ApplyURLDomains(1, "", []string{"ads.com", "exempt.com"})

	if !bl.IsBlocked("ads.com", []string{}) {
		t.Error("ads.com should be blocked")
	}
	if bl.IsBlocked("exempt.com", []string{}) {
		t.Error("exempt.com is in allowed list and must not be blocked")
	}
}

func TestBlocklistManager_ApplyURLDomains_Normalization(t *testing.T) {
	bl := NewBlocklistManager()
	bl.ApplyURLDomains(1, "", []string{"ADS.COM", "Tracker.NET."})

	if !bl.IsBlocked("ads.com", []string{}) {
		t.Error("should be blocked after lowercase normalization")
	}
	if !bl.IsBlocked("tracker.net", []string{}) {
		t.Error("should be blocked after trailing dot removal")
	}
}

func TestBlocklistManager_ApplyURLDomains_ConcurrentSafe(t *testing.T) {
	bl := NewBlocklistManager()
	bl.ApplyURLDomains(1, "", []string{"base.com"})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		urlID := i + 2
		go func() {
			defer wg.Done()
			bl.ApplyURLDomains(urlID, "", []string{"concurrent.com"})
		}()
		go func() {
			defer wg.Done()
			_ = bl.IsBlocked("base.com", []string{})
		}()
	}
	wg.Wait()
}
