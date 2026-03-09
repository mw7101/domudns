package dnsserver

import (
	"context"
	"net"
	"sync"
	"testing"
)

// mockBlocklistStore implements BlocklistStore for tests.
type mockBlocklistStore struct {
	domains   []string
	cidrs     []string
	domainErr error
	cidrErr   error
}

func (m *mockBlocklistStore) GetBlockedDomains(_ context.Context) ([]string, error) {
	return m.domains, m.domainErr
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
	bl.domains["ads.evil.com"] = struct{}{}
	bl.domains["tracker.net"] = struct{}{}
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
			got := bl.IsBlocked(tc.domain)
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

	if !bl.IsBlocked("ads.com") {
		t.Error("ads.com sollte geblockt sein")
	}
	if !bl.IsBlocked("malware.org") {
		t.Error("MALWARE.ORG should be blocked after normalization")
	}
	if !bl.IsWhitelisted(net.ParseIP("10.1.2.3")) {
		t.Error("10.1.2.3 sollte whitelisted sein")
	}
	if !bl.IsWhitelisted(net.ParseIP("192.168.100.1")) {
		t.Error("192.168.100.1 sollte whitelisted sein")
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
	bl.domains["a.com"] = struct{}{}
	bl.domains["b.com"] = struct{}{}
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
			got := bl.IsBlocked(tc.domain)
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
			got := bl.IsBlocked(tc.domain)
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

	if !bl.IsBlocked("exact.com") {
		t.Error("exact.com sollte geblockt sein")
	}
	if !bl.IsBlocked("sub.wildcard.net") {
		t.Error("sub.wildcard.net should be blocked via wildcard")
	}
	if !bl.IsBlocked("re5.test.com") {
		t.Error("re5.test.com should be blocked via regex")
	}
	if bl.IsBlocked("re.test.com") {
		t.Error("re.test.com should not be blocked (no numeric suffix)")
	}
}

// mockBlocklistStoreWithPatterns also provides pattern data.
type mockBlocklistStoreWithPatterns struct {
	domains   []string
	wildcards []string
	regexps   []string
}

func (m *mockBlocklistStoreWithPatterns) GetBlockedDomains(_ context.Context) ([]string, error) {
	return m.domains, nil
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
	bl.domains["concurrent.com"] = struct{}{}
	bl.mu.Unlock()

	var wg sync.WaitGroup

	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = bl.IsBlocked("concurrent.com")
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
