package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mw7101/domudns/internal/config"
	"github.com/mw7101/domudns/internal/store"
	"github.com/stretchr/testify/assert"
)

type mockBlocklistStore struct{}

func (m *mockBlocklistStore) ListBlocklistURLs(ctx context.Context) ([]store.BlocklistURL, error) {
	return nil, nil
}
func (m *mockBlocklistStore) AddBlocklistURL(ctx context.Context, url string, enabled bool) (*store.BlocklistURL, error) {
	return &store.BlocklistURL{ID: 1, URL: url, Enabled: enabled, CreatedAt: time.Now()}, nil
}
func (m *mockBlocklistStore) RemoveBlocklistURL(ctx context.Context, id int) error { return nil }
func (m *mockBlocklistStore) SetBlocklistURLEnabled(ctx context.Context, id int, enabled bool) error {
	return nil
}
func (m *mockBlocklistStore) UpdateBlocklistURLFetch(ctx context.Context, id int, lastError *string) error {
	return nil
}
func (m *mockBlocklistStore) SetBlocklistURLDomains(ctx context.Context, urlID int, domains []string) error {
	return nil
}
func (m *mockBlocklistStore) ListBlockedDomains(ctx context.Context) ([]string, error) {
	return nil, nil
}
func (m *mockBlocklistStore) AddBlockedDomain(ctx context.Context, domain string) error { return nil }
func (m *mockBlocklistStore) RemoveBlockedDomain(ctx context.Context, domain string) error {
	return nil
}
func (m *mockBlocklistStore) ListAllowedDomains(ctx context.Context) ([]string, error) {
	return nil, nil
}
func (m *mockBlocklistStore) AddAllowedDomain(ctx context.Context, domain string) error { return nil }
func (m *mockBlocklistStore) RemoveAllowedDomain(ctx context.Context, domain string) error {
	return nil
}
func (m *mockBlocklistStore) ListWhitelistIPs(ctx context.Context) ([]string, error) {
	return nil, nil
}
func (m *mockBlocklistStore) AddWhitelistIP(ctx context.Context, ipCIDR string) error { return nil }
func (m *mockBlocklistStore) RemoveWhitelistIP(ctx context.Context, ipCIDR string) error {
	return nil
}
func (m *mockBlocklistStore) GetMergedBlocklist(ctx context.Context) ([]string, error) {
	return nil, nil
}
func (m *mockBlocklistStore) ListBlocklistPatterns(ctx context.Context) ([]store.BlocklistPattern, error) {
	return nil, nil
}
func (m *mockBlocklistStore) AddBlocklistPattern(ctx context.Context, pattern string, patternType string) (*store.BlocklistPattern, error) {
	return &store.BlocklistPattern{ID: 1, Pattern: pattern, Type: patternType}, nil
}
func (m *mockBlocklistStore) RemoveBlocklistPattern(ctx context.Context, id int) error { return nil }

func TestBlocklistHandler_Disabled(t *testing.T) {
	cfg := &config.Config{
		Blocklist: config.BlocklistConfig{Enabled: false},
	}
	blStore := &mockBlocklistStore{}
	handler := NewBlocklistHandler(blStore, cfg, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/blocklist/urls", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "disabled")
}
