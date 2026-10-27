package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mw7101/domudns/internal/config"
	"github.com/mw7101/domudns/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

const testConfigAPIKey = "valid-api-key-with-at-least-32-characters-long"

// testMemAuthStore is an in-memory AuthStore for tests.
type testMemAuthStore struct {
	cfg store.AuthConfig
}

func (m *testMemAuthStore) GetAuthConfig(ctx context.Context) (*store.AuthConfig, error) {
	c := m.cfg
	return &c, nil
}

func (m *testMemAuthStore) UpdateAuthConfig(ctx context.Context, cfg *store.AuthConfig) error {
	m.cfg = *cfg
	return nil
}

func (m *testMemAuthStore) MarkSetupCompleted(ctx context.Context) error {
	m.cfg.SetupCompleted = true
	return nil
}

// newTestAuthManagerWithKey creates an AuthManager with a pre-set API key (for tests).
func newTestAuthManagerWithKey(t *testing.T, apiKey string) *AuthManager {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("admin"), 4) // cost 4 for fast tests
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	s := &testMemAuthStore{cfg: store.AuthConfig{
		Username:       "admin",
		PasswordHash:   string(hash),
		APIKey:         apiKey,
		SetupCompleted: true,
		UpdatedAt:      time.Now(),
	}}
	am, err := NewAuthManager(context.Background(), s)
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	return am
}

func TestConfigHandler_GET(t *testing.T) {
	cfg := &config.Config{
		Blocklist: config.BlocklistConfig{Enabled: true},
	}
	h := NewConfigHandler(cfg, nil)
	authMgr := newTestAuthManagerWithKey(t, testConfigAPIKey)

	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	req.Header.Set("Authorization", "Bearer "+testConfigAPIKey)
	w := httptest.NewRecorder()

	handler := AuthMiddleware(authMgr, NewSessionManager(), h)
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Blocklist struct {
				Enabled bool `json:"enabled"`
			} `json:"blocklist"`
			System struct {
				Auth struct {
					APIKey string `json:"api_key"`
				} `json:"auth"`
			} `json:"system"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)
	assert.True(t, resp.Data.Blocklist.Enabled)
	assert.Equal(t, "***", resp.Data.System.Auth.APIKey)
}

type mockConfigStore struct {
	overrides map[string]interface{}
	updateErr error
}

func (m *mockConfigStore) GetOverrides(ctx context.Context) (map[string]interface{}, error) {
	return m.overrides, nil
}

func (m *mockConfigStore) UpdateOverrides(ctx context.Context, overrides map[string]interface{}) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.overrides = overrides
	return nil
}

func TestConfigHandler_PATCH(t *testing.T) {
	cfg := &config.Config{Blocklist: config.BlocklistConfig{Enabled: true}}
	s := &mockConfigStore{overrides: map[string]interface{}{}}
	h := NewConfigHandler(cfg, s)
	authMgr := newTestAuthManagerWithKey(t, testConfigAPIKey)

	body := bytes.NewBufferString(`{"blocklist":{"enabled":false}}`)
	req := httptest.NewRequest(http.MethodPatch, "/api/config", body)
	req.Header.Set("Authorization", "Bearer "+testConfigAPIKey)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler := AuthMiddleware(authMgr, NewSessionManager(), h)
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.False(t, cfg.Blocklist.Enabled)
	assert.NotNil(t, s.overrides["blocklist"])
}

func TestConfigHandler_PATCH_no_store(t *testing.T) {
	cfg := &config.Config{}
	h := NewConfigHandler(cfg, nil)
	authMgr := newTestAuthManagerWithKey(t, testConfigAPIKey)

	body := bytes.NewBufferString(`{"blocklist":{"enabled":false}}`)
	req := httptest.NewRequest(http.MethodPatch, "/api/config", body)
	req.Header.Set("Authorization", "Bearer "+testConfigAPIKey)
	w := httptest.NewRecorder()

	handler := AuthMiddleware(authMgr, NewSessionManager(), h)
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}
