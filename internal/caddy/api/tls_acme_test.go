package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mw7101/domudns/internal/store"
)

// tlsACMEMockStore für die Handler-Tests
type tlsACMEMockStore struct {
	config *store.TLSACMEConfig
	cert   *store.TLSCertPayload
}

func (m *tlsACMEMockStore) GetTLSACMEConfig(_ context.Context) (*store.TLSACMEConfig, error) {
	return m.config, nil
}
func (m *tlsACMEMockStore) SetTLSACMEConfig(_ context.Context, cfg *store.TLSACMEConfig) error {
	m.config = cfg
	return nil
}
func (m *tlsACMEMockStore) GetTLSCert(_ context.Context) (*store.TLSCertPayload, error) {
	return m.cert, nil
}
func (m *tlsACMEMockStore) SetTLSCert(_ context.Context, p *store.TLSCertPayload) error {
	m.cert = p
	return nil
}

type mockCertStatusProvider struct {
	validUntil time.Time
}

func (m *mockCertStatusProvider) Status() store.TLSCertStatus {
	return store.TLSCertStatus{ValidUntil: m.validUntil, Domain: "dns.example.com"}
}
func (m *mockCertStatusProvider) TriggerRenewal(_ context.Context) {}

func TestTLSACMEHandler_Get(t *testing.T) {
	ms := &tlsACMEMockStore{config: &store.TLSACMEConfig{Enabled: true, Domain: "dns.example.com", Email: "a@b.com"}}
	h := NewTLSACMEHandler(ms, &mockCertStatusProvider{})

	req := httptest.NewRequest(http.MethodGet, "/api/tls/acme", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	// API always wraps in {"success": true, "data": ...}
	var wrapper struct {
		Data store.TLSACMEConfig `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &wrapper); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if wrapper.Data.Domain != "dns.example.com" {
		t.Fatalf("got domain %q", wrapper.Data.Domain)
	}
}

func TestTLSACMEHandler_Put_InvalidDomain(t *testing.T) {
	ms := &tlsACMEMockStore{}
	h := NewTLSACMEHandler(ms, &mockCertStatusProvider{})

	body, _ := json.Marshal(map[string]interface{}{
		"enabled": true, "domain": "", "email": "a@b.com",
	})
	req := httptest.NewRequest(http.MethodPut, "/api/tls/acme", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestTLSACMEHandler_Put_InvalidEmail(t *testing.T) {
	ms := &tlsACMEMockStore{}
	h := NewTLSACMEHandler(ms, &mockCertStatusProvider{})

	body, _ := json.Marshal(map[string]interface{}{
		"enabled": true, "domain": "dns.example.com", "email": "not-an-email",
	})
	req := httptest.NewRequest(http.MethodPut, "/api/tls/acme", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestTLSACMEHandler_RenewSlaveReturns403(t *testing.T) {
	ms := &tlsACMEMockStore{}
	h := NewTLSACMEHandler(ms, &mockCertStatusProvider{})
	h.SetSlaveMode(true)

	req := httptest.NewRequest(http.MethodPost, "/api/tls/acme/renew", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestTLSACMEHandler_PutSlaveReturns403(t *testing.T) {
	ms := &tlsACMEMockStore{}
	h := NewTLSACMEHandler(ms, &mockCertStatusProvider{})
	h.SetSlaveMode(true)

	body, _ := json.Marshal(store.TLSACMEConfig{Enabled: true, Domain: "d.com", Email: "a@b.com"})
	req := httptest.NewRequest(http.MethodPut, "/api/tls/acme", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}
