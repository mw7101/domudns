package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockACMEStore implements ACMEStore for unit tests.
type mockACMEStore struct {
	challenges map[string]string
}

func newMockACMEStore() *mockACMEStore {
	return &mockACMEStore{challenges: make(map[string]string)}
}

func (m *mockACMEStore) PutACMEChallenge(ctx context.Context, fqdn, value string, ttl time.Duration) error {
	m.challenges[fqdn] = value
	return nil
}

func (m *mockACMEStore) DeleteACMEChallenge(ctx context.Context, fqdn string) error {
	delete(m.challenges, fqdn)
	return nil
}

func TestACMEHandler_Present(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		body           string
		wantStatus     int
		wantBodySubstr string
		wantCode       string
		checkMock      func(*testing.T, *mockACMEStore)
	}{
		{
			name:           "success",
			method:         http.MethodPost,
			body:           `{"domain":"example.com","txt_value":"challenge-value"}`,
			wantStatus:     http.StatusOK,
			wantBodySubstr: `"status":"ok"`,
			checkMock: func(t *testing.T, m *mockACMEStore) {
				v, ok := m.challenges["_acme-challenge.example.com"]
				assert.True(t, ok, "mock should contain _acme-challenge.example.com")
				assert.Equal(t, "challenge-value", v)
			},
		},
		{
			name:           "domain with trailing dot",
			method:         http.MethodPost,
			body:           `{"domain":"example.com.","txt_value":"x"}`,
			wantStatus:     http.StatusOK,
			wantBodySubstr: `"status":"ok"`,
			checkMock: func(t *testing.T, m *mockACMEStore) {
				v, ok := m.challenges["_acme-challenge.example.com"]
				assert.True(t, ok)
				assert.Equal(t, "x", v)
			},
		},
		{
			name:           "missing domain",
			method:         http.MethodPost,
			body:           `{"txt_value":"x"}`,
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "INVALID_REQUEST",
			wantCode:       "INVALID_REQUEST",
		},
		{
			name:           "missing txt_value",
			method:         http.MethodPost,
			body:           `{"domain":"example.com"}`,
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "INVALID_REQUEST",
			wantCode:       "INVALID_REQUEST",
		},
		{
			name:           "txt_value exceeds 512 bytes",
			method:         http.MethodPost,
			body:           `{"domain":"example.com","txt_value":"` + strings.Repeat("x", 513) + `"}`,
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "INVALID_REQUEST",
			wantCode:       "INVALID_REQUEST",
		},
		{
			name:           "invalid domain",
			method:         http.MethodPost,
			body:           `{"domain":"_acme-challenge.example.com","txt_value":"x"}`,
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "INVALID_REQUEST",
			wantCode:       "INVALID_REQUEST",
		},
		{
			name:           "invalid JSON",
			method:         http.MethodPost,
			body:           `{invalid}`,
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "INVALID_JSON",
			wantCode:       "INVALID_JSON",
		},
		{
			name:           "wrong method GET",
			method:         http.MethodGet,
			body:           `{"domain":"example.com","txt_value":"x"}`,
			wantStatus:     http.StatusMethodNotAllowed,
			wantBodySubstr: "METHOD_NOT_ALLOWED",
			wantCode:       "METHOD_NOT_ALLOWED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockACMEStore()
			h := NewACMEHandler(store, 60)

			req := httptest.NewRequest(tt.method, "/api/acme/dns-01/present", bytes.NewReader([]byte(tt.body)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			h.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code, "status code")
			assert.Contains(t, w.Body.String(), tt.wantBodySubstr, "response body")
			if tt.wantCode != "" {
				assert.Contains(t, w.Body.String(), tt.wantCode)
			}
			if tt.checkMock != nil {
				tt.checkMock(t, store)
			}
		})
	}
}

func TestACMEHandler_Cleanup(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		body           string
		prepareMock    func(*mockACMEStore)
		wantStatus     int
		wantBodySubstr string
		wantCode       string
		checkMock      func(*testing.T, *mockACMEStore)
	}{
		{
			name:        "success",
			method:      http.MethodPost,
			body:        `{"domain":"example.com"}`,
			prepareMock: func(m *mockACMEStore) { m.challenges["_acme-challenge.example.com"] = "old" },
			wantStatus:  http.StatusOK,
			checkMock: func(t *testing.T, m *mockACMEStore) {
				_, ok := m.challenges["_acme-challenge.example.com"]
				assert.False(t, ok, "mock should not contain _acme-challenge.example.com after cleanup")
			},
		},
		{
			name:           "missing domain",
			method:         http.MethodPost,
			body:           `{}`,
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "INVALID_REQUEST",
			wantCode:       "INVALID_REQUEST",
		},
		{
			name:           "invalid domain",
			method:         http.MethodPost,
			body:           `{"domain":"_acme-challenge.example.com"}`,
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "INVALID_REQUEST",
			wantCode:       "INVALID_REQUEST",
		},
		{
			name:           "wrong method GET",
			method:         http.MethodGet,
			body:           `{"domain":"example.com"}`,
			wantStatus:     http.StatusMethodNotAllowed,
			wantBodySubstr: "METHOD_NOT_ALLOWED",
			wantCode:       "METHOD_NOT_ALLOWED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockACMEStore()
			if tt.prepareMock != nil {
				tt.prepareMock(store)
			}
			h := NewACMEHandler(store, 60)

			req := httptest.NewRequest(tt.method, "/api/acme/dns-01/cleanup", bytes.NewReader([]byte(tt.body)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			h.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
			if tt.wantBodySubstr != "" {
				assert.Contains(t, w.Body.String(), tt.wantBodySubstr)
			}
			if tt.wantCode != "" {
				assert.Contains(t, w.Body.String(), tt.wantCode)
			}
			if tt.checkMock != nil {
				tt.checkMock(t, store)
			}
		})
	}
}

func TestACMEHandler_Routing(t *testing.T) {
	store := newMockACMEStore()
	h := NewACMEHandler(store, 60)

	req := httptest.NewRequest(http.MethodGet, "/api/acme/dns-01/unknown", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "NOT_FOUND")
}
