package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mw7101/domudns/internal/caddy/api"
	"github.com/mw7101/domudns/internal/store"
)

// --- Mock Store ---

type mockTSIGStore struct {
	keys []store.TSIGKey
}

func (m *mockTSIGStore) GetTSIGKeys(_ context.Context) ([]store.TSIGKey, error) {
	cp := make([]store.TSIGKey, len(m.keys))
	copy(cp, m.keys)
	return cp, nil
}

func (m *mockTSIGStore) PutTSIGKey(_ context.Context, key store.TSIGKey) error {
	for i, k := range m.keys {
		if k.Name == key.Name {
			m.keys[i] = key
			return nil
		}
	}
	m.keys = append(m.keys, key)
	return nil
}

func (m *mockTSIGStore) DeleteTSIGKey(_ context.Context, name string) error {
	filtered := m.keys[:0]
	for _, k := range m.keys {
		if k.Name != name {
			filtered = append(filtered, k)
		}
	}
	m.keys = filtered
	return nil
}

// --- Mock KeyUpdater ---

type mockKeyUpdater struct {
	called bool
	keys   []store.TSIGKey
}

func (m *mockKeyUpdater) UpdateTSIGKeys(keys []store.TSIGKey) {
	m.called = true
	m.keys = keys
}

// --- Helper functions ---

func newDDNSHandler(t *testing.T) (*api.DDNSAPIHandler, *mockTSIGStore, *mockKeyUpdater) {
	t.Helper()
	s := &mockTSIGStore{}
	u := &mockKeyUpdater{}
	h := api.NewDDNSAPIHandler(s, u)
	return h, s, u
}

func do(t *testing.T, h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// --- Tests ---

func TestDDNSAPI_ListKeys_Empty(t *testing.T) {
	h, _, _ := newDDNSHandler(t)
	rr := do(t, h, http.MethodGet, "/api/ddns/keys", nil)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Data) != 0 {
		t.Fatalf("want empty list, got %d items", len(resp.Data))
	}
}

func TestDDNSAPI_CreateKey_ReturnsSecret(t *testing.T) {
	h, s, u := newDDNSHandler(t)
	rr := do(t, h, http.MethodPost, "/api/ddns/keys", map[string]string{
		"name":      "test-key",
		"algorithm": "hmac-sha256",
	})

	if rr.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Data struct {
			Name      string    `json:"name"`
			Algorithm string    `json:"algorithm"`
			Secret    string    `json:"secret"`
			CreatedAt time.Time `json:"created_at"`
		} `json:"data"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	if resp.Data.Name != "test-key" {
		t.Errorf("want name=test-key, got %q", resp.Data.Name)
	}
	if resp.Data.Algorithm != "hmac-sha256" {
		t.Errorf("want algorithm=hmac-sha256, got %q", resp.Data.Algorithm)
	}
	if resp.Data.Secret == "" {
		t.Error("secret must be non-empty on creation")
	}
	if resp.Data.CreatedAt.IsZero() {
		t.Error("created_at must be non-zero")
	}

	// Key must be persisted in the store
	if len(s.keys) != 1 || s.keys[0].Name != "test-key" {
		t.Errorf("key not persisted in store: %+v", s.keys)
	}

	// KeyUpdater must have been called
	if !u.called {
		t.Error("keyUpdater.UpdateTSIGKeys not called after create")
	}
}

func TestDDNSAPI_ListKeys_NoSecretInResponse(t *testing.T) {
	h, _, _ := newDDNSHandler(t)

	// Create key
	do(t, h, http.MethodPost, "/api/ddns/keys", map[string]string{
		"name":      "my-key",
		"algorithm": "hmac-sha256",
	})

	// List — secret must NOT be returned
	rr := do(t, h, http.MethodGet, "/api/ddns/keys", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}

	var resp struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Data) != 1 {
		t.Fatalf("want 1 key, got %d", len(resp.Data))
	}
	if _, hasSecret := resp.Data[0]["secret"]; hasSecret {
		t.Error("secret must NOT be returned in GET /api/ddns/keys")
	}
}

func TestDDNSAPI_DeleteKey(t *testing.T) {
	h, s, u := newDDNSHandler(t)

	// Create key
	do(t, h, http.MethodPost, "/api/ddns/keys", map[string]string{
		"name": "del-key",
	})
	if len(s.keys) != 1 {
		t.Fatal("setup: key not created")
	}

	u.called = false // Reset

	rr := do(t, h, http.MethodDelete, "/api/ddns/keys/del-key", nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	if len(s.keys) != 0 {
		t.Errorf("want 0 keys after delete, got %d", len(s.keys))
	}
	if !u.called {
		t.Error("keyUpdater.UpdateTSIGKeys not called after delete")
	}
}

func TestDDNSAPI_CreateKey_InvalidAlgorithm(t *testing.T) {
	h, _, _ := newDDNSHandler(t)
	rr := do(t, h, http.MethodPost, "/api/ddns/keys", map[string]string{
		"name":      "bad-key",
		"algorithm": "md5",
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestDDNSAPI_CreateKey_MissingName(t *testing.T) {
	h, _, _ := newDDNSHandler(t)
	rr := do(t, h, http.MethodPost, "/api/ddns/keys", map[string]string{
		"algorithm": "hmac-sha256",
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestDDNSAPI_CreateKey_DefaultAlgorithm(t *testing.T) {
	h, s, _ := newDDNSHandler(t)
	do(t, h, http.MethodPost, "/api/ddns/keys", map[string]string{
		"name": "default-alg-key",
	})
	if len(s.keys) != 1 {
		t.Fatal("key not created")
	}
	if s.keys[0].Algorithm != "hmac-sha256" {
		t.Errorf("want default algorithm hmac-sha256, got %q", s.keys[0].Algorithm)
	}
}

func TestDDNSAPI_DeleteKey_NoName(t *testing.T) {
	h, _, _ := newDDNSHandler(t)
	rr := do(t, h, http.MethodDelete, "/api/ddns/keys/", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", rr.Code, rr.Body.String())
	}
}
