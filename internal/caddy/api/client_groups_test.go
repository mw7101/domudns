package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mw7101/domudns/internal/caddy/api"
	"github.com/mw7101/domudns/internal/dns"
	"github.com/mw7101/domudns/internal/dnsserver"
)

type clientGroupTestStore struct {
	groups []*dns.ClientGroup
}

func (s *clientGroupTestStore) GetClientGroups(_ context.Context) ([]*dns.ClientGroup, error) {
	if s.groups == nil {
		return []*dns.ClientGroup{}, nil
	}
	return s.groups, nil
}
func (s *clientGroupTestStore) SetClientGroups(_ context.Context, groups []*dns.ClientGroup) error {
	s.groups = groups
	return nil
}

func TestClientGroupsHandlerGETEmpty(t *testing.T) {
	h := api.NewClientGroupsHandler(&clientGroupTestStore{}, dnsserver.NewClientGroupResolver())
	req := httptest.NewRequest(http.MethodGet, "/api/client-groups", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		Data []dns.ClientGroup `json:"data"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Data == nil {
		t.Error("data should be [] not null")
	}
}

func TestClientGroupsHandlerPUTValid(t *testing.T) {
	h := api.NewClientGroupsHandler(&clientGroupTestStore{}, dnsserver.NewClientGroupResolver())
	body := `[{"name":"kinder","cidrs":["192.168.2.0/24"],"categories":["ads","malware"]}]`
	req := httptest.NewRequest(http.MethodPut, "/api/client-groups", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestClientGroupsHandlerPUTInvalidCIDR(t *testing.T) {
	h := api.NewClientGroupsHandler(&clientGroupTestStore{}, dnsserver.NewClientGroupResolver())
	body := `[{"name":"bad","cidrs":["not-cidr"],"categories":["ads"]}]`
	req := httptest.NewRequest(http.MethodPut, "/api/client-groups", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestClientGroupsHandlerPUTUnknownCategory(t *testing.T) {
	h := api.NewClientGroupsHandler(&clientGroupTestStore{}, dnsserver.NewClientGroupResolver())
	body := `[{"name":"x","cidrs":["10.0.0.0/8"],"categories":["unknowncategory"]}]`
	req := httptest.NewRequest(http.MethodPut, "/api/client-groups", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestClientGroupsHandlerPUTDuplicateName(t *testing.T) {
	h := api.NewClientGroupsHandler(&clientGroupTestStore{}, dnsserver.NewClientGroupResolver())
	body := `[{"name":"x","cidrs":["10.0.0.0/8"],"categories":["ads"]},{"name":"x","cidrs":["172.16.0.0/12"],"categories":["malware"]}]`
	req := httptest.NewRequest(http.MethodPut, "/api/client-groups", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestClientGroupsHandlerPUTEmpty(t *testing.T) {
	h := api.NewClientGroupsHandler(&clientGroupTestStore{}, dnsserver.NewClientGroupResolver())
	req := httptest.NewRequest(http.MethodPut, "/api/client-groups", bytes.NewBufferString("[]"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for empty PUT, got %d", w.Code)
	}
}
