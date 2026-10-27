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
	"github.com/mw7101/domudns/internal/store"
)

// cloneTestStore is a minimal in-memory ZoneStore for clone tests.
type cloneTestStore struct {
	zones map[string]*dns.Zone // key: "domain" or "domain@view"
}

func newCloneTestStore() *cloneTestStore {
	return &cloneTestStore{zones: make(map[string]*dns.Zone)}
}

func (s *cloneTestStore) key(domain, view string) string {
	if view != "" {
		return domain + "@" + view
	}
	return domain
}

func (s *cloneTestStore) GetZone(ctx context.Context, domain string) (*dns.Zone, error) {
	z, ok := s.zones[domain]
	if !ok {
		return nil, dns.ErrZoneNotFound
	}
	return z, nil
}

func (s *cloneTestStore) GetZoneView(ctx context.Context, domain, view string) (*dns.Zone, error) {
	z, ok := s.zones[s.key(domain, view)]
	if !ok {
		return nil, dns.ErrZoneNotFound
	}
	return z, nil
}

func (s *cloneTestStore) PutZone(ctx context.Context, zone *dns.Zone) error {
	s.zones[s.key(zone.Domain, zone.View)] = zone
	return nil
}

// ZoneStore interface requires additional methods — implement as no-ops.
func (s *cloneTestStore) ListZones(ctx context.Context) ([]*dns.Zone, error)            { return nil, nil }
func (s *cloneTestStore) DeleteZone(ctx context.Context, domain string) error           { return nil }
func (s *cloneTestStore) DeleteZoneView(ctx context.Context, domain, view string) error { return nil }

// UpdateZone is unused by the zone_cloner code paths under test (cloning
// only reads the source zone and PutZone's the clone) — no-op like the
// other unused ZoneStore methods above.
func (s *cloneTestStore) UpdateZone(ctx context.Context, domain, view string, mutate func(*dns.Zone) error) error {
	return nil
}

func makeSourceZone() *dns.Zone {
	return &dns.Zone{
		Domain:      "source.example.com",
		View:        "",
		TTL:         3600,
		TTLOverride: 300,
		Nameservers: []string{"ns1.example.com"},
		Records: []dns.Record{
			{ID: 10, Name: "@", Type: dns.TypeA, TTL: 3600, Value: "1.2.3.4"},
			{ID: 20, Name: "mail", Type: dns.TypeMX, TTL: 3600, Value: "mail.example.com", Priority: 10},
		},
		SOA: &dns.SOA{MName: "ns1.source.example.com.", RName: "admin.source.example.com."},
	}
}

// cloneResponse wraps the api.Response so we can unpack the data field.
type cloneResponse struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
}

func unmarshalZone(t *testing.T, body []byte) dns.Zone {
	t.Helper()
	var wrapper cloneResponse
	if err := json.Unmarshal(body, &wrapper); err != nil {
		t.Fatalf("unmarshal response wrapper: %v", err)
	}
	var result dns.Zone
	if err := json.Unmarshal(wrapper.Data, &result); err != nil {
		t.Fatalf("unmarshal zone from data: %v", err)
	}
	return result
}

func doClone(t *testing.T, s store.ZoneStore, sourceDomain, sourceView, newDomain, newView string) *httptest.ResponseRecorder {
	t.Helper()
	reloaded := false
	h := api.NewZoneCloneHandler(s, func() error { reloaded = true; return nil })
	_ = reloaded

	body := map[string]string{"new_domain": newDomain, "new_view": newView}
	b, _ := json.Marshal(body)
	url := "/api/zones/" + sourceDomain + "/clone"
	if sourceView != "" {
		url += "?view=" + sourceView
	}
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestCloneZone_HappyPath(t *testing.T) {
	s := newCloneTestStore()
	s.zones["source.example.com"] = makeSourceZone()

	w := doClone(t, s, "source.example.com", "", "target.example.net", "")
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body)
	}

	result := unmarshalZone(t, w.Body.Bytes())
	if result.Domain != "target.example.net" {
		t.Errorf("domain = %q, want target.example.net", result.Domain)
	}
	if result.View != "" {
		t.Errorf("view = %q, want empty", result.View)
	}
	if len(result.Records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(result.Records))
	}
	if result.Records[0].ID != 1 || result.Records[1].ID != 2 {
		t.Errorf("IDs not sequential: %d, %d", result.Records[0].ID, result.Records[1].ID)
	}
	if result.TTL != 3600 || result.TTLOverride != 300 {
		t.Errorf("metadata not copied: TTL=%d TTLOverride=%d", result.TTL, result.TTLOverride)
	}
	if len(result.Nameservers) != 1 || result.Nameservers[0] != "ns1.example.com" {
		t.Errorf("nameservers not copied: %v", result.Nameservers)
	}
}

func TestCloneZone_FreshSOA(t *testing.T) {
	s := newCloneTestStore()
	src := makeSourceZone()
	s.zones["source.example.com"] = src

	w := doClone(t, s, "source.example.com", "", "clone.example.com", "")
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}
	result := unmarshalZone(t, w.Body.Bytes())
	if result.SOA == nil {
		t.Fatal("SOA must not be nil")
	}
	if result.SOA.MName == src.SOA.MName {
		t.Errorf("SOA.MName copied from source; expected fresh SOA")
	}
}

func TestCloneZone_ZeroRecords(t *testing.T) {
	s := newCloneTestStore()
	s.zones["empty.example.com"] = &dns.Zone{
		Domain: "empty.example.com",
		TTL:    3600,
		SOA:    &dns.SOA{MName: "ns1.empty.example.com."},
	}
	w := doClone(t, s, "empty.example.com", "", "clone.example.com", "")
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body)
	}
	result := unmarshalZone(t, w.Body.Bytes())
	if len(result.Records) != 0 {
		t.Errorf("expected 0 records, got %d", len(result.Records))
	}
	if result.SOA == nil {
		t.Error("SOA must not be nil")
	}
}

func TestCloneZone_CrossView(t *testing.T) {
	s := newCloneTestStore()
	src := makeSourceZone()
	src.View = "internal"
	s.zones["source.example.com@internal"] = src

	w := doClone(t, s, "source.example.com", "internal", "source.example.com", "")
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body)
	}
	result := unmarshalZone(t, w.Body.Bytes())
	if result.View != "" {
		t.Errorf("expected empty view, got %q", result.View)
	}
}

func TestCloneZone_SelfClone_Conflict(t *testing.T) {
	s := newCloneTestStore()
	s.zones["source.example.com"] = makeSourceZone()

	w := doClone(t, s, "source.example.com", "", "source.example.com", "")
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", w.Code)
	}
}

func TestCloneZone_TargetExists(t *testing.T) {
	s := newCloneTestStore()
	s.zones["source.example.com"] = makeSourceZone()
	s.zones["target.example.com"] = &dns.Zone{Domain: "target.example.com", TTL: 3600}

	w := doClone(t, s, "source.example.com", "", "target.example.com", "")
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", w.Code)
	}
}

func TestCloneZone_SourceNotFound(t *testing.T) {
	s := newCloneTestStore()
	w := doClone(t, s, "notexist.example.com", "", "new.example.com", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestCloneZone_InvalidNewDomain(t *testing.T) {
	s := newCloneTestStore()
	s.zones["source.example.com"] = makeSourceZone()
	w := doClone(t, s, "source.example.com", "", "not a valid domain!", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCloneZone_InvalidNewView(t *testing.T) {
	s := newCloneTestStore()
	s.zones["source.example.com"] = makeSourceZone()
	w := doClone(t, s, "source.example.com", "", "new.example.com", "INVALID VIEW!")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}
