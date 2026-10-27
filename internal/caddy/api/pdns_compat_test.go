package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mw7101/domudns/internal/dns"
)

// pdnsTestStore is a minimal in-memory store.ZoneStore for pdns_compat tests.
type pdnsTestStore struct {
	zones map[string]*dns.Zone
}

func newPDNSTestStore() *pdnsTestStore {
	return &pdnsTestStore{zones: make(map[string]*dns.Zone)}
}

func (s *pdnsTestStore) GetZone(_ context.Context, domain string) (*dns.Zone, error) {
	z, ok := s.zones[domain]
	if !ok {
		return nil, dns.ErrZoneNotFound
	}
	// Return a copy so mutation by the handler under test doesn't alias the
	// stored fixture (mirrors filestore.GetZone, which decodes fresh JSON on
	// every call).
	cp := *z
	cp.Records = append([]dns.Record(nil), z.Records...)
	if z.SOA != nil {
		soa := *z.SOA
		cp.SOA = &soa
	}
	return &cp, nil
}

func (s *pdnsTestStore) GetZoneView(_ context.Context, domain, view string) (*dns.Zone, error) {
	return s.GetZone(context.Background(), domain+"@"+view)
}

func (s *pdnsTestStore) ListZones(_ context.Context) ([]*dns.Zone, error) {
	result := make([]*dns.Zone, 0, len(s.zones))
	for _, z := range s.zones {
		result = append(result, z)
	}
	return result, nil
}

func (s *pdnsTestStore) PutZone(_ context.Context, zone *dns.Zone) error {
	s.zones[zone.Domain] = zone
	return nil
}

func (s *pdnsTestStore) DeleteZone(_ context.Context, domain string) error {
	delete(s.zones, domain)
	return nil
}

func (s *pdnsTestStore) DeleteZoneView(_ context.Context, domain, view string) error {
	delete(s.zones, domain+"@"+view)
	return nil
}

// UpdateZone mirrors filestore.FileStore.UpdateZone: mutate runs against a
// private copy, which only replaces the stored zone if mutate succeeds —
// so a failed mutate (as exercised by the limit/validation tests) leaves
// the fixture untouched, just like the real store leaves the on-disk file
// untouched.
func (s *pdnsTestStore) UpdateZone(_ context.Context, domain, view string, mutate func(*dns.Zone) error) error {
	key := domain
	if view != "" {
		key = domain + "@" + view
	}
	orig, ok := s.zones[key]
	if !ok {
		return dns.ErrZoneNotFound
	}
	cp := *orig
	cp.Records = append([]dns.Record(nil), orig.Records...)
	if orig.SOA != nil {
		soa := *orig.SOA
		cp.SOA = &soa
	}
	if err := mutate(&cp); err != nil {
		return err
	}
	s.zones[key] = &cp
	return nil
}

func testZone() *dns.Zone {
	return &dns.Zone{
		Domain: "example.org",
		TTL:    3600,
		SOA: &dns.SOA{
			MName: "ns1.example.org", RName: "hostmaster.example.org",
			Serial: 2024010100, Refresh: 3600, Retry: 1800, Expire: 604800, Minimum: 300,
		},
		Records: []dns.Record{
			{ID: 1, Name: "@", Type: dns.TypeA, TTL: 3600, Value: "192.0.2.1"},
			{ID: 2, Name: "_acme-challenge", Type: dns.TypeTXT, TTL: 300, Value: "tok1"},
			{ID: 3, Name: "_acme-challenge", Type: dns.TypeTXT, TTL: 300, Value: "tok2"},
			{ID: 4, Name: "@", Type: dns.TypeFWD, TTL: 3600, Value: "1.2.3.4"},
		},
	}
}

func pdnsHandlerWithZone(z *dns.Zone) (*PDNSCompatHandler, *pdnsTestStore) {
	s := newPDNSTestStore()
	if z != nil {
		s.zones[z.Domain] = z
	}
	return NewPDNSCompatHandler(s, nil), s
}

// --- GET /zones ---

func TestPDNSCompat_ListZones(t *testing.T) {
	h, _ := pdnsHandlerWithZone(testZone())
	req := httptest.NewRequest(http.MethodGet, "/api/pdns/v1/servers/localhost/zones", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var zones []pdnsZoneSummary
	if err := json.Unmarshal(w.Body.Bytes(), &zones); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, w.Body.String())
	}
	if len(zones) != 1 || zones[0].Name != "example.org." {
		t.Errorf("zones = %+v, want one zone named example.org.", zones)
	}
	if zones[0].ID != "example.org." || zones[0].Kind != "Native" {
		t.Errorf("zones[0] = %+v", zones[0])
	}
}

// --- GET /zones/{zone_id} ---

func TestPDNSCompat_GetZone_GroupsMultiValueRRSet(t *testing.T) {
	h, _ := pdnsHandlerWithZone(testZone())
	req := httptest.NewRequest(http.MethodGet, "/api/pdns/v1/servers/localhost/zones/example.org.", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var detail pdnsZoneDetail
	if err := json.Unmarshal(w.Body.Bytes(), &detail); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, w.Body.String())
	}
	if detail.Name != "example.org." || detail.Serial != 2024010100 {
		t.Errorf("detail = %+v", detail)
	}

	var txtSet *pdnsRRSet
	for i := range detail.RRSets {
		if detail.RRSets[i].Type == "TXT" {
			txtSet = &detail.RRSets[i]
		}
		// FWD is domudns-synthetic and must never appear.
		if detail.RRSets[i].Type == "FWD" {
			t.Errorf("FWD rrset leaked into PowerDNS-compat response: %+v", detail.RRSets[i])
		}
	}
	if txtSet == nil {
		t.Fatal("no TXT rrset found")
	}
	if txtSet.Name != "_acme-challenge.example.org." {
		t.Errorf("TXT rrset name = %q, want _acme-challenge.example.org.", txtSet.Name)
	}
	if len(txtSet.Records) != 2 {
		t.Fatalf("TXT rrset has %d records, want 2 (multi-value grouping)", len(txtSet.Records))
	}
	contents := map[string]bool{txtSet.Records[0].Content: true, txtSet.Records[1].Content: true}
	if !contents[`"tok1"`] || !contents[`"tok2"`] {
		t.Errorf("TXT contents = %v, want quoted tok1/tok2", contents)
	}

	var soaSet *pdnsRRSet
	for i := range detail.RRSets {
		if detail.RRSets[i].Type == "SOA" {
			soaSet = &detail.RRSets[i]
		}
	}
	if soaSet == nil || len(soaSet.Records) != 1 {
		t.Fatalf("SOA rrset missing or malformed: %+v", soaSet)
	}

	// dns-lexicon indexes record["disabled"] without a default, so the field
	// must be present on every record even when it is false (see
	// pdnsRecordEntry) — this is what makes certbot-dns-powerdns work.
	if !strings.Contains(w.Body.String(), `"disabled":false`) {
		t.Errorf("GET zone detail omits disabled:false, which dns-lexicon requires; body=%s", w.Body.String())
	}
}

func TestPDNSCompat_GetZone_NotFound(t *testing.T) {
	h, _ := pdnsHandlerWithZone(nil)
	req := httptest.NewRequest(http.MethodGet, "/api/pdns/v1/servers/localhost/zones/nope.example.", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	assertPDNSErrorBody(t, w)
}

func assertPDNSErrorBody(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal error body: %v; body=%s", err, w.Body.String())
	}
	if body["error"] == "" {
		t.Errorf("body = %v, want non-empty \"error\" field (PowerDNS error shape)", body)
	}
}

// --- PATCH /zones/{zone_id} ---

func patchZone(t *testing.T, h *PDNSCompatHandler, domain string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPatch, "/api/pdns/v1/servers/localhost/zones/"+domain+".", bytes.NewReader(b))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// A successful PATCH must trigger the in-memory zone reload, otherwise the
// master keeps answering from its startup snapshot and ACME DNS-01 TXT
// records are only visible on cluster slaves (→ LE NXDOMAIN).
func TestPDNSCompat_Patch_TriggersZoneReload(t *testing.T) {
	s := newPDNSTestStore()
	s.zones["example.org"] = testZone()
	reloaded := make(chan struct{}, 1)
	h := NewPDNSCompatHandler(s, func() error {
		reloaded <- struct{}{}
		return nil
	})

	w := patchZone(t, h, "example.org", pdnsPatchRequest{
		RRSets: []pdnsRRSet{
			{
				Name: "_acme-challenge.example.org.", Type: "TXT", TTL: 300, ChangeType: "REPLACE",
				Records: []pdnsRecordEntry{{Content: `"reload-token"`}},
			},
		},
	})
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", w.Code, w.Body.String())
	}

	select {
	case <-reloaded:
	case <-time.After(2 * time.Second):
		t.Error("zone reloader was not called after a successful PATCH")
	}
}

func TestPDNSCompat_Patch_Replace(t *testing.T) {
	h, s := pdnsHandlerWithZone(testZone())
	w := patchZone(t, h, "example.org", pdnsPatchRequest{
		RRSets: []pdnsRRSet{
			{
				Name: "_acme-challenge.example.org.", Type: "TXT", TTL: 300, ChangeType: "REPLACE",
				Records: []pdnsRecordEntry{{Content: `"newtoken"`}},
			},
		},
	})
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", w.Code, w.Body.String())
	}

	updated := s.zones["example.org"]
	var txt []dns.Record
	for _, r := range updated.Records {
		if r.Type == dns.TypeTXT {
			txt = append(txt, r)
		}
	}
	if len(txt) != 1 || txt[0].Value != "newtoken" || txt[0].TTL != 300 {
		t.Errorf("TXT records after REPLACE = %+v, want single record {newtoken, ttl 120}", txt)
	}
}

func TestPDNSCompat_Patch_Delete(t *testing.T) {
	h, s := pdnsHandlerWithZone(testZone())
	w := patchZone(t, h, "example.org", pdnsPatchRequest{
		RRSets: []pdnsRRSet{
			{Name: "_acme-challenge.example.org.", Type: "TXT", ChangeType: "DELETE"},
		},
	})
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", w.Code, w.Body.String())
	}

	updated := s.zones["example.org"]
	for _, r := range updated.Records {
		if r.Type == dns.TypeTXT {
			t.Errorf("TXT record %+v still present after DELETE", r)
		}
	}
	// The unrelated A record must survive.
	found := false
	for _, r := range updated.Records {
		if r.Type == dns.TypeA {
			found = true
		}
	}
	if !found {
		t.Error("A record was removed by an unrelated TXT DELETE")
	}
}

func TestPDNSCompat_Patch_UnknownZone_404(t *testing.T) {
	h, _ := pdnsHandlerWithZone(nil)
	w := patchZone(t, h, "nope.example", pdnsPatchRequest{RRSets: []pdnsRRSet{}})
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
}

func TestPDNSCompat_Patch_InvalidChangeType_422(t *testing.T) {
	h, _ := pdnsHandlerWithZone(testZone())
	w := patchZone(t, h, "example.org", pdnsPatchRequest{
		RRSets: []pdnsRRSet{
			{Name: "www.example.org.", Type: "A", TTL: 300, ChangeType: "BOGUS",
				Records: []pdnsRecordEntry{{Content: "192.0.2.2"}}},
		},
	})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", w.Code, w.Body.String())
	}
	assertPDNSErrorBody(t, w)
}

func TestPDNSCompat_Patch_UnsupportedType_422(t *testing.T) {
	h, _ := pdnsHandlerWithZone(testZone())
	w := patchZone(t, h, "example.org", pdnsPatchRequest{
		RRSets: []pdnsRRSet{
			{Name: "www.example.org.", Type: "ALIAS", TTL: 300, ChangeType: "REPLACE",
				Records: []pdnsRecordEntry{{Content: "target.example.net."}}},
		},
	})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", w.Code, w.Body.String())
	}
	assertPDNSErrorBody(t, w)
}

func TestPDNSCompat_Patch_BrokenContent_422(t *testing.T) {
	h, _ := pdnsHandlerWithZone(testZone())
	w := patchZone(t, h, "example.org", pdnsPatchRequest{
		RRSets: []pdnsRRSet{
			{Name: "www.example.org.", Type: "A", TTL: 300, ChangeType: "REPLACE",
				Records: []pdnsRecordEntry{{Content: "not-an-ip"}}},
		},
	})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", w.Code, w.Body.String())
	}
	assertPDNSErrorBody(t, w)
}

func TestPDNSCompat_Patch_SOADeleteGuard_422(t *testing.T) {
	h, _ := pdnsHandlerWithZone(testZone())
	w := patchZone(t, h, "example.org", pdnsPatchRequest{
		RRSets: []pdnsRRSet{
			{Name: "example.org.", Type: "SOA", ChangeType: "DELETE"},
		},
	})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", w.Code, w.Body.String())
	}
	assertPDNSErrorBody(t, w)
}

func TestPDNSCompat_Patch_SOAReplaceEmptyRecords_422(t *testing.T) {
	h, _ := pdnsHandlerWithZone(testZone())
	w := patchZone(t, h, "example.org", pdnsPatchRequest{
		RRSets: []pdnsRRSet{
			{Name: "example.org.", Type: "SOA", ChangeType: "REPLACE", Records: []pdnsRecordEntry{}},
		},
	})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", w.Code, w.Body.String())
	}
	assertPDNSErrorBody(t, w)
}

func TestPDNSCompat_Patch_SOAReplace_UpdatesZone(t *testing.T) {
	h, s := pdnsHandlerWithZone(testZone())
	w := patchZone(t, h, "example.org", pdnsPatchRequest{
		RRSets: []pdnsRRSet{
			{
				Name: "example.org.", Type: "SOA", ChangeType: "REPLACE",
				Records: []pdnsRecordEntry{{Content: "ns1.example.org. hostmaster.example.org. 2024010200 3600 1800 604800 300"}},
			},
		},
	})
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", w.Code, w.Body.String())
	}
	if s.zones["example.org"].SOA.Serial != 2024010200 {
		t.Errorf("SOA serial = %d, want 2024010200", s.zones["example.org"].SOA.Serial)
	}
}

// --- PATCH request size limits (RRsets / records per rrset) ---

// buildRRSets returns n distinct, valid TXT REPLACE rrsets (one record
// each), used to probe the maxPDNSPatchRRSets boundary without tripping
// any other validation rule.
func buildRRSets(n int) []pdnsRRSet {
	rrsets := make([]pdnsRRSet, n)
	for i := 0; i < n; i++ {
		rrsets[i] = pdnsRRSet{
			Name: fmt.Sprintf("bulk%d.example.org.", i), Type: "TXT", TTL: 300, ChangeType: "REPLACE",
			Records: []pdnsRecordEntry{{Content: fmt.Sprintf(`"v%d"`, i)}},
		}
	}
	return rrsets
}

// buildRecords returns n distinct, valid TXT record entries for a single
// rrset, used to probe the maxPDNSPatchRecordsPerRRSet boundary.
func buildRecords(n int) []pdnsRecordEntry {
	records := make([]pdnsRecordEntry, n)
	for i := 0; i < n; i++ {
		records[i] = pdnsRecordEntry{Content: fmt.Sprintf(`"v%d"`, i)}
	}
	return records
}

func TestPDNSCompat_Patch_RRSetLimit_AtLimit_OK(t *testing.T) {
	h, s := pdnsHandlerWithZone(testZone())
	w := patchZone(t, h, "example.org", pdnsPatchRequest{RRSets: buildRRSets(maxPDNSPatchRRSets)})
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 at exactly the limit (%d rrsets); body=%s", w.Code, maxPDNSPatchRRSets, w.Body.String())
	}
	count := 0
	for _, r := range s.zones["example.org"].Records {
		if r.Type == dns.TypeTXT && strings.HasPrefix(r.Name, "bulk") {
			count++
		}
	}
	if count != maxPDNSPatchRRSets {
		t.Errorf("bulk TXT records written = %d, want %d", count, maxPDNSPatchRRSets)
	}
}

func TestPDNSCompat_Patch_RRSetLimit_ExceedsLimit_422(t *testing.T) {
	h, s := pdnsHandlerWithZone(testZone())
	original := len(s.zones["example.org"].Records)

	w := patchZone(t, h, "example.org", pdnsPatchRequest{RRSets: buildRRSets(maxPDNSPatchRRSets + 1)})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 for %d rrsets (limit %d); body=%s", w.Code, maxPDNSPatchRRSets+1, maxPDNSPatchRRSets, w.Body.String())
	}
	assertPDNSErrorBody(t, w)

	if got := len(s.zones["example.org"].Records); got != original {
		t.Errorf("zone was mutated despite rejected request: %d records, want unchanged %d", got, original)
	}
}

func TestPDNSCompat_Patch_RecordsPerRRSetLimit_AtLimit_OK(t *testing.T) {
	h, s := pdnsHandlerWithZone(testZone())
	w := patchZone(t, h, "example.org", pdnsPatchRequest{
		RRSets: []pdnsRRSet{
			{Name: "bulk.example.org.", Type: "TXT", TTL: 300, ChangeType: "REPLACE",
				Records: buildRecords(maxPDNSPatchRecordsPerRRSet)},
		},
	})
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 at exactly the limit (%d records); body=%s", w.Code, maxPDNSPatchRecordsPerRRSet, w.Body.String())
	}
	count := 0
	for _, r := range s.zones["example.org"].Records {
		if r.Type == dns.TypeTXT && r.Name == "bulk" {
			count++
		}
	}
	if count != maxPDNSPatchRecordsPerRRSet {
		t.Errorf("records in bulk rrset = %d, want %d", count, maxPDNSPatchRecordsPerRRSet)
	}
}

func TestPDNSCompat_Patch_RecordsPerRRSetLimit_ExceedsLimit_422(t *testing.T) {
	h, s := pdnsHandlerWithZone(testZone())
	original := len(s.zones["example.org"].Records)

	w := patchZone(t, h, "example.org", pdnsPatchRequest{
		RRSets: []pdnsRRSet{
			{Name: "bulk.example.org.", Type: "TXT", TTL: 300, ChangeType: "REPLACE",
				Records: buildRecords(maxPDNSPatchRecordsPerRRSet + 1)},
		},
	})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 for %d records (limit %d); body=%s", w.Code, maxPDNSPatchRecordsPerRRSet+1, maxPDNSPatchRecordsPerRRSet, w.Body.String())
	}
	assertPDNSErrorBody(t, w)

	if got := len(s.zones["example.org"].Records); got != original {
		t.Errorf("zone was mutated despite rejected request: %d records, want unchanged %d", got, original)
	}
}

// --- Path validation ---

func TestPDNSCompat_InvalidZoneID_422(t *testing.T) {
	h, _ := pdnsHandlerWithZone(testZone())
	req := httptest.NewRequest(http.MethodGet, "/api/pdns/v1/servers/localhost/zones/..%2f..%2fetc", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnprocessableEntity && w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 422 or 404 for path-traversal-shaped zone id", w.Code)
	}
}

// --- Router: slave read-only enforcement ---

func TestPDNSCompat_Router_SlaveBlocksPatchAllowsGet(t *testing.T) {
	authMgr := newTestAuthManagerWithKey(t, testAPIKey)
	sessions := NewSessionManager(context.Background())
	zonesH := NewZonesHandler(nil, nil)
	recordsH := NewRecordsHandler(nil, nil, nil)
	router := NewRouter(nil, nil, nil, zonesH, recordsH, nil, nil, authMgr, nil, nil, sessions, false)
	pdnsH, _ := pdnsHandlerWithZone(testZone())
	router.SetPDNSCompatHandler(pdnsH)
	router.SetSlaveMode("https://master.internal")

	patchReq := httptest.NewRequest(http.MethodPatch, "/api/pdns/v1/servers/localhost/zones/example.org.", bytes.NewReader([]byte(`{"rrsets":[]}`)))
	patchReq.Header.Set("Authorization", "Bearer "+testAPIKey)
	patchW := httptest.NewRecorder()
	router.ServeHTTP(patchW, patchReq)
	if patchW.Code != http.StatusForbidden {
		t.Errorf("PATCH on slave: status = %d, want 403; body=%s", patchW.Code, patchW.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/pdns/v1/servers/localhost/zones", nil)
	getReq.Header.Set("Authorization", "Bearer "+testAPIKey)
	getW := httptest.NewRecorder()
	router.ServeHTTP(getW, getReq)
	if getW.Code != http.StatusOK {
		t.Errorf("GET on slave: status = %d, want 200; body=%s", getW.Code, getW.Body.String())
	}
}

// --- Router: canonical /api/v1/servers/ prefix reaches the handler ---

// TestPDNSCompat_Router_CanonicalPath guards the router wiring for the
// canonical prefix acme.sh's dns_pdns hook and the Proxmox VE pdns plugin
// build. Without it the request falls through to the "Unknown endpoint" 404
// and the hook aborts with "invalid domain".
func TestPDNSCompat_Router_CanonicalPath(t *testing.T) {
	authMgr := newTestAuthManagerWithKey(t, testAPIKey)
	sessions := NewSessionManager(context.Background())
	zonesH := NewZonesHandler(nil, nil)
	recordsH := NewRecordsHandler(nil, nil, nil)
	router := NewRouter(nil, nil, nil, zonesH, recordsH, nil, nil, authMgr, nil, nil, sessions, false)
	pdnsH, _ := pdnsHandlerWithZone(testZone())
	router.SetPDNSCompatHandler(pdnsH)

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/servers/localhost/zones", nil)
	getReq.Header.Set("X-API-Key", testAPIKey)
	getW := httptest.NewRecorder()
	router.ServeHTTP(getW, getReq)
	if getW.Code != http.StatusOK {
		t.Fatalf("canonical GET via router: status = %d, want 200; body=%s", getW.Code, getW.Body.String())
	}
	var zones []pdnsZoneSummary
	if err := json.Unmarshal(getW.Body.Bytes(), &zones); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, getW.Body.String())
	}
	if len(zones) != 1 || zones[0].Name != "example.org." {
		t.Errorf("zones = %+v, want one zone named example.org.", zones)
	}

	patchReq := httptest.NewRequest(http.MethodPatch, "/api/v1/servers/localhost/zones/example.org.",
		bytes.NewReader([]byte(`{"rrsets":[{"name":"_acme-challenge.example.org.","type":"TXT","ttl":300,"changetype":"REPLACE","records":[{"content":"\"via-router\""}]}]}`)))
	patchReq.Header.Set("X-API-Key", testAPIKey)
	patchW := httptest.NewRecorder()
	router.ServeHTTP(patchW, patchReq)
	if patchW.Code != http.StatusNoContent {
		t.Fatalf("canonical PATCH via router: status = %d, want 204; body=%s", patchW.Code, patchW.Body.String())
	}
}

// TestPDNSCompat_Router_CanonicalPath_Guards verifies the AuthMiddleware and
// the slave read-only guard apply to the canonical prefix exactly as they do
// to the legacy one — the new route must not be a way around either.
func TestPDNSCompat_Router_CanonicalPath_Guards(t *testing.T) {
	authMgr := newTestAuthManagerWithKey(t, testAPIKey)
	sessions := NewSessionManager(context.Background())
	zonesH := NewZonesHandler(nil, nil)
	recordsH := NewRecordsHandler(nil, nil, nil)

	newRouter := func() *Router {
		r := NewRouter(nil, nil, nil, zonesH, recordsH, nil, nil, authMgr, nil, nil, sessions, false)
		h, _ := pdnsHandlerWithZone(testZone())
		r.SetPDNSCompatHandler(h)
		return r
	}

	// No credentials → 401 (the invalid-key test bypasses the router).
	req := httptest.NewRequest(http.MethodGet, "/api/v1/servers/localhost/zones", nil)
	w := httptest.NewRecorder()
	newRouter().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated canonical GET: status = %d, want 401; body=%s", w.Code, w.Body.String())
	}

	// Slave mode → a mutating canonical request is refused before auth runs.
	slaveRouter := newRouter()
	slaveRouter.SetSlaveMode("https://master.internal")
	patchReq := httptest.NewRequest(http.MethodPatch, "/api/v1/servers/localhost/zones/example.org.",
		bytes.NewReader([]byte(`{"rrsets":[]}`)))
	patchReq.Header.Set("X-API-Key", testAPIKey)
	patchW := httptest.NewRecorder()
	slaveRouter.ServeHTTP(patchW, patchReq)
	if patchW.Code != http.StatusForbidden {
		t.Errorf("canonical PATCH on slave: status = %d, want 403; body=%s", patchW.Code, patchW.Body.String())
	}
}

// --- Auth: X-API-Key ---

func TestPDNSCompat_Auth_XAPIKeyHeader(t *testing.T) {
	h, _ := pdnsHandlerWithZone(testZone())
	authMgr := newTestAuthManagerWithKey(t, testAPIKey)
	wrapped := AuthMiddleware(authMgr, NewSessionManager(context.Background()), h)

	req := httptest.NewRequest(http.MethodGet, "/api/pdns/v1/servers/localhost/zones", nil)
	req.Header.Set("X-API-Key", testAPIKey)
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

func TestPDNSCompat_Auth_XAPIKeyHeader_Invalid(t *testing.T) {
	h, _ := pdnsHandlerWithZone(testZone())
	authMgr := newTestAuthManagerWithKey(t, testAPIKey)
	wrapped := AuthMiddleware(authMgr, NewSessionManager(context.Background()), h)

	req := httptest.NewRequest(http.MethodGet, "/api/pdns/v1/servers/localhost/zones", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
}

// --- Canonical /api/v1/servers/ prefix (acme.sh dns_pdns, PVE plugin) ---

// patchZoneCanonical issues a PATCH to the canonical /api/v1/servers/ path.
func patchZoneCanonical(t *testing.T, h *PDNSCompatHandler, domain string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/servers/localhost/zones/"+domain+".", bytes.NewReader(b))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestPDNSCompat_Canonical_ListAndDetail(t *testing.T) {
	h, _ := pdnsHandlerWithZone(testZone())

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/servers/localhost/zones", nil)
	listW := httptest.NewRecorder()
	h.ServeHTTP(listW, listReq)
	if listW.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200; body=%s", listW.Code, listW.Body.String())
	}
	var zones []pdnsZoneSummary
	if err := json.Unmarshal(listW.Body.Bytes(), &zones); err != nil {
		t.Fatalf("unmarshal list: %v; body=%s", err, listW.Body.String())
	}
	if len(zones) != 1 || zones[0].Name != "example.org." {
		t.Errorf("zones = %+v, want one zone named example.org.", zones)
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/api/v1/servers/localhost/zones/example.org.", nil)
	detailW := httptest.NewRecorder()
	h.ServeHTTP(detailW, detailReq)
	if detailW.Code != http.StatusOK {
		t.Fatalf("detail status = %d, want 200; body=%s", detailW.Code, detailW.Body.String())
	}
	var detail pdnsZoneDetail
	if err := json.Unmarshal(detailW.Body.Bytes(), &detail); err != nil {
		t.Fatalf("unmarshal detail: %v; body=%s", err, detailW.Body.String())
	}
	if detail.Name != "example.org." || detail.Serial != 2024010100 {
		t.Errorf("detail = %+v", detail)
	}
}

func TestPDNSCompat_Canonical_PatchReplaceAndDelete(t *testing.T) {
	h, s := pdnsHandlerWithZone(testZone())

	replaceW := patchZoneCanonical(t, h, "example.org", pdnsPatchRequest{
		RRSets: []pdnsRRSet{
			{
				Name: "_acme-challenge.example.org.", Type: "TXT", TTL: 300, ChangeType: "REPLACE",
				Records: []pdnsRecordEntry{{Content: `"canonical-token"`}},
			},
		},
	})
	if replaceW.Code != http.StatusNoContent {
		t.Fatalf("REPLACE status = %d, want 204; body=%s", replaceW.Code, replaceW.Body.String())
	}
	var txt []dns.Record
	for _, r := range s.zones["example.org"].Records {
		if r.Type == dns.TypeTXT {
			txt = append(txt, r)
		}
	}
	if len(txt) != 1 || txt[0].Value != "canonical-token" || txt[0].TTL != 300 {
		t.Errorf("TXT records after canonical REPLACE = %+v, want single {canonical-token, ttl 300}", txt)
	}

	deleteW := patchZoneCanonical(t, h, "example.org", pdnsPatchRequest{
		RRSets: []pdnsRRSet{
			{Name: "_acme-challenge.example.org.", Type: "TXT", ChangeType: "DELETE"},
		},
	})
	if deleteW.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, want 204; body=%s", deleteW.Code, deleteW.Body.String())
	}
	for _, r := range s.zones["example.org"].Records {
		if r.Type == dns.TypeTXT {
			t.Errorf("TXT record %+v still present after canonical DELETE", r)
		}
	}
}

// TestPDNSCompat_Canonical_PatchMultiLabelRelativeName covers the ACME
// DNS-01 case for hosts below the zone apex: Proxmox VE's "DNS-01 PowerDNS
// API" plugin (acme.sh dns_pdns) writes "_acme-challenge.<host>.<zone>." and
// domudns must store it as the multi-label relative name
// "_acme-challenge.<host>" instead of rejecting it with 422.
func TestPDNSCompat_Canonical_PatchMultiLabelRelativeName(t *testing.T) {
	h, s := pdnsHandlerWithZone(testZone())

	replaceW := patchZoneCanonical(t, h, "example.org", pdnsPatchRequest{
		RRSets: []pdnsRRSet{
			{
				Name: "_acme-challenge.pve-node.example.org.", Type: "TXT", TTL: 300, ChangeType: "REPLACE",
				Records: []pdnsRecordEntry{{Content: `"pve-node-token"`}},
			},
		},
	})
	if replaceW.Code != http.StatusNoContent {
		t.Fatalf("REPLACE status = %d, want 204; body=%s", replaceW.Code, replaceW.Body.String())
	}

	var stored []dns.Record
	for _, r := range s.zones["example.org"].Records {
		if r.Name == "_acme-challenge.pve-node" {
			stored = append(stored, r)
		}
	}
	if len(stored) != 1 || stored[0].Type != dns.TypeTXT || stored[0].Value != "pve-node-token" {
		t.Fatalf("records named _acme-challenge.pve-node = %+v, want single TXT {pve-node-token}", stored)
	}

	deleteW := patchZoneCanonical(t, h, "example.org", pdnsPatchRequest{
		RRSets: []pdnsRRSet{
			{Name: "_acme-challenge.pve-node.example.org.", Type: "TXT", ChangeType: "DELETE"},
		},
	})
	if deleteW.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, want 204; body=%s", deleteW.Code, deleteW.Body.String())
	}
	for _, r := range s.zones["example.org"].Records {
		if r.Name == "_acme-challenge.pve-node" {
			t.Errorf("record %+v still present after DELETE", r)
		}
	}
}

// TestPDNSCompat_Canonical_Patch_ClampsLowTTL verifies a requested TTL below
// dns.MinRecordTTL is clamped to it instead of being rejected with 422 —
// acme.sh's default PDNS_Ttl is 60 and it does not use curl --fail, so a 422
// makes the hook report success while the record is never written.
func TestPDNSCompat_Canonical_Patch_ClampsLowTTL(t *testing.T) {
	h, s := pdnsHandlerWithZone(testZone())

	w := patchZoneCanonical(t, h, "example.org", pdnsPatchRequest{
		RRSets: []pdnsRRSet{
			{
				Name: "ttl.example.org.", Type: "A", TTL: 60, ChangeType: "REPLACE",
				Records: []pdnsRecordEntry{{Content: "192.0.2.9"}},
			},
		},
	})
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", w.Code, w.Body.String())
	}

	for _, r := range s.zones["example.org"].Records {
		if r.Name != "ttl" {
			continue
		}
		if r.TTL != dns.MinRecordTTL {
			t.Errorf("TTL = %d, want clamped to %d", r.TTL, dns.MinRecordTTL)
		}
		return
	}
	t.Fatal("record ttl.example.org was not stored")
}

func TestPDNSCompat_LegacyAlias_StillWorks(t *testing.T) {
	h, _ := pdnsHandlerWithZone(testZone())
	req := httptest.NewRequest(http.MethodGet, "/api/pdns/v1/servers/localhost/zones", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("legacy list status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var zones []pdnsZoneSummary
	if err := json.Unmarshal(w.Body.Bytes(), &zones); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, w.Body.String())
	}
	if len(zones) != 1 || zones[0].Name != "example.org." {
		t.Errorf("zones = %+v, want one zone named example.org.", zones)
	}
}

func TestPDNSCompat_Notify_Canonical(t *testing.T) {
	h, _ := pdnsHandlerWithZone(testZone())
	req := httptest.NewRequest(http.MethodPut, "/api/v1/servers/localhost/zones/example.org./notify", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", w.Code, w.Body.String())
	}
}

func TestPDNSCompat_Notify_InvalidZoneID_422(t *testing.T) {
	h, _ := pdnsHandlerWithZone(testZone())
	req := httptest.NewRequest(http.MethodPut, "/api/v1/servers/localhost/zones/invalid_zone./notify", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", w.Code, w.Body.String())
	}
	assertPDNSErrorBody(t, w)
}

func TestPDNSCompat_Notify_WrongMethod_405(t *testing.T) {
	h, _ := pdnsHandlerWithZone(testZone())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/servers/localhost/zones/example.org./notify", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405; body=%s", w.Code, w.Body.String())
	}
	assertPDNSErrorBody(t, w)
}

// --- Unit tests for small helpers ---

func TestRelativeRecordName(t *testing.T) {
	tests := []struct {
		name       string
		rrsetName  string
		zoneDomain string
		want       string
		wantErr    bool
	}{
		{"apex", "example.org.", "example.org", "@", false},
		{"apex_no_trailing_dot", "example.org", "example.org", "@", false},
		{"subdomain", "_acme-challenge.example.org.", "example.org", "_acme-challenge", false},
		{"outside_zone", "example.net.", "example.org", "", true},
		{"case_insensitive", "WWW.Example.ORG.", "example.org", "www", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := relativeRecordName(tt.rrsetName, tt.zoneDomain)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseSOAContent(t *testing.T) {
	soa, err := parseSOAContent("ns1.example.org. hostmaster.example.org. 2024010100 3600 1800 604800 300")
	if err != nil {
		t.Fatalf("parseSOAContent: %v", err)
	}
	if soa.MName != "ns1.example.org" || soa.Serial != 2024010100 || soa.Minimum != 300 {
		t.Errorf("soa = %+v", soa)
	}

	if _, err := parseSOAContent("too few fields"); err == nil {
		t.Error("expected error for malformed SOA content")
	}
}
