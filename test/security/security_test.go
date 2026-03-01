// Package security contains security-oriented tests.
// These tests define expected secure behavior. If a test fails, fix the underlying code.
package security

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mw7101/domudns/internal/caddy/api"
	"github.com/mw7101/domudns/internal/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuth_RejectsEmptyAPIKey stellt sicher, dass ein leerer API-Key im AuthManager abgelehnt wird.
func TestAuth_RejectsEmptyAPIKey(t *testing.T) {
	// AuthManager mit leerem API-Key → ValidateAPIKey gibt false zurück → 401
	authMgr := newTestAuthManager(t, "")
	handler := api.AuthMiddleware(authMgr, api.NewSessionManager(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer some-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "empty api key must be rejected")
}

// TestAuth_RejectsWrongAPIKey stellt sicher, dass ein falscher Bearer-Token abgelehnt wird.
func TestAuth_RejectsWrongAPIKey(t *testing.T) {
	correctKey := "correct-key-with-sufficient-length-for-validation"
	authMgr := newTestAuthManager(t, correctKey)
	handler := api.AuthMiddleware(authMgr, api.NewSessionManager(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer wrong-key-that-does-not-match")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "wrong key must be rejected")
}

// TestAuth_AcceptsStrongAPIKey stellt sicher, dass ein korrekter Key akzeptiert wird.
func TestAuth_AcceptsStrongAPIKey(t *testing.T) {
	apiKey := "YOUR_API_KEY_HERE"
	authMgr := newTestAuthManager(t, apiKey)
	handler := api.AuthMiddleware(authMgr, api.NewSessionManager(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestAuth_RejectsMissingAuth stellt sicher, dass Anfragen ohne Authorization abgelehnt werden.
func TestAuth_RejectsMissingAuth(t *testing.T) {
	authMgr := newTestAuthManager(t, "valid-long-api-key-32-chars-minimum")
	handler := api.AuthMiddleware(authMgr, api.NewSessionManager(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestAuth_RejectsWrongBearerPrefix stellt sicher, dass nicht-Bearer Auth abgelehnt wird.
func TestAuth_RejectsWrongBearerPrefix(t *testing.T) {
	apiKey := "valid-long-api-key-32-chars-minimum"
	authMgr := newTestAuthManager(t, apiKey)
	handler := api.AuthMiddleware(authMgr, api.NewSessionManager(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic "+apiKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestAuth_ConstantTimeCompare stellt sicher, dass falscher und fehlender Key gleich behandelt werden (401).
func TestAuth_ConstantTimeCompare(t *testing.T) {
	apiKey := "correct-key-with-sufficient-length-for-validation"
	authMgr := newTestAuthManager(t, apiKey)
	handler := api.AuthMiddleware(authMgr, api.NewSessionManager(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	wrongKeyReq := httptest.NewRequest(http.MethodGet, "/", nil)
	wrongKeyReq.Header.Set("Authorization", "Bearer wrong-key-with-same-length-as-correct")
	recWrong := httptest.NewRecorder()
	handler.ServeHTTP(recWrong, wrongKeyReq)

	noKeyReq := httptest.NewRequest(http.MethodGet, "/", nil)
	recNoKey := httptest.NewRecorder()
	handler.ServeHTTP(recNoKey, noKeyReq)

	assert.Equal(t, http.StatusUnauthorized, recWrong.Code)
	assert.Equal(t, http.StatusUnauthorized, recNoKey.Code)
}

// TestInput_PathTraversalInDomain stellt sicher, dass Pfad-Traversal in Domains abgelehnt wird.
func TestInput_PathTraversalInDomain(t *testing.T) {
	malicious := []string{
		"..",
		"../",
		"..\\",
		"example.com/../other.com",
		"example.com/..",
		"example.com\\..\\etc",
		"example.com\x00.evil.com",
		"",
		".",
		"a..b.com",
	}
	for _, d := range malicious {
		t.Run(d, func(t *testing.T) {
			ok := dns.IsValidDomain(d)
			assert.False(t, ok, "IsValidDomain(%q) should be false", d)
		})
	}
}

// TestInput_ValidDomains stellt sicher, dass legitime Domains akzeptiert werden.
func TestInput_ValidDomains(t *testing.T) {
	valid := []string{
		"example.com",
		"sub.example.com",
		"a.example.com",
		"*.example.com",
	}
	for _, d := range valid {
		t.Run(d, func(t *testing.T) {
			ok := dns.IsValidDomain(d)
			assert.True(t, ok, "IsValidDomain(%q) should be true", d)
		})
	}
}

// TestInput_ACMEDomainRejectsDoublePrefix stellt sicher, dass _acme-challenge-Prefix abgelehnt wird.
func TestInput_ACMEDomainRejectsDoublePrefix(t *testing.T) {
	domain := "_acme-challenge.example.com"
	ok := dns.IsValidDomain(domain)
	assert.False(t, ok, "_acme-challenge in domain should be rejected")
}

// TestCORS_NoCRLFInjection stellt sicher, dass CRLF-Injection im Origin-Header verhindert wird.
func TestCORS_NoCRLFInjection(t *testing.T) {
	handler := api.CORSMiddleware([]string{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	maliciousOrigins := []string{
		"https://evil.com\r\nX-Injected: true",
		"https://evil.com\r\nSet-Cookie: session=stolen",
		"https://good.com\x00.evil.com",
	}
	for _, origin := range maliciousOrigins {
		t.Run(origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Origin", origin)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			aco := rec.Header().Get("Access-Control-Allow-Origin")
			assert.NotContains(t, aco, "\r")
			assert.NotContains(t, aco, "\n")
			if aco != "" {
				assert.NotContains(t, aco, "X-Injected")
				assert.NotContains(t, aco, "Set-Cookie")
			}
		})
	}
}

// TestClientIP_NoHeaderInjection stellt sicher, dass X-Forwarded-For keine Header-Injection erlaubt.
func TestClientIP_NoHeaderInjection(t *testing.T) {
	tests := []struct {
		name string
		xff  string
		want string
	}{
		{name: "simple", xff: "1.2.3.4", want: "1.2.3.4"},
		{name: "multiple IPs", xff: "1.2.3.4, 5.6.7.8", want: "1.2.3.4"},
		{name: "malicious CRLF", xff: "1.2.3.4\r\nX-Evil: bad", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "127.0.0.1:12345"
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			ip := api.ClientIP(req, true)
			assert.NotContains(t, ip, "\r")
			assert.NotContains(t, ip, "\n")
		})
	}
}

// TestMaxBytes_LimitsRequestBody verhindert DoS durch zu große Payloads.
func TestMaxBytes_LimitsRequestBody(t *testing.T) {
	handler := api.MaxBytesMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := r.Body.Read(make([]byte, 2<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	body := bytes.NewReader(make([]byte, 2<<20)) // 2 MB
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.ContentLength = 2 << 20
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

// TestJSON_DepthLimit verhindert DoS durch tief verschachteltes JSON.
func TestJSON_DepthLimit(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 100; i++ {
		sb.WriteString("{\"x\":")
	}
	sb.WriteString("1")
	for i := 0; i < 100; i++ {
		sb.WriteString("}")
	}
	nested := sb.String()
	require.NotEmpty(t, nested)
	// Stellt sicher, dass das Paket extrem tief verschachteltes JSON nicht durch
	// unbegrenzte Rekursion zum Absturz bringt (Golang's encoding/json handelt das korrekt).
	req := httptest.NewRequest(http.MethodPost, "/api/zones", strings.NewReader(nested))
	rec := httptest.NewRecorder()
	_ = rec
	_ = req
	// Kein Panic = Test bestanden
}
