package api

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

const testAPIKey = "this-is-a-valid-api-key-with-32chars!!"

func TestAuthMiddleware_SessionCookie_Valid(t *testing.T) {
	sessions := NewSessionManager(context.Background())
	token, _ := sessions.Create()
	authMgr := newTestAuthManagerWithKey(t, testAPIKey)

	h := AuthMiddleware(authMgr, sessions, okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/zones", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with valid session cookie, got %d", w.Code)
	}
}

func TestAuthMiddleware_SessionCookie_Invalid(t *testing.T) {
	sessions := NewSessionManager(context.Background())
	authMgr := newTestAuthManagerWithKey(t, testAPIKey)

	h := AuthMiddleware(authMgr, sessions, okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/zones", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "not-a-valid-token"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with invalid session cookie, got %d", w.Code)
	}
}

func TestAuthMiddleware_BearerToken_Valid(t *testing.T) {
	authMgr := newTestAuthManagerWithKey(t, testAPIKey)
	h := AuthMiddleware(authMgr, NewSessionManager(context.Background()), okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/zones", nil)
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with valid bearer token, got %d", w.Code)
	}
}

func TestAuthMiddleware_BearerToken_Invalid(t *testing.T) {
	authMgr := newTestAuthManagerWithKey(t, testAPIKey)
	h := AuthMiddleware(authMgr, NewSessionManager(context.Background()), okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/zones", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with invalid bearer token, got %d", w.Code)
	}
}

func TestAuthMiddleware_NoAuth_APIRequest_Returns401(t *testing.T) {
	authMgr := newTestAuthManagerWithKey(t, testAPIKey)
	h := AuthMiddleware(authMgr, NewSessionManager(context.Background()), okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/zones", nil)
	// No Accept: text/html → JSON 401 (no redirect)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated API request, got %d", w.Code)
	}
}

func TestAuthMiddleware_NoAuth_BrowserRequest_RedirectsToLogin(t *testing.T) {
	authMgr := newTestAuthManagerWithKey(t, testAPIKey)
	h := AuthMiddleware(authMgr, NewSessionManager(context.Background()), okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/zones", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect for browser request, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login") {
		t.Errorf("expected redirect to /login, got %q", loc)
	}
}

func TestAuthMiddleware_EmptyAPIKey_Returns401(t *testing.T) {
	// AuthManager with empty API key → ValidateAPIKey returns false
	authMgr := newTestAuthManagerWithKey(t, "")
	h := AuthMiddleware(authMgr, NewSessionManager(context.Background()), okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/zones", nil)
	req.Header.Set("Authorization", "Bearer some-key")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("empty api key: expected 401, got %d", w.Code)
	}
}

func TestAuthMiddleware_DeletedSession_Returns401(t *testing.T) {
	sessions := NewSessionManager(context.Background())
	token, _ := sessions.Create()
	sessions.Delete(token)
	authMgr := newTestAuthManagerWithKey(t, testAPIKey)

	h := AuthMiddleware(authMgr, sessions, okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/zones", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 after session deletion, got %d", w.Code)
	}
}

// bodyReadingHandler reads the full request body and returns 200 on success.
var bodyReadingHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if _, err := io.ReadAll(r.Body); err != nil {
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
		return
	}
	w.WriteHeader(http.StatusOK)
})

func TestMaxBytesMiddleware_RegularPath_RejectsOversizedBody(t *testing.T) {
	h := MaxBytesMiddleware(bodyReadingHandler)
	// Body is 1 MB + 1 byte — must be rejected.
	body := bytes.Repeat([]byte("x"), maxRequestBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/api/zones", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		t.Errorf("expected non-200 for oversized body on regular path, got %d", w.Code)
	}
}

func TestMaxBytesMiddleware_InternalPath_AllowsOversizedBody(t *testing.T) {
	h := MaxBytesMiddleware(bodyReadingHandler)
	// Body is 1.5 MB — exceeds the 1 MB cap but must pass through for /api/internal/*.
	// This simulates a cluster sync payload with 220k+ gzip+base64 encoded domains.
	body := bytes.Repeat([]byte("x"), maxRequestBodyBytes+512*1024)
	req := httptest.NewRequest(http.MethodPost, "/api/internal/sync", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for oversized body on /api/internal/ path, got %d", w.Code)
	}
}
