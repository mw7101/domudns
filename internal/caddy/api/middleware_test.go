package api

import (
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
	sessions := NewSessionManager()
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
	sessions := NewSessionManager()
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
	h := AuthMiddleware(authMgr, NewSessionManager(), okHandler)
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
	h := AuthMiddleware(authMgr, NewSessionManager(), okHandler)
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
	h := AuthMiddleware(authMgr, NewSessionManager(), okHandler)
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
	h := AuthMiddleware(authMgr, NewSessionManager(), okHandler)
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
	h := AuthMiddleware(authMgr, NewSessionManager(), okHandler)
	req := httptest.NewRequest(http.MethodGet, "/api/zones", nil)
	req.Header.Set("Authorization", "Bearer some-key")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("empty api key: expected 401, got %d", w.Code)
	}
}

func TestAuthMiddleware_DeletedSession_Returns401(t *testing.T) {
	sessions := NewSessionManager()
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
