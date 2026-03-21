package api

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/time/rate"
)

// MaxBytesReader wraps r.Body with a limit. Prevents DoS via huge JSON payloads.
const maxRequestBodyBytes = 1 << 20 // 1 MB

// ClientIP returns the client IP from the request.
// When trustProxy is true, uses X-Real-IP or first IP in X-Forwarded-For (when behind reverse proxy).
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
			return extractIP(ip)
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// First IP is the original client
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			return extractIP(first)
		}
	}
	return extractIP(r.RemoteAddr)
}

func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		addr = strings.TrimSpace(addr)
	} else {
		addr = strings.TrimSpace(host)
	}
	return sanitizeIP(addr)
}

// sanitizeIP removes CRLF and other control chars to prevent header injection in rate-limit key.
func sanitizeIP(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r > 0 && r < 32 || r == 127 {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// MaxBytesMiddleware limits request body size for methods that accept a body.
func MaxBytesMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

const rateLimitCleanupInterval = 5 * time.Minute
const rateLimitIdleTTL = 10 * time.Minute

// rateLimitEntry holds a limiter and last-access time for eviction.
type rateLimitEntry struct {
	limiter  *rate.Limiter
	lastUsed time.Time
}

// RateLimitMiddleware returns a middleware that limits requests per IP.
// Stale entries are evicted periodically to prevent unbounded map growth.
// When trustProxy is true, client IP is taken from X-Real-IP or X-Forwarded-For.
// The cleanup goroutine stops when ctx is cancelled (e.g. server shutdown).
func RateLimitMiddleware(ctx context.Context, requestsPerMinute int, trustProxy bool, next http.Handler) http.Handler {
	if requestsPerMinute <= 0 {
		return next
	}
	limiters := make(map[string]*rateLimitEntry)
	var mu sync.Mutex

	// Periodically evict limiters not used for rateLimitIdleTTL.
	// Stops when ctx is cancelled to avoid goroutine leaks.
	go func() {
		ticker := time.NewTicker(rateLimitCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				mu.Lock()
				cutoff := time.Now().Add(-rateLimitIdleTTL)
				for ip, ent := range limiters {
					if ent.lastUsed.Before(cutoff) {
						delete(limiters, ip)
					}
				}
				mu.Unlock()
			}
		}
	}()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r, trustProxy)
		mu.Lock()
		ent, ok := limiters[ip]
		if !ok {
			ent = &rateLimitEntry{
				limiter:  rate.NewLimiter(rate.Every(time.Minute/time.Duration(requestsPerMinute)), requestsPerMinute),
				lastUsed: time.Now(),
			}
			limiters[ip] = ent
		}
		ent.lastUsed = time.Now()
		lim := ent.limiter
		mu.Unlock()
		if !lim.Allow() {
			writeError(w, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED", "Too many requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// AuthMiddleware checks whether a request is authenticated.
// Order of checks:
//  1. Session cookie (browser after login via /login)
//  2. Bearer token (programmatic access: curl, scripts)
//
// On missing/invalid auth:
//   - Browser requests (Accept: text/html) → redirect to /login
//   - API requests → JSON 401
func AuthMiddleware(auth *AuthManager, sessions *SessionManager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Check session cookie (browser)
		if cookie, err := r.Cookie(SessionCookieName); err == nil && sessions.Valid(cookie.Value) {
			next.ServeHTTP(w, r)
			return
		}

		// 2. Check bearer token (API/curl)
		if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
			key := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
			if auth.ValidateAnyKey(r.Context(), key) {
				next.ServeHTTP(w, r)
				return
			}
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
			return
		}

		// 3. Check basic auth (password = named API key, for Traefik httpreq provider)
		if _, password, ok := r.BasicAuth(); ok {
			if auth.ValidateAnyKey(r.Context(), password) {
				next.ServeHTTP(w, r)
				return
			}
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
			return
		}

		// No valid auth method → redirect browser to login page, API gets 401
		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			http.Redirect(w, r, "/login?redirect="+r.URL.RequestURI(), http.StatusSeeOther)
			return
		}
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
	})
}

// hasCRLF returns true if s contains carriage return or newline (prevents header injection).
func hasCRLF(s string) bool {
	for _, r := range s {
		if r == '\r' || r == '\n' {
			return true
		}
	}
	return false
}

// CORSMiddleware adds CORS headers for the Web UI.
// If allowedOrigins is nil or empty, "*" is used (allow all origins).
// In production, set system.cors_origins to restrict access to specific domains.
// Otherwise only origins in the list are allowed; the request's Origin is checked if present.
func CORSMiddleware(allowedOrigins []string, next http.Handler) http.Handler {
	allowAll := len(allowedOrigins) == 0
	if allowAll {
		log.Warn().Msg("CORS: no allowed origins configured, all origins permitted — set system.cors_origins in production")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if allowAll {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else if origin != "" && !hasCRLF(origin) {
			for _, o := range allowedOrigins {
				if o == origin {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					// Vary: Origin tells caches that the response depends on the Origin header
					w.Header().Add("Vary", "Origin")
					break
				}
			}
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
