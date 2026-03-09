package api

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

const (
	SessionCookieName      = "dns_stack_session"
	sessionTTL             = 24 * time.Hour
	sessionCleanupInterval = 15 * time.Minute
)

type sessionEntry struct {
	expiresAt time.Time
}

// SessionManager verwaltet In-Memory Browser-Sessions.
// Sessions laufen nach 24 Stunden ab und werden periodisch bereinigt.
type SessionManager struct {
	mu       sync.Mutex
	sessions map[string]sessionEntry
}

func NewSessionManager() *SessionManager {
	sm := &SessionManager{
		sessions: make(map[string]sessionEntry),
	}
	go sm.cleanupLoop()
	return sm
}

// Create erstellt eine neue Session und gibt das Token zurück.
func (sm *SessionManager) Create() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.URLEncoding.EncodeToString(b)
	sm.mu.Lock()
	sm.sessions[token] = sessionEntry{expiresAt: time.Now().Add(sessionTTL)}
	sm.mu.Unlock()
	return token, nil
}

// Valid gibt true zurück wenn das Token existiert und noch nicht abgelaufen ist.
func (sm *SessionManager) Valid(token string) bool {
	if token == "" {
		return false
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	entry, ok := sm.sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(entry.expiresAt) {
		delete(sm.sessions, token)
		return false
	}
	return true
}

// Delete löscht eine Session (Logout).
func (sm *SessionManager) Delete(token string) {
	sm.mu.Lock()
	delete(sm.sessions, token)
	sm.mu.Unlock()
}

// cleanupLoop entfernt abgelaufene Sessions periodisch.
func (sm *SessionManager) cleanupLoop() {
	ticker := time.NewTicker(sessionCleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		sm.mu.Lock()
		now := time.Now()
		for token, entry := range sm.sessions {
			if now.After(entry.expiresAt) {
				delete(sm.sessions, token)
			}
		}
		sm.mu.Unlock()
	}
}
