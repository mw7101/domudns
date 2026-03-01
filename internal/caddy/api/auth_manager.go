package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/mw7101/domudns/internal/store"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 12

// AuthManager holds the auth configuration in memory and synchronizes with the database.
// It is goroutine-safe and uses RWMutex for read-heavy access.
type AuthManager struct {
	mu    sync.RWMutex
	store store.AuthStore
	cfg   *store.AuthConfig
}

// NewAuthManager loads the auth configuration from the store.
// If no password hash is present, a hash for "admin" is generated.
func NewAuthManager(ctx context.Context, s store.AuthStore) (*AuthManager, error) {
	am := &AuthManager{store: s}
	if err := am.load(ctx); err != nil {
		return nil, fmt.Errorf("load auth config: %w", err)
	}

	// No hash present → set default credentials "admin"/"admin"
	if am.cfg.PasswordHash == "" {
		hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcryptCost)
		if err != nil {
			return nil, fmt.Errorf("generate default password hash: %w", err)
		}
		am.mu.Lock()
		am.cfg.Username = "admin"
		am.cfg.PasswordHash = string(hash)
		am.mu.Unlock()
		if err := s.UpdateAuthConfig(ctx, am.cfg); err != nil {
			log.Warn().Err(err).Msg("could not save default credentials to store")
		}
	}
	return am, nil
}

func (am *AuthManager) load(ctx context.Context) error {
	cfg, err := am.store.GetAuthConfig(ctx)
	if err != nil {
		return err
	}
	am.mu.Lock()
	am.cfg = cfg
	am.mu.Unlock()
	return nil
}

// Reload reloads the auth configuration from the database (for cluster synchronization).
func (am *AuthManager) Reload(ctx context.Context) error {
	return am.load(ctx)
}

// IsSetupCompleted returns whether the setup wizard has been completed.
func (am *AuthManager) IsSetupCompleted() bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.cfg.SetupCompleted
}

// getCurrentUsername returns the currently configured username.
func (am *AuthManager) getCurrentUsername() string {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.cfg.Username
}

// ValidatePassword checks username and password (bcrypt).
// Returns no details on failure (prevents username enumeration).
func (am *AuthManager) ValidatePassword(username, password string) bool {
	am.mu.RLock()
	cfg := am.cfg
	am.mu.RUnlock()

	// Username: constant-time comparison
	usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(cfg.Username)) == 1
	// Password: bcrypt comparison
	err := bcrypt.CompareHashAndPassword([]byte(cfg.PasswordHash), []byte(password))
	return usernameMatch && err == nil
}

// ValidateAPIKey checks the API key (constant-time, no bcrypt).
func (am *AuthManager) ValidateAPIKey(key string) bool {
	am.mu.RLock()
	apiKey := am.cfg.APIKey
	am.mu.RUnlock()

	if apiKey == "" || key == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(key), []byte(apiKey)) == 1
}

// UpdatePassword sets a new password (bcrypt hash) and persists it.
func (am *AuthManager) UpdatePassword(ctx context.Context, username, password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	am.mu.Lock()
	am.cfg.Username = username
	am.cfg.PasswordHash = string(hash)
	cfgCopy := *am.cfg
	am.mu.Unlock()

	return am.store.UpdateAuthConfig(ctx, &cfgCopy)
}

// RegenerateAPIKey creates a new API key (64 random hex characters) and persists it.
// Returns the new key (shown only once).
func (am *AuthManager) RegenerateAPIKey(ctx context.Context) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate api key: %w", err)
	}
	newKey := hex.EncodeToString(raw)

	am.mu.Lock()
	am.cfg.APIKey = newKey
	cfgCopy := *am.cfg
	am.mu.Unlock()

	if err := am.store.UpdateAuthConfig(ctx, &cfgCopy); err != nil {
		return "", err
	}
	return newKey, nil
}

// MarkSetupCompleted marks setup as completed (DB + in-memory).
func (am *AuthManager) MarkSetupCompleted(ctx context.Context) error {
	if err := am.store.MarkSetupCompleted(ctx); err != nil {
		return err
	}
	am.mu.Lock()
	am.cfg.SetupCompleted = true
	am.mu.Unlock()
	return nil
}
