package store

import (
	"context"
	"time"
)

// AuthConfig contains the authentication configuration.
// Stored in the database (dns_auth_config).
type AuthConfig struct {
	Username       string    `json:"username"`
	PasswordHash   string    `json:"password_hash"`
	APIKey         string    `json:"api_key"`
	SetupCompleted bool      `json:"setup_completed"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// AuthStore defines the interface for authentication data.
type AuthStore interface {
	GetAuthConfig(ctx context.Context) (*AuthConfig, error)
	UpdateAuthConfig(ctx context.Context, cfg *AuthConfig) error
	MarkSetupCompleted(ctx context.Context) error
}
