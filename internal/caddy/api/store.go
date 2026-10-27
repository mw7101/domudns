package api

import (
	"context"

	"github.com/mw7101/domudns/internal/store"
)

// TSIGKeyStore manages TSIG keys for RFC 2136 DDNS authentication.
type TSIGKeyStore interface {
	GetTSIGKeys(ctx context.Context) ([]store.TSIGKey, error)
	PutTSIGKey(ctx context.Context, key store.TSIGKey) error
	DeleteTSIGKey(ctx context.Context, name string) error
}

// NamedAPIKeyStore manages named API keys for external tool authentication.
type NamedAPIKeyStore interface {
	CreateNamedAPIKey(ctx context.Context, name, description string) (*store.NamedAPIKey, error)
	ListNamedAPIKeys(ctx context.Context) ([]store.NamedAPIKey, error)
	DeleteNamedAPIKey(ctx context.Context, id string) error
	ValidateNamedAPIKey(ctx context.Context, key string) bool
}

// Store combines ZoneStore, RecordStore, ACMEStore, BlocklistStore, AuthStore, TSIGKeyStore,
// NamedAPIKeyStore and HealthCheck.
// Implemented by *filestore.FileStore and *cluster.PropagatingStore.
type Store interface {
	ZoneStore
	RecordStore
	ACMEStore
	BlocklistStore
	store.AuthStore
	TSIGKeyStore
	NamedAPIKeyStore
	HealthCheck(ctx context.Context) error
}
