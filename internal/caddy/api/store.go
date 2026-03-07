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

// Store combines ZoneStore, RecordStore, ACMEStore, BlocklistStore, AuthStore, TSIGKeyStore and HealthCheck.
// Implemented by *filestore.FileStore and *cluster.PropagatingStore.
type Store interface {
	ZoneStore
	RecordStore
	ACMEStore
	BlocklistStore
	store.AuthStore
	TSIGKeyStore
	HealthCheck(ctx context.Context) error
}
