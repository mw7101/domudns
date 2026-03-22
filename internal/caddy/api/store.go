package api

import (
	"context"

	"github.com/mw7101/domudns/internal/store"
)

// Store combines all canonical store interfaces plus HealthCheck.
// Implemented by *filestore.FileStore and *cluster.PropagatingStore.
type Store interface {
	store.ZoneStore
	store.RecordStore
	store.ACMEStore
	store.BlocklistStore
	store.AuthStore
	store.TSIGKeyStore
	store.NamedAPIKeyStore
	HealthCheck(ctx context.Context) error
}
