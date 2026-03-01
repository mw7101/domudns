package blocklist

import (
	"context"

	"github.com/mw7101/domudns/internal/store"
)

// FetchStoreBackend is the backend interface for FileFetchAdapter.
// Implemented by *filestore.FileStore and *cluster.PropagatingStore.
// PropagatingStore must be used here so that domains are automatically
// propagated to all slave nodes after fetching (via EventURLDomains).
type FetchStoreBackend interface {
	ListBlocklistURLs(ctx context.Context) ([]store.BlocklistURL, error)
	UpdateBlocklistURLFetch(ctx context.Context, id int, lastError *string) error
	SetBlocklistURLDomains(ctx context.Context, urlID int, domains []string) error
	GetMergedBlocklist(ctx context.Context) ([]string, error)
}

// FileFetchAdapter adapts FetchStoreBackend to FetchLoopStore.
// On the master, the store must be the PropagatingStore so that SetBlocklistURLDomains
// automatically pushes domains to slaves.
type FileFetchAdapter struct {
	Store FetchStoreBackend
}

// ListBlocklistURLs converts []store.BlocklistURL → []URLItem.
func (a *FileFetchAdapter) ListBlocklistURLs(ctx context.Context) ([]URLItem, error) {
	urls, err := a.Store.ListBlocklistURLs(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]URLItem, len(urls))
	for i, u := range urls {
		items[i] = URLItem{ID: u.ID, URL: u.URL, Enabled: u.Enabled}
	}
	return items, nil
}

// UpdateBlocklistURLFetch delegates to the backend.
func (a *FileFetchAdapter) UpdateBlocklistURLFetch(ctx context.Context, id int, lastError *string) error {
	return a.Store.UpdateBlocklistURLFetch(ctx, id, lastError)
}

// SetBlocklistURLDomains delegates to the backend.
// On the master (PropagatingStore), domains are automatically pushed to slaves.
func (a *FileFetchAdapter) SetBlocklistURLDomains(ctx context.Context, urlID int, domains []string) error {
	return a.Store.SetBlocklistURLDomains(ctx, urlID, domains)
}

// GetMergedBlocklist delegates to the backend.
func (a *FileFetchAdapter) GetMergedBlocklist(ctx context.Context) ([]string, error) {
	return a.Store.GetMergedBlocklist(ctx)
}
