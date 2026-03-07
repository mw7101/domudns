package blocklist

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
)

// FetchLoopStore provides blocklist URL operations for the fetch loop.
type FetchLoopStore interface {
	ListBlocklistURLs(ctx context.Context) ([]URLItem, error)
	UpdateBlocklistURLFetch(ctx context.Context, id int, lastError *string) error
	SetBlocklistURLDomains(ctx context.Context, urlID int, domains []string) error
	MergedBlocklistStore
}

// URLItem is a minimal view of a blocklist URL for the fetch loop.
type URLItem struct {
	ID      int
	URL     string
	Enabled bool
}

// RunFetchLoop runs a background loop that fetches enabled blocklist URLs periodically.
func RunFetchLoop(ctx context.Context, store FetchLoopStore, interval time.Duration, regen func(context.Context)) error {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	// Initial fetch after a short delay
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
		// proceed
	}
	for {
		items, err := store.ListBlocklistURLs(ctx)
		if err != nil {
			log.Warn().Err(err).Msg("blocklist: list urls for fetch")
		} else {
			for _, u := range items {
				if !u.Enabled {
					continue
				}
				domains, fetchErr := FetchURL(ctx, u.URL)
				if fetchErr != nil {
					errStr := fetchErr.Error()
					_ = store.UpdateBlocklistURLFetch(ctx, u.ID, &errStr)
					log.Warn().Err(fetchErr).Str("url", u.URL).Msg("blocklist: fetch failed")
					continue
				}
				_ = store.UpdateBlocklistURLFetch(ctx, u.ID, nil)
				if err := store.SetBlocklistURLDomains(ctx, u.ID, domains); err != nil {
					log.Warn().Err(err).Str("url", u.URL).Msg("blocklist: set domains failed")
					continue
				}
			}
			regen(ctx)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// next iteration
		}
	}
}
