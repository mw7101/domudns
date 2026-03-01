package blocklist

import (
	"context"
	"fmt"
)

// MergedBlocklistStore provides the merged blocklist for writing.
type MergedBlocklistStore interface {
	GetMergedBlocklist(ctx context.Context) ([]string, error)
}

// RegenerateHostsFile fetches merged blocklist from store and writes hosts file.
func RegenerateHostsFile(ctx context.Context, store MergedBlocklistStore, filePath, ip4, ip6 string) error {
	domains, err := store.GetMergedBlocklist(ctx)
	if err != nil {
		return fmt.Errorf("get merged blocklist: %w", err)
	}
	return WriteHostsFile(filePath, domains, ip4, ip6)
}
