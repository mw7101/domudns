package filestore_test

import (
	"context"
	"sync"
	"testing"

	"github.com/mw7101/domudns/internal/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFileStore_UpdateZone_ConcurrentNoLostUpdate is the regression test for
// the TOCTOU/lost-update finding: a GetZone (short RLock) followed by a
// separately-locked PutZone leaves the caller's business logic unprotected
// in between, so a concurrent second writer can commit in that window and
// be silently overwritten by the first writer's later PutZone.
//
// UpdateZone closes that window by holding a single write lock across load,
// mutate, and save. This test fires two concurrent UpdateZone calls against
// the same zone, each adding a distinct record, and asserts that both
// records survive — proof that neither call's result was lost.
func TestFileStore_UpdateZone_ConcurrentNoLostUpdate(t *testing.T) {
	ctx := context.Background()
	fs, _ := newTestStore(t)

	zone := &dns.Zone{
		Domain:  "concurrent.local",
		TTL:     3600,
		Records: []dns.Record{},
		SOA:     &dns.SOA{Serial: 2020010100},
	}
	require.NoError(t, fs.PutZone(ctx, zone))

	const goroutines = 20
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			err := fs.UpdateZone(ctx, "concurrent.local", "", func(z *dns.Zone) error {
				z.Records = append(z.Records, dns.Record{
					ID:    z.NextRecordID(),
					Name:  "from-goroutine",
					Type:  dns.TypeTXT,
					TTL:   300,
					Value: recordValueFor(n),
				})
				z.SOA.IncrementSerial()
				return nil
			})
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}

	got, err := fs.GetZone(ctx, "concurrent.local")
	require.NoError(t, err)

	// Every goroutine's record must be present — a lost update would show up
	// as fewer than `goroutines` records (a later writer's save overwrote an
	// earlier writer's in-memory copy that never saw the earlier write).
	assert.Len(t, got.Records, goroutines, "expected one record per goroutine, some updates were lost")

	seen := make(map[string]bool, goroutines)
	for _, r := range got.Records {
		seen[r.Value] = true
	}
	for i := 0; i < goroutines; i++ {
		assert.Truef(t, seen[recordValueFor(i)], "record from goroutine %d missing (lost update)", i)
	}

	// IDs must also be unique — NextRecordID() must have seen every prior
	// write, which only holds if the lock spans the whole read-modify-write.
	ids := make(map[int]bool, goroutines)
	for _, r := range got.Records {
		assert.False(t, ids[r.ID], "duplicate record ID %d (concurrent NextRecordID saw stale data)", r.ID)
		ids[r.ID] = true
	}

	// The SOA serial must reflect all `goroutines` increments (RFC 1982
	// wraparound is not a concern at this scale), a second confirmation the
	// writes were properly serialized rather than lost.
	assert.GreaterOrEqual(t, got.SOA.Serial, uint32(2020010100)+uint32(goroutines))
}

func recordValueFor(n int) string {
	return "goroutine-value-" + string(rune('A'+n))
}
