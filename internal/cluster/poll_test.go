package cluster

import (
	"context"
	"encoding/json"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mw7101/domudns/internal/dns"
	"github.com/mw7101/domudns/internal/filestore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newPollTestStore mirrors cluster_test.go's newTestStore, duplicated here
// (package cluster, not cluster_test) so applyMasterState — unexported — is
// reachable directly.
func newPollTestStore(t *testing.T) *filestore.FileStore {
	t.Helper()
	dir, err := os.MkdirTemp("", "poll-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	fs, err := filestore.NewFileStore(dir)
	require.NoError(t, err)
	return fs
}

func rawJSON(t *testing.T, v interface{}) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	return data
}

// TestApplyMasterState_AppliesSectionsAndTriggersCallbacksOnce verifies that
// a full master state is applied to the local store and that reload
// callbacks fire exactly once — not again on a second, identical poll
// (SHA256 checksum gating in pollState).
func TestApplyMasterState_AppliesSectionsAndTriggersCallbacksOnce(t *testing.T) {
	fs := newPollTestStore(t)
	ctx := context.Background()

	zone := &dns.Zone{Domain: "example.com", TTL: 3600, Records: []dns.Record{}}
	state := MasterStateResponse{
		Zones:          rawJSON(t, []*dns.Zone{zone}),
		AllowedDomains: rawJSON(t, []string{"allowed.example.com"}),
	}

	var zoneReloads, blocklistReloads atomic.Int32
	callbacks := ReloadCallbacks{
		ZoneReloader:      func() error { zoneReloads.Add(1); return nil },
		BlocklistReloader: func() error { blocklistReloads.Add(1); return nil },
	}

	var ps pollState
	require.NoError(t, applyMasterState(ctx, fs, state, callbacks, &ps))

	// Reload callbacks run in a goroutine; wait for both.
	waitForCondition(t, func() bool { return zoneReloads.Load() == 1 && blocklistReloads.Load() == 1 })

	got, err := fs.GetZone(ctx, "example.com")
	require.NoError(t, err)
	assert.Equal(t, "example.com", got.Domain)

	allowed, err := fs.ListAllowedDomains(ctx)
	require.NoError(t, err)
	assert.Contains(t, allowed, "allowed.example.com")

	// Second poll with the byte-identical state must not fire callbacks
	// again — this is the whole point of pollState's checksum gating.
	require.NoError(t, applyMasterState(ctx, fs, state, callbacks, &ps))
	time.Sleep(20 * time.Millisecond) // let any (unwanted) goroutine run
	assert.Equal(t, int32(1), zoneReloads.Load())
	assert.Equal(t, int32(1), blocklistReloads.Load())
}

// TestApplyMasterState_IgnoresAbsentAndNullSections verifies that omitted
// (zero-length) and explicit JSON-null sections are skipped without error
// and without triggering any reload.
func TestApplyMasterState_IgnoresAbsentAndNullSections(t *testing.T) {
	fs := newPollTestStore(t)
	ctx := context.Background()

	state := MasterStateResponse{
		TSIGKeys: json.RawMessage("null"),
		// Zones, AllowedDomains, ... left as nil (zero-length) on purpose.
	}

	var reloads atomic.Int32
	callbacks := ReloadCallbacks{
		DDNSKeyReloader: func() error { reloads.Add(1); return nil },
	}

	var ps pollState
	require.NoError(t, applyMasterState(ctx, fs, state, callbacks, &ps))
	time.Sleep(20 * time.Millisecond) // let any (unwanted) goroutine run
	assert.Equal(t, int32(0), reloads.Load())
}

// waitForCondition polls cond until it's true or a 2s deadline passes.
// Reload callbacks in applyMasterState run in a goroutine, so tests can't
// observe them synchronously.
func waitForCondition(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timeout waiting for reload callbacks")
}
