package cluster

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mw7101/domudns/internal/filestore"
	"github.com/stretchr/testify/require"
)

// newURLDomainsMaster starts an httptest master exposing the cluster handler
// (state + url-domains pull endpoint) backed by a fresh FileStore.
func newURLDomainsMaster(t *testing.T, secret string) (*httptest.Server, *filestore.FileStore) {
	t.Helper()
	fs, err := filestore.NewFileStore(t.TempDir())
	require.NoError(t, err)
	h := NewHandler(NewReceiverHandler(fs, secret, ReloadCallbacks{}), fs)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, fs
}

func TestServeState_PollsRequireHMAC(t *testing.T) {
	srv, fs := newURLDomainsMaster(t, "secret")
	ctx := context.Background()
	require.NoError(t, fs.SetBlocklistURLDomains(ctx, 1, []string{"ads.com"}))

	client := srv.Client()

	// No auth headers -> unauthorized.
	resp, err := client.Get(srv.URL + "/api/internal/state")
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	_ = resp.Body.Close()

	// Valid HMAC -> 200 OK.
	ts := time.Now().UnixNano()
	nonce, err := newNonce()
	require.NoError(t, err)
	sig := computeHMAC("secret", statePullEvent, ts, nonce, []byte("state"))
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/internal/state", nil)
	require.NoError(t, err)
	req.Header.Set("X-Sync-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Sync-Nonce", nonce)
	req.Header.Set("X-Sync-HMAC", sig)
	resp, err = client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// Replay same nonce -> unauthorized.
	req, err = http.NewRequest(http.MethodGet, srv.URL+"/api/internal/state", nil)
	require.NoError(t, err)
	req.Header.Set("X-Sync-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Sync-Nonce", nonce)
	req.Header.Set("X-Sync-HMAC", sig)
	resp, err = client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestServeURLDomains_PullEndpointAndAuth(t *testing.T) {
	srv, fs := newURLDomainsMaster(t, "secret")
	ctx := context.Background()
	require.NoError(t, fs.SetBlocklistURLDomains(ctx, 3, []string{"ads.com", "track.com"}))

	client := srv.Client()

	// No auth headers -> unauthorized.
	resp, err := client.Get(srv.URL + "/api/internal/url-domains/3")
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	_ = resp.Body.Close()

	// Valid HMAC -> gzip payload.
	ts := time.Now().UnixNano()
	nonce, err := newNonce()
	require.NoError(t, err)
	sig := computeHMAC("secret", pullURLDomainsEvent, ts, nonce, []byte("3"))
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/internal/url-domains/3", nil)
	require.NoError(t, err)
	req.Header.Set("X-Sync-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Sync-Nonce", nonce)
	req.Header.Set("X-Sync-HMAC", sig)
	resp, err = client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "application/gzip", resp.Header.Get("Content-Type"))
	gz, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.NotEmpty(t, gz)

	// Same nonce replayed -> unauthorized (replay protection).
	req, err = http.NewRequest(http.MethodGet, srv.URL+"/api/internal/url-domains/3", nil)
	require.NoError(t, err)
	req.Header.Set("X-Sync-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Sync-Nonce", nonce)
	req.Header.Set("X-Sync-HMAC", sig)
	resp, err = client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	_ = resp.Body.Close()
}

func TestRunPollLoopWithHMAC(t *testing.T) {
	// This test verifies the slave poll uses HMAC for /api/internal/state.
	srv, masterFS := newURLDomainsMaster(t, "secret")
	ctx := context.Background()
	require.NoError(t, masterFS.SetBlocklistURLDomains(ctx, 1, []string{"ads.com"}))

	slaveFS, err := filestore.NewFileStore(t.TempDir())
	require.NoError(t, err)

	var updates atomic.Int32
	callbacks := ReloadCallbacks{
		BlocklistURLDomainsUpdater: func(int, string, []string) { updates.Add(1) },
	}

	client := &http.Client{Timeout: 5 * time.Second}
	// Run a single poll (mock ticker).
	var ps pollState
	err = pollMaster(ctx, client, srv.URL, "secret", slaveFS, callbacks, &ps)
	require.NoError(t, err)

	// Slave should have pulled the URL domains.
	meta, err := slaveFS.ListURLDomainsMeta()
	require.NoError(t, err)
	require.Len(t, meta, 1)
}

func TestSyncURLDomains_PullsOnlyStaleSets(t *testing.T) {
	srv, masterFS := newURLDomainsMaster(t, "secret")
	ctx := context.Background()
	require.NoError(t, masterFS.SetBlocklistURLDomains(ctx, 5, []string{"ads.com", "track.com"}))

	slaveFS, err := filestore.NewFileStore(t.TempDir())
	require.NoError(t, err)

	var updates atomic.Int32
	callbacks := ReloadCallbacks{
		BlocklistURLDomainsUpdater: func(urlID int, category string, domains []string) {
			updates.Add(1)
		},
	}

	masterMeta, err := masterFS.ListURLDomainsMeta()
	require.NoError(t, err)
	require.Len(t, masterMeta, 1)
	raw, err := json.Marshal(masterMeta)
	require.NoError(t, err)

	client := &http.Client{Timeout: 5 * time.Second}

	// First poll: slave has no local file -> pull.
	syncURLDomains(ctx, client, srv.URL, "secret", slaveFS, callbacks, raw)
	require.Equal(t, int32(1), updates.Load())

	slaveMeta, err := slaveFS.ListURLDomainsMeta()
	require.NoError(t, err)
	require.Len(t, slaveMeta, 1)
	require.Equal(t, masterMeta[0].SHA256, slaveMeta[0].SHA256, "pulled set must match master checksum")

	// Second poll: nothing stale -> no extra pull.
	syncURLDomains(ctx, client, srv.URL, "secret", slaveFS, callbacks, raw)
	require.Equal(t, int32(1), updates.Load())

	// Master changes the set -> slave pulls again.
	require.NoError(t, masterFS.SetBlocklistURLDomains(ctx, 5, []string{"ads.com"}))
	changedMeta, err := masterFS.ListURLDomainsMeta()
	require.NoError(t, err)
	changedRaw, err := json.Marshal(changedMeta)
	require.NoError(t, err)
	syncURLDomains(ctx, client, srv.URL, "secret", slaveFS, callbacks, changedRaw)
	require.Equal(t, int32(2), updates.Load())
}

func TestSyncURLDomains_WrongSecretDoesNotPull(t *testing.T) {
	srv, masterFS := newURLDomainsMaster(t, "secret")
	ctx := context.Background()
	require.NoError(t, masterFS.SetBlocklistURLDomains(ctx, 5, []string{"ads.com"}))

	slaveFS, err := filestore.NewFileStore(t.TempDir())
	require.NoError(t, err)

	var updates atomic.Int32
	callbacks := ReloadCallbacks{
		BlocklistURLDomainsUpdater: func(int, string, []string) { updates.Add(1) },
	}
	meta, err := masterFS.ListURLDomainsMeta()
	require.NoError(t, err)
	raw, err := json.Marshal(meta)
	require.NoError(t, err)

	client := &http.Client{Timeout: 5 * time.Second}
	syncURLDomains(ctx, client, srv.URL, "wrong-secret", slaveFS, callbacks, raw)

	require.Zero(t, updates.Load())
	local, err := slaveFS.ListURLDomainsMeta()
	require.NoError(t, err)
	require.Empty(t, local)
}

func TestPullURLDomainsChecksumMismatchDoesNotWrite(t *testing.T) {
	srv, masterFS := newURLDomainsMaster(t, "secret")
	ctx := context.Background()
	require.NoError(t, masterFS.SetBlocklistURLDomains(ctx, 5, []string{"ads.com"}))

	slaveFS, err := filestore.NewFileStore(t.TempDir())
	require.NoError(t, err)

	client := &http.Client{Timeout: 5 * time.Second}
	wrong := "0000000000000000000000000000000000000000000000000000000000000000"
	err = pullURLDomains(ctx, client, srv.URL, "secret", slaveFS, ReloadCallbacks{}, 5, wrong)
	require.Error(t, err)

	local, err := slaveFS.ListURLDomainsMeta()
	require.NoError(t, err)
	require.Empty(t, local, "a payload whose checksum does not match must not be persisted")
}

func TestBuildStateIncludesURLDomainsMeta(t *testing.T) {
	_, fs := newURLDomainsMaster(t, "secret")
	ctx := context.Background()
	require.NoError(t, fs.SetBlocklistURLDomains(ctx, 11, []string{"x.com"}))

	h := NewHandler(NewReceiverHandler(fs, "secret", ReloadCallbacks{}), fs)
	state, err := h.buildState(ctx)
	require.NoError(t, err)
	require.True(t, sectionPresent(state.URLDomainsMeta))

	var meta []filestore.URLDomainMeta
	require.NoError(t, json.Unmarshal(state.URLDomainsMeta, &meta))
	require.Len(t, meta, 1)
	require.Equal(t, 11, meta[0].URLID)
}
