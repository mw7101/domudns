//go:build integration

package integration

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mw7101/domudns/internal/cluster"
	"github.com/mw7101/domudns/internal/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSecret = "test-hmac-secret-for-integration-tests"

// TestClusterSync_ZonePropagation verifies that a zone written on the master
// is pushed to and stored on the slave via the HTTP sync endpoint.
func TestClusterSync_ZonePropagation(t *testing.T) {
	ctx := context.Background()

	// Create separate FileStore instances for master and slave in temp dirs.
	masterFS := newTestStore(t)
	slaveFS := newTestStore(t)

	// Build slave HTTP server using the actual cluster handler.
	slaveReceiver := cluster.NewReceiverHandler(slaveFS, testSecret, cluster.ReloadCallbacks{})
	slaveHandler := cluster.NewHandler(slaveReceiver, slaveFS)
	slaveServer := httptest.NewServer(slaveHandler)
	defer slaveServer.Close()

	// Build master PropagatingStore pointing to the slave.
	propagator := cluster.NewPropagator(
		[]string{slaveServer.URL},
		testSecret,
		5*time.Second,
	)
	masterStore := cluster.NewPropagatingStore(masterFS, propagator)

	// Mutate a zone on the master — this triggers PushAsync to the slave.
	// Domain names must not have a trailing dot; ValidateZone uses IsValidDomain
	// which rejects empty labels produced by a trailing dot.
	zone := &dns.Zone{
		Domain: "cluster-test.example.com",
		TTL:    3600,
		Records: []dns.Record{
			{Name: "@", Type: dns.TypeA, TTL: 300, Value: "192.168.1.10"},
		},
		SOA: dns.DefaultSOA("cluster-test.example.com"),
	}
	require.NoError(t, masterStore.PutZone(ctx, zone))

	// Wait up to 2s for the zone to appear on the slave.
	var slaveZone *dns.Zone
	var err error
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		slaveZone, err = slaveFS.GetZone(ctx, "cluster-test.example.com")
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	require.NoError(t, err, "zone should have propagated to slave within 2s")
	assert.Equal(t, "cluster-test.example.com", slaveZone.Domain)
	assert.Equal(t, 3600, slaveZone.TTL)
	require.Len(t, slaveZone.Records, 1)
	assert.Equal(t, "192.168.1.10", slaveZone.Records[0].Value)
}

// TestClusterSync_HMACRejection verifies that a slave rejects sync requests
// signed with a wrong HMAC secret.
func TestClusterSync_HMACRejection(t *testing.T) {
	ctx := context.Background()

	masterFS := newTestStore(t)
	slaveFS := newTestStore(t)

	// Slave is configured with testSecret.
	slaveReceiver := cluster.NewReceiverHandler(slaveFS, testSecret, cluster.ReloadCallbacks{})
	slaveHandler := cluster.NewHandler(slaveReceiver, slaveFS)
	slaveServer := httptest.NewServer(slaveHandler)
	defer slaveServer.Close()

	// Master propagator uses a WRONG secret — slave must reject all sync requests.
	wrongPropagator := cluster.NewPropagator(
		[]string{slaveServer.URL},
		"wrong-secret-that-does-not-match",
		5*time.Second,
	)
	masterStore := cluster.NewPropagatingStore(masterFS, wrongPropagator)

	zone := &dns.Zone{
		Domain:  "rejected-zone.example.com",
		TTL:     3600,
		Records: []dns.Record{},
		SOA:     dns.DefaultSOA("rejected-zone.example.com"),
	}
	require.NoError(t, masterStore.PutZone(ctx, zone))

	// Give the async push some time to reach the slave (and be rejected).
	time.Sleep(500 * time.Millisecond)

	// The zone must NOT have been stored on the slave.
	_, err := slaveFS.GetZone(ctx, "rejected-zone.example.com")
	assert.ErrorIs(t, err, dns.ErrZoneNotFound,
		"slave must not accept zone when HMAC secret is wrong")

	// Sanity check: zone exists on master.
	_, err = masterFS.GetZone(ctx, "rejected-zone.example.com")
	require.NoError(t, err, "zone should still exist on master")

	_ = ctx
}
