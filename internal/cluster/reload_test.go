package cluster

import (
	"sync/atomic"
	"testing"
	"time"
)

// mustReceive waits for a value on ch or fails the test after 2s.
func mustReceive(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for %s", what)
	}
}

// TestReloadScheduler_CoalescesConcurrentTriggers verifies that callbacks of
// the same kind never run concurrently and that multiple triggers arriving
// while a run is in progress coalesce into exactly one follow-up run.
func TestReloadScheduler_CoalescesConcurrentTriggers(t *testing.T) {
	var s reloadScheduler

	var (
		runs       atomic.Int32
		inRun      atomic.Int32
		started    = make(chan struct{}, 8)
		release    = make(chan struct{})
		overlapped atomic.Bool
	)

	cb := func() error {
		if inRun.Add(1) != 1 {
			overlapped.Store(true)
		}
		runs.Add(1)
		started <- struct{}{}
		<-release
		inRun.Add(-1)
		return nil
	}

	// First trigger starts the run.
	s.trigger(true, cb, "zone")
	mustReceive(t, started, "first run to start")

	// Triggers while the first run is blocked must coalesce.
	for i := 0; i < 5; i++ {
		s.trigger(true, cb, "zone")
	}

	// Release the first run; exactly one follow-up run must start.
	release <- struct{}{}
	mustReceive(t, started, "coalesced follow-up run to start")
	release <- struct{}{}

	waitForCondition(t, func() bool { return runs.Load() == 2 })
	// Ensure no third run sneaks in after the follow-up finishes.
	time.Sleep(50 * time.Millisecond)

	if got := runs.Load(); got != 2 {
		t.Fatalf("expected exactly 2 coalesced runs, got %d", got)
	}
	if overlapped.Load() {
		t.Fatal("same-kind callbacks overlapped")
	}
}

// TestReloadScheduler_DifferentKindsRunConcurrently verifies that different
// callback kinds are not serialized against each other.
func TestReloadScheduler_DifferentKindsRunConcurrently(t *testing.T) {
	var s reloadScheduler

	started := make(chan struct{}, 2)
	release := make(chan struct{})

	cb := func() error {
		started <- struct{}{}
		<-release
		return nil
	}

	s.trigger(true, cb, "zone")
	s.trigger(true, cb, "blocklist")

	// Both must be running before either is released.
	mustReceive(t, started, "zone run to start")
	mustReceive(t, started, "blocklist run to start")

	release <- struct{}{}
	release <- struct{}{}
}

// TestReloadCallbacks_SharedSchedulerSerializesPollAndPush verifies that a
// poll-driven and a push-driven reload of the same kind share one scheduler,
// so they never run concurrently; the second trigger coalesces into a single
// follow-up run.
func TestReloadCallbacks_SharedSchedulerSerializesPollAndPush(t *testing.T) {
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	var runs, inRun atomic.Int32
	var overlapped atomic.Bool

	cb := func() error {
		if inRun.Add(1) != 1 {
			overlapped.Store(true)
		}
		runs.Add(1)
		started <- struct{}{}
		<-release
		inRun.Add(-1)
		return nil
	}

	callbacks := ReloadCallbacks{ZoneReloader: cb}.WithSharedReloadScheduler()
	rh := &ReceiverHandler{callbacks: callbacks}

	// Push path starts a zone reload.
	rh.triggerZoneReload()
	mustReceive(t, started, "push zone reload to start")

	// Poll path triggers the same kind while it runs → coalesce, no overlap.
	callbacks.trigger(true, callbacks.ZoneReloader, "zone")

	release <- struct{}{}
	mustReceive(t, started, "coalesced follow-up run to start")
	release <- struct{}{}

	waitForCondition(t, func() bool { return runs.Load() == 2 })
	time.Sleep(50 * time.Millisecond)
	if got := runs.Load(); got != 2 {
		t.Fatalf("expected exactly 2 runs, got %d", got)
	}
	if overlapped.Load() {
		t.Fatal("poll and push reloads overlapped despite the shared scheduler")
	}
}

// TestReloadCallbacks_NoSchedulerFallsBackToGoroutine verifies the legacy
// behaviour when no shared scheduler is configured (e.g. tests).
func TestReloadCallbacks_NoSchedulerFallsBackToGoroutine(t *testing.T) {
	var runs atomic.Int32
	var callbacks ReloadCallbacks
	callbacks.trigger(true, func() error { runs.Add(1); return nil }, "zone")
	waitForCondition(t, func() bool { return runs.Load() == 1 })
}

// TestReloadScheduler_NoOpTriggers verifies that unchanged/nil callbacks do
// not start a run.
func TestReloadScheduler_NoOpTriggers(t *testing.T) {
	var s reloadScheduler

	var runs atomic.Int32
	cb := func() error { runs.Add(1); return nil }

	s.trigger(false, cb, "zone") // not changed
	s.trigger(true, nil, "zone") // nil callback

	time.Sleep(50 * time.Millisecond)
	if got := runs.Load(); got != 0 {
		t.Fatalf("expected no runs, got %d", got)
	}
}
