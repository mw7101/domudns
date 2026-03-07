package querylog

import (
	"context"
	"sync"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{
		Enabled:       true,
		MemoryEntries: 100,
		PushInterval:  30 * time.Second,
	}
}

func TestNew_Disabled(t *testing.T) {
	cfg := Config{Enabled: false}
	q := New(cfg, "node1")
	if q != nil {
		t.Error("expected nil when Enabled=false")
	}
}

func TestNew_Enabled(t *testing.T) {
	q := New(testConfig(), "192.0.2.1")
	if q == nil {
		t.Fatal("expected non-nil QueryLogger")
	}
	if q.ring == nil {
		t.Error("ring buffer must not be nil")
	}
}

func TestQueryLogger_NilSafe(t *testing.T) {
	var q *QueryLogger
	// All methods must be nil-safe
	q.Log(QueryLogEntry{})
	q.LogQuery("1.1.1.1", "example.com", "A", ResultForwarded, "", time.Millisecond, 0)
	page := q.Query(QueryLogFilter{})
	if len(page.Entries) != 0 {
		t.Error("nil logger should return empty page")
	}
	stats := q.Stats()
	if stats.TotalQueries != 0 {
		t.Error("nil logger should return 0 queries")
	}
	if q.Len() != 0 {
		t.Error("nil logger should return Len=0")
	}
}

func TestQueryLogger_LogAndQuery(t *testing.T) {
	q := New(testConfig(), "192.0.2.1")

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		q.Run(ctx)
	}()

	q.LogQuery("192.168.1.10", "example.com", "A", ResultForwarded, "1.1.1.1", 2*time.Millisecond, 0)
	q.LogQuery("192.168.1.20", "ads.bad.com", "A", ResultBlocked, "", 0, 0)
	q.LogQuery("192.168.1.10", "google.com", "AAAA", ResultCached, "", 0, 0)

	// Wait briefly until background goroutine has processed the entries
	time.Sleep(20 * time.Millisecond)

	page := q.Query(QueryLogFilter{Limit: 100})
	if page.Total != 3 {
		t.Errorf("expected 3 entries, got %d", page.Total)
	}

	cancel()
	wg.Wait()
}

func TestQueryLogger_NodeIDInjection(t *testing.T) {
	q := New(testConfig(), "192.0.2.1")

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		q.Run(ctx)
	}()

	q.Log(QueryLogEntry{Domain: "example.com", QType: "A"})
	time.Sleep(20 * time.Millisecond)

	page := q.Query(QueryLogFilter{Limit: 10})
	if page.Total != 1 {
		t.Fatalf("expected 1 entry, got %d", page.Total)
	}
	if page.Entries[0].NodeID != "192.0.2.1" {
		t.Errorf("expected NodeID '192.0.2.1', got '%s'", page.Entries[0].NodeID)
	}

	cancel()
	wg.Wait()
}

func TestQueryLogger_ChannelFullDrop(t *testing.T) {
	cfg := testConfig()
	q := New(cfg, "node1")
	// Do NOT start Run() → channel is not drained
	// Channel buffer is 512 — send 600 entries, rest is dropped
	for i := 0; i < 600; i++ {
		q.Log(QueryLogEntry{Domain: "test.com"})
	}
	// No panic, no deadlock → test passed
}

func TestQueryLogger_PushFunc(t *testing.T) {
	cfg := testConfig()
	cfg.PushInterval = 10 * time.Millisecond
	q := New(cfg, "slave-node")

	var mu sync.Mutex
	var received []QueryLogEntry

	q.SetPushFunc(func(entries []QueryLogEntry) error {
		mu.Lock()
		defer mu.Unlock()
		received = append(received, entries...)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		q.Run(ctx)
	}()

	q.LogQuery("10.0.0.1", "example.com", "A", ResultForwarded, "8.8.8.8", time.Millisecond, 0)
	time.Sleep(20 * time.Millisecond) // let entry be written to ring buffer

	// Wait until push is triggered
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	count := len(received)
	mu.Unlock()

	if count == 0 {
		t.Error("expected at least 1 entry from push")
	}

	cancel()
	wg.Wait()
}

func TestQueryLogger_AddEntries(t *testing.T) {
	q := New(testConfig(), "master")
	entries := []QueryLogEntry{
		{Domain: "a.com", QType: "A", Result: ResultForwarded},
		{Domain: "b.com", QType: "AAAA", Result: ResultBlocked, Blocked: true},
	}
	q.AddEntries(entries)

	if q.Len() != 2 {
		t.Errorf("expected 2 entries after AddEntries, got %d", q.Len())
	}
}
