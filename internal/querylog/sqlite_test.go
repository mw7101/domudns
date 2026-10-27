package querylog

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func tempDB(t *testing.T) (*SQLiteStore, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "querylog-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	store, err := NewSQLiteStore(f.Name(), "", 7)
	if err != nil {
		os.Remove(f.Name())
		t.Fatal(err)
	}
	return store, func() {
		store.db.Close()
		os.Remove(f.Name())
		os.Remove(f.Name() + "-wal")
		os.Remove(f.Name() + "-shm")
	}
}

func makeEntryAt(domain, result string, blocked bool, ts time.Time) QueryLogEntry {
	return QueryLogEntry{
		Timestamp: ts,
		NodeID:    "test-node",
		ClientIP:  "192.168.1.1",
		Domain:    domain,
		QType:     "A",
		Result:    result,
		Latency:   1000,
		Blocked:   blocked,
		RCODE:     0,
	}
}

func TestSQLiteStore_WriteBatchAndQuery(t *testing.T) {
	store, cleanup := tempDB(t)
	defer cleanup()

	entries := []QueryLogEntry{
		makeEntryAt("a.com", ResultForwarded, false, time.Now().Add(-2*time.Minute)),
		makeEntryAt("b.com", ResultBlocked, true, time.Now().Add(-1*time.Minute)),
		makeEntryAt("c.com", ResultCached, false, time.Now()),
	}
	if err := store.writeBatch(entries); err != nil {
		t.Fatalf("writeBatch fehlgeschlagen: %v", err)
	}

	page, err := store.Query(context.Background(), QueryLogFilter{Limit: 100})
	if err != nil {
		t.Fatalf("Query fehlgeschlagen: %v", err)
	}
	if page.Total != 3 {
		t.Errorf("erwartet 3 Einträge, got %d", page.Total)
	}
	// Neueste zuerst
	if page.Entries[0].Domain != "c.com" {
		t.Errorf("erwartet c.com als neuesten Eintrag, got %s", page.Entries[0].Domain)
	}
}

func TestSQLiteStore_FilterByResult(t *testing.T) {
	store, cleanup := tempDB(t)
	defer cleanup()

	entries := []QueryLogEntry{
		makeEntryAt("ads.com", ResultBlocked, true, time.Now()),
		makeEntryAt("ok.com", ResultForwarded, false, time.Now()),
	}
	_ = store.writeBatch(entries)

	page, err := store.Query(context.Background(), QueryLogFilter{Result: ResultBlocked, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 {
		t.Errorf("erwartet 1 blockierten Eintrag, got %d", page.Total)
	}
	if page.Entries[0].Domain != "ads.com" {
		t.Errorf("erwartet ads.com, got %s", page.Entries[0].Domain)
	}
}

func TestSQLiteStore_FilterByDomain(t *testing.T) {
	store, cleanup := tempDB(t)
	defer cleanup()

	entries := []QueryLogEntry{
		makeEntryAt("ads.example.com", ResultBlocked, true, time.Now()),
		makeEntryAt("www.example.com", ResultForwarded, false, time.Now()),
		makeEntryAt("google.com", ResultForwarded, false, time.Now()),
	}
	_ = store.writeBatch(entries)

	page, err := store.Query(context.Background(), QueryLogFilter{Domain: "example.com", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 {
		t.Errorf("erwartet 2 Einträge mit 'example.com', got %d", page.Total)
	}
}

func TestSQLiteStore_FilterByTimeRange(t *testing.T) {
	store, cleanup := tempDB(t)
	defer cleanup()

	now := time.Now()
	entries := []QueryLogEntry{
		makeEntryAt("old.com", ResultForwarded, false, now.Add(-2*time.Hour)),
		makeEntryAt("recent.com", ResultForwarded, false, now.Add(-30*time.Minute)),
		makeEntryAt("newest.com", ResultForwarded, false, now),
	}
	_ = store.writeBatch(entries)

	since := now.Add(-1 * time.Hour)
	page, err := store.Query(context.Background(), QueryLogFilter{Since: since, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 {
		t.Errorf("erwartet 2 Einträge nach since, got %d", page.Total)
	}
}

func TestSQLiteStore_Pagination(t *testing.T) {
	store, cleanup := tempDB(t)
	defer cleanup()

	entries := make([]QueryLogEntry, 20)
	for i := range entries {
		entries[i] = makeEntryAt(fmt.Sprintf("domain%02d.com", i), ResultForwarded, false, time.Now().Add(time.Duration(i)*time.Second))
	}
	_ = store.writeBatch(entries)

	page1, _ := store.Query(context.Background(), QueryLogFilter{Limit: 10, Offset: 0})
	if len(page1.Entries) != 10 {
		t.Errorf("erwartet 10 Einträge Seite 1, got %d", len(page1.Entries))
	}
	if !page1.HasMore {
		t.Error("erwartet HasMore=true auf Seite 1")
	}

	page2, _ := store.Query(context.Background(), QueryLogFilter{Limit: 10, Offset: 10})
	if len(page2.Entries) != 10 {
		t.Errorf("erwartet 10 Einträge Seite 2, got %d", len(page2.Entries))
	}
	if page2.HasMore {
		t.Error("erwartet HasMore=false auf letzter Seite")
	}
}

func TestSQLiteStore_Cleanup(t *testing.T) {
	store, cleanup := tempDB(t)
	defer cleanup()
	store.persistDays = 1 // nur 1 Tag Retention

	now := time.Now()
	entries := []QueryLogEntry{
		makeEntryAt("old.com", ResultForwarded, false, now.Add(-48*time.Hour)), // zu alt
		makeEntryAt("ok.com", ResultForwarded, false, now.Add(-12*time.Hour)),  // noch frisch
	}
	_ = store.writeBatch(entries)

	store.runCleanup()

	page, _ := store.Query(context.Background(), QueryLogFilter{Limit: 100})
	if page.Total != 1 {
		t.Errorf("erwartet 1 Eintrag nach Cleanup, got %d", page.Total)
	}
	if page.Entries[0].Domain != "ok.com" {
		t.Errorf("erwartet ok.com nach Cleanup, got %s", page.Entries[0].Domain)
	}
}

func TestSQLiteStore_BatchViaChannel(t *testing.T) {
	store, cleanup := tempDB(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		store.Run(ctx)
	}()

	// Einträge via Add() senden
	for i := 0; i < 5; i++ {
		store.Add(makeEntryAt(fmt.Sprintf("d%d.com", i), ResultForwarded, false, time.Now()))
	}

	// Batch-Ticker feuern lassen (kurz warten), dann Shutdown
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	// Nach Run()-Ende ist DB noch offen (Close wird von Logger aufgerufen, nicht von Run)
	// Direkt auf Store zugreifen um Einträge zu prüfen
	page, err := store.Query(context.Background(), QueryLogFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 5 {
		t.Errorf("erwartet 5 Einträge nach Shutdown-Flush, got %d", page.Total)
	}
}

func TestSQLiteStore_WALMode(t *testing.T) {
	store, cleanup := tempDB(t)
	defer cleanup()

	var mode string
	if err := store.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Errorf("erwartet WAL-Mode, got %s", mode)
	}
}
