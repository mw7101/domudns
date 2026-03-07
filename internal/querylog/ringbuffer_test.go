package querylog

import (
	"fmt"
	"testing"
	"time"
)

func makeEntry(domain, client, result string, blocked bool) QueryLogEntry {
	return QueryLogEntry{
		Timestamp: time.Now(),
		NodeID:    "192.0.2.1",
		ClientIP:  client,
		Domain:    domain,
		QType:     "A",
		Result:    result,
		Latency:   1000,
		Blocked:   blocked,
		RCODE:     0,
	}
}

func TestRingBuffer_AddAndQuery(t *testing.T) {
	rb := NewRingBuffer(10)

	for i := 0; i < 5; i++ {
		rb.Add(makeEntry(fmt.Sprintf("domain%d.com", i), "192.168.1.1", ResultForwarded, false))
	}

	page := rb.Query(QueryLogFilter{Limit: 100})
	if page.Total != 5 {
		t.Errorf("erwartet 5 Einträge, got %d", page.Total)
	}
}

func TestRingBuffer_Overflow(t *testing.T) {
	rb := NewRingBuffer(5)

	for i := 0; i < 8; i++ {
		rb.Add(makeEntry(fmt.Sprintf("domain%d.com", i), "192.168.1.1", ResultForwarded, false))
	}

	if rb.Len() != 5 {
		t.Errorf("erwartet 5 Einträge nach Overflow, got %d", rb.Len())
	}

	// Neueste Einträge müssen domain3–domain7 sein
	page := rb.Query(QueryLogFilter{Limit: 100})
	if page.Total != 5 {
		t.Errorf("erwartet 5 gefilterte Einträge, got %d", page.Total)
	}
	// Neueste zuerst → domain7 an erster Stelle
	if page.Entries[0].Domain != "domain7.com" {
		t.Errorf("erwartet domain7.com als neuesten Eintrag, got %s", page.Entries[0].Domain)
	}
}

func TestRingBuffer_FilterByClient(t *testing.T) {
	rb := NewRingBuffer(100)
	rb.Add(makeEntry("a.com", "192.168.1.10", ResultForwarded, false))
	rb.Add(makeEntry("b.com", "192.168.1.20", ResultBlocked, true))
	rb.Add(makeEntry("c.com", "10.0.0.1", ResultCached, false))

	page := rb.Query(QueryLogFilter{Client: "192.168.1", Limit: 100})
	if page.Total != 2 {
		t.Errorf("erwartet 2 Einträge für Client-Prefix 192.168.1, got %d", page.Total)
	}
}

func TestRingBuffer_FilterByResult(t *testing.T) {
	rb := NewRingBuffer(100)
	rb.Add(makeEntry("a.com", "1.1.1.1", ResultBlocked, true))
	rb.Add(makeEntry("b.com", "1.1.1.1", ResultBlocked, true))
	rb.Add(makeEntry("c.com", "1.1.1.1", ResultForwarded, false))

	page := rb.Query(QueryLogFilter{Result: ResultBlocked, Limit: 100})
	if page.Total != 2 {
		t.Errorf("erwartet 2 blockierte Einträge, got %d", page.Total)
	}
}

func TestRingBuffer_FilterByDomain(t *testing.T) {
	rb := NewRingBuffer(100)
	rb.Add(makeEntry("ads.example.com", "1.1.1.1", ResultBlocked, true))
	rb.Add(makeEntry("www.example.com", "1.1.1.1", ResultForwarded, false))
	rb.Add(makeEntry("google.com", "1.1.1.1", ResultForwarded, false))

	page := rb.Query(QueryLogFilter{Domain: "example.com", Limit: 100})
	if page.Total != 2 {
		t.Errorf("erwartet 2 Einträge mit 'example.com', got %d", page.Total)
	}
}

func TestRingBuffer_Pagination(t *testing.T) {
	rb := NewRingBuffer(100)
	for i := 0; i < 20; i++ {
		rb.Add(makeEntry(fmt.Sprintf("domain%d.com", i), "1.1.1.1", ResultForwarded, false))
	}

	page1 := rb.Query(QueryLogFilter{Limit: 10, Offset: 0})
	if len(page1.Entries) != 10 {
		t.Errorf("erwartet 10 Einträge auf Seite 1, got %d", len(page1.Entries))
	}
	if !page1.HasMore {
		t.Error("erwartet HasMore=true auf Seite 1")
	}

	page2 := rb.Query(QueryLogFilter{Limit: 10, Offset: 10})
	if len(page2.Entries) != 10 {
		t.Errorf("erwartet 10 Einträge auf Seite 2, got %d", len(page2.Entries))
	}
	if page2.HasMore {
		t.Error("erwartet HasMore=false auf letzter Seite")
	}
}

func TestRingBuffer_Stats(t *testing.T) {
	rb := NewRingBuffer(100)
	rb.Add(makeEntry("ads.com", "192.168.1.1", ResultBlocked, true))
	rb.Add(makeEntry("ads.com", "192.168.1.1", ResultBlocked, true))
	rb.Add(makeEntry("google.com", "192.168.1.2", ResultForwarded, false))

	stats := rb.Stats()
	if stats.TotalQueries != 3 {
		t.Errorf("erwartet 3 Queries, got %d", stats.TotalQueries)
	}
	// Block-Rate: 2/3
	expected := 2.0 / 3.0
	if stats.BlockRate < expected-0.01 || stats.BlockRate > expected+0.01 {
		t.Errorf("erwartet BlockRate %.2f, got %.2f", expected, stats.BlockRate)
	}
	if len(stats.TopBlocked) == 0 || stats.TopBlocked[0].Domain != "ads.com" {
		t.Errorf("erwartet ads.com als top-blockierte Domain")
	}
}

func TestRingBuffer_Drain(t *testing.T) {
	rb := NewRingBuffer(100)
	for i := 0; i < 10; i++ {
		rb.Add(makeEntry(fmt.Sprintf("domain%d.com", i), "1.1.1.1", ResultForwarded, false))
	}

	entries := rb.Drain(time.Time{}, 5)
	if len(entries) != 5 {
		t.Errorf("erwartet 5 Einträge von Drain, got %d", len(entries))
	}
	// Neueste 5: domain5–domain9
	if entries[0].Domain != "domain5.com" {
		t.Errorf("erwartet domain5.com als ältesten der neuesten 5, got %s", entries[0].Domain)
	}
}

func TestRingBuffer_DrainSince(t *testing.T) {
	rb := NewRingBuffer(100)

	before := time.Now()
	time.Sleep(time.Millisecond) // sicherstellen dass Einträge nach `before` liegen
	for i := 0; i < 5; i++ {
		rb.Add(makeEntry(fmt.Sprintf("new%d.com", i), "1.1.1.1", ResultForwarded, false))
	}

	// Nur Einträge nach `before` → alle 5 neuen
	entries := rb.Drain(before, 0)
	if len(entries) != 5 {
		t.Errorf("erwartet 5 neue Einträge nach since, got %d", len(entries))
	}

	// Letzten Timestamp merken (simuliert lastPushTime nach erstem Push)
	lastPush := entries[len(entries)-1].Timestamp
	time.Sleep(time.Millisecond)

	// 3 weitere Einträge hinzufügen
	for i := 0; i < 3; i++ {
		rb.Add(makeEntry(fmt.Sprintf("newer%d.com", i), "1.1.1.1", ResultForwarded, false))
	}

	// Nur die 3 neuen seit lastPush
	entries2 := rb.Drain(lastPush, 0)
	if len(entries2) != 3 {
		t.Errorf("erwartet 3 Einträge nach lastPush, got %d", len(entries2))
	}
	if entries2[0].Domain != "newer0.com" {
		t.Errorf("erwartet newer0.com, got %s", entries2[0].Domain)
	}
}

func TestRingBuffer_Empty(t *testing.T) {
	rb := NewRingBuffer(100)

	page := rb.Query(QueryLogFilter{Limit: 100})
	if page.Total != 0 || len(page.Entries) != 0 {
		t.Error("leerer Buffer sollte 0 Einträge liefern")
	}

	stats := rb.Stats()
	if stats.TotalQueries != 0 {
		t.Error("leerer Buffer sollte 0 TotalQueries liefern")
	}
}
