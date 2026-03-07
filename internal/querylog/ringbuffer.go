package querylog

import (
	"strings"
	"sync"
	"time"
)

// RingBuffer ist ein thread-sicherer Ringbuffer fester Größe für QueryLogEntry.
// Bei vollem Buffer werden die ältesten Einträge überschrieben.
type RingBuffer struct {
	mu       sync.RWMutex
	entries  []QueryLogEntry
	capacity int
	head     int // Schreibposition (nächster freier Slot)
	count    int // Aktuelle Anzahl Einträge (max = capacity)
}

// NewRingBuffer erstellt einen neuen RingBuffer mit der angegebenen Kapazität.
func NewRingBuffer(capacity int) *RingBuffer {
	if capacity <= 0 {
		capacity = 5000
	}
	return &RingBuffer{
		entries:  make([]QueryLogEntry, capacity),
		capacity: capacity,
	}
}

// Add fügt einen Eintrag in den Ringbuffer ein.
// Bei vollem Buffer wird der älteste Eintrag überschrieben.
func (r *RingBuffer) Add(entry QueryLogEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.entries[r.head] = entry
	r.head = (r.head + 1) % r.capacity
	if r.count < r.capacity {
		r.count++
	}
}

// Query gibt gefilterte und paginierte Einträge zurück.
// Einträge werden in umgekehrter chronologischer Reihenfolge zurückgegeben (neueste zuerst).
func (r *RingBuffer) Query(f QueryLogFilter) QueryLogPage {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Einträge in chronologischer Reihenfolge sammeln (älteste zuerst)
	ordered := make([]QueryLogEntry, 0, r.count)
	if r.count < r.capacity {
		// Buffer noch nicht voll: head ist gleichzeitig der älteste Index
		ordered = append(ordered, r.entries[:r.count]...)
	} else {
		// Buffer voll: ältester Eintrag ist an Position head
		ordered = append(ordered, r.entries[r.head:]...)
		ordered = append(ordered, r.entries[:r.head]...)
	}

	// Filter anwenden
	filtered := make([]QueryLogEntry, 0, len(ordered))
	for i := len(ordered) - 1; i >= 0; i-- { // neueste zuerst
		e := ordered[i]
		if !matchesFilter(e, f) {
			continue
		}
		filtered = append(filtered, e)
	}

	total := len(filtered)

	// Pagination
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return QueryLogPage{Entries: []QueryLogEntry{}, Total: total, HasMore: false}
	}

	end := offset + limit
	hasMore := end < total
	if end > total {
		end = total
	}

	return QueryLogPage{
		Entries: filtered[offset:end],
		Total:   total,
		HasMore: hasMore,
	}
}

// Stats berechnet aggregierte Statistiken über alle Einträge im Buffer.
func (r *RingBuffer) Stats() QueryLogStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.count == 0 {
		return QueryLogStats{
			TopClients:     []ClientStat{},
			TopDomains:     []DomainStat{},
			TopBlocked:     []DomainStat{},
			QueriesPerHour: []HourStat{},
		}
	}

	clientCounts := make(map[string]int64)
	domainCounts := make(map[string]int64)
	blockedCounts := make(map[string]int64)
	hourCounts := make(map[time.Time]int64)

	var totalBlocked int64
	now := time.Now()
	cutoff := now.Add(-24 * time.Hour)

	for i := 0; i < r.count; i++ {
		e := r.entries[i]
		clientCounts[e.ClientIP]++
		domainCounts[e.Domain]++
		if e.Blocked {
			totalBlocked++
			blockedCounts[e.Domain]++
		}
		if e.Timestamp.After(cutoff) {
			hour := e.Timestamp.Truncate(time.Hour)
			hourCounts[hour]++
		}
	}

	var blockRate float64
	if r.count > 0 {
		blockRate = float64(totalBlocked) / float64(r.count)
	}

	return QueryLogStats{
		TotalQueries:   int64(r.count),
		BlockRate:      blockRate,
		TopClients:     topClients(clientCounts, 10),
		TopDomains:     topDomains(domainCounts, 10),
		TopBlocked:     topDomains(blockedCounts, 10),
		QueriesPerHour: buildHourStats(hourCounts, now),
	}
}

// Len gibt die aktuelle Anzahl Einträge im Buffer zurück.
func (r *RingBuffer) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.count
}

// Drain gibt Einträge zurück, die nach `since` hinzugefügt wurden (älteste zuerst).
// Bei `since.IsZero()` werden alle Einträge zurückgegeben (kein Zeitfilter).
// Es werden maximal `max` Einträge zurückgegeben.
// Gedacht für den Slave-Push: nur neue Einträge seit dem letzten Push übertragen.
func (r *RingBuffer) Drain(since time.Time, max int) []QueryLogEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.count == 0 {
		return nil
	}

	// Alle in chronologischer Reihenfolge sammeln
	var ordered []QueryLogEntry
	if r.count < r.capacity {
		ordered = make([]QueryLogEntry, r.count)
		copy(ordered, r.entries[:r.count])
	} else {
		ordered = make([]QueryLogEntry, r.capacity)
		n := copy(ordered, r.entries[r.head:])
		copy(ordered[n:], r.entries[:r.head])
	}

	// Nur Einträge nach `since` übernehmen (verhindert Duplikate beim wiederholten Push)
	if !since.IsZero() {
		filtered := ordered[:0]
		for _, e := range ordered {
			if e.Timestamp.After(since) {
				filtered = append(filtered, e)
			}
		}
		ordered = filtered
	}

	if max > 0 && len(ordered) > max {
		// Nur die neuesten `max` Einträge
		ordered = ordered[len(ordered)-max:]
	}

	return ordered
}

// matchesFilter prüft ob ein Eintrag den Filterkriterien entspricht.
func matchesFilter(e QueryLogEntry, f QueryLogFilter) bool {
	if f.Client != "" && !strings.HasPrefix(e.ClientIP, f.Client) {
		return false
	}
	if f.Domain != "" && !strings.Contains(e.Domain, f.Domain) {
		return false
	}
	if f.Result != "" && e.Result != f.Result {
		return false
	}
	if f.QType != "" && e.QType != f.QType {
		return false
	}
	if f.Node != "" && e.NodeID != f.Node {
		return false
	}
	if !f.Since.IsZero() && e.Timestamp.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && e.Timestamp.After(f.Until) {
		return false
	}
	return true
}

// topClients gibt die N häufigsten Clients zurück (absteigend sortiert).
func topClients(counts map[string]int64, n int) []ClientStat {
	stats := make([]ClientStat, 0, len(counts))
	for ip, c := range counts {
		stats = append(stats, ClientStat{ClientIP: ip, Count: c})
	}
	sortDesc(len(stats), func(i, j int) bool {
		return stats[i].Count > stats[j].Count
	}, func(i, j int) {
		stats[i], stats[j] = stats[j], stats[i]
	})
	if len(stats) > n {
		stats = stats[:n]
	}
	return stats
}

// topDomains gibt die N häufigsten Domains zurück (absteigend sortiert).
func topDomains(counts map[string]int64, n int) []DomainStat {
	stats := make([]DomainStat, 0, len(counts))
	for d, c := range counts {
		stats = append(stats, DomainStat{Domain: d, Count: c})
	}
	sortDesc(len(stats), func(i, j int) bool {
		return stats[i].Count > stats[j].Count
	}, func(i, j int) {
		stats[i], stats[j] = stats[j], stats[i]
	})
	if len(stats) > n {
		stats = stats[:n]
	}
	return stats
}

// buildHourStats baut die HourStat-Slice für die letzten 24 Stunden auf.
func buildHourStats(counts map[time.Time]int64, now time.Time) []HourStat {
	result := make([]HourStat, 0, 24)
	base := now.Truncate(time.Hour)
	for i := 23; i >= 0; i-- {
		hour := base.Add(-time.Duration(i) * time.Hour)
		result = append(result, HourStat{Hour: hour, Count: counts[hour]})
	}
	return result
}

// sortDesc ist eine einfache Insertion-Sort-Implementierung ohne import von "sort".
// Für kleine Slices (≤1000) ausreichend performant.
func sortDesc(n int, less func(i, j int) bool, swap func(i, j int)) {
	for i := 1; i < n; i++ {
		for j := i; j > 0 && less(j, j-1); j-- {
			swap(j, j-1)
		}
	}
}
