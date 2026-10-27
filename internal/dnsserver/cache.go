package dnsserver

import (
	"container/heap"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// CacheEntry represents a cached DNS response with expiration.
type CacheEntry struct {
	key        string
	response   *dns.Msg
	expiresAt  time.Time
	accessTime time.Time // for LRU eviction
	heapIdx    int       // position in lruHeap (-1 = not in heap)
}

// lruHeap implements heap.Interface ordered by accessTime (oldest first).
type lruHeap []*CacheEntry

func (h lruHeap) Len() int           { return len(h) }
func (h lruHeap) Less(i, j int) bool { return h[i].accessTime.Before(h[j].accessTime) }
func (h lruHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].heapIdx = i
	h[j].heapIdx = j
}
func (h *lruHeap) Push(x any) {
	entry := x.(*CacheEntry)
	entry.heapIdx = len(*h)
	*h = append(*h, entry)
}
func (h *lruHeap) Pop() any {
	old := *h
	n := len(old)
	entry := old[n-1]
	old[n-1] = nil
	entry.heapIdx = -1
	*h = old[:n-1]
	return entry
}

// CacheManager manages DNS response cache with O(log n) LRU eviction.
type CacheManager struct {
	entries     map[string]*CacheEntry // key = qname:qtype
	lru         lruHeap                // min-heap by accessTime
	maxEntries  int
	defaultTTL  time.Duration
	negativeTTL time.Duration
	mu          sync.Mutex
	hits        uint64
	misses      uint64
}

// NewCacheManager creates a new cache manager.
func NewCacheManager(maxEntries int, defaultTTL, negativeTTL time.Duration) *CacheManager {
	if maxEntries <= 0 {
		maxEntries = 10000
	}
	if defaultTTL == 0 {
		defaultTTL = 1 * time.Hour
	}
	if negativeTTL == 0 {
		negativeTTL = 5 * time.Minute
	}

	c := &CacheManager{
		entries:     make(map[string]*CacheEntry, maxEntries),
		lru:         make(lruHeap, 0, maxEntries),
		maxEntries:  maxEntries,
		defaultTTL:  defaultTTL,
		negativeTTL: negativeTTL,
	}
	heap.Init(&c.lru)
	return c
}

// Get retrieves a cached response if available and not expired.
func (c *CacheManager) Get(qname string, qtype uint16) *dns.Msg {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := cacheKey(qname, qtype)
	entry, ok := c.entries[key]
	if !ok {
		c.misses++
		return nil
	}

	// Check expiration
	if time.Now().After(entry.expiresAt) {
		c.removeEntry(entry)
		c.misses++
		return nil
	}

	// Update access time and fix heap position (O(log n))
	entry.accessTime = time.Now()
	heap.Fix(&c.lru, entry.heapIdx)
	c.hits++

	// Return a copy to avoid mutation
	return entry.response.Copy()
}

// Set stores a DNS response in the cache.
func (c *CacheManager) Set(qname string, qtype uint16, response *dns.Msg) {
	if response == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Determine TTL based on response
	ttl := c.determineTTL(response)
	if ttl == 0 {
		return // Don't cache zero TTL responses
	}

	key := cacheKey(qname, qtype)
	now := time.Now()

	// Update existing entry in-place
	if existing, ok := c.entries[key]; ok {
		existing.response = response.Copy()
		existing.expiresAt = now.Add(ttl)
		existing.accessTime = now
		heap.Fix(&c.lru, existing.heapIdx)
		return
	}

	// LRU eviction if cache is full (O(log n))
	if len(c.entries) >= c.maxEntries {
		c.evictLRU()
	}

	// Store new entry
	entry := &CacheEntry{
		key:        key,
		response:   response.Copy(),
		expiresAt:  now.Add(ttl),
		accessTime: now,
		heapIdx:    -1,
	}
	c.entries[key] = entry
	heap.Push(&c.lru, entry)
}

// determineTTL determines the cache TTL for a response.
func (c *CacheManager) determineTTL(response *dns.Msg) time.Duration {
	// Negative response (NXDOMAIN etc.)
	if response.Rcode != dns.RcodeSuccess || len(response.Answer) == 0 {
		return c.negativeTTL
	}

	// Use minimum TTL from answer section
	minTTL := uint32(0)
	for i, rr := range response.Answer {
		ttl := rr.Header().Ttl
		if i == 0 || ttl < minTTL {
			minTTL = ttl
		}
	}

	// If no TTL found, use default
	if minTTL == 0 {
		return c.defaultTTL
	}

	return time.Duration(minTTL) * time.Second
}

// evictLRU removes the least recently accessed entry (O(log n)).
func (c *CacheManager) evictLRU() {
	if len(c.lru) == 0 {
		return
	}
	oldest := heap.Pop(&c.lru).(*CacheEntry)
	delete(c.entries, oldest.key)
	log.Debug().Str("key", oldest.key).Msg("cache LRU eviction")
}

// removeEntry removes an entry from both the map and the heap.
func (c *CacheManager) removeEntry(entry *CacheEntry) {
	delete(c.entries, entry.key)
	if entry.heapIdx >= 0 && entry.heapIdx < len(c.lru) {
		heap.Remove(&c.lru, entry.heapIdx)
	}
}

// Clean removes expired entries (periodic cleanup).
func (c *CacheManager) Clean() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	count := 0

	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			heap.Remove(&c.lru, entry.heapIdx)
			delete(c.entries, key)
			count++
		}
	}

	if count > 0 {
		log.Debug().Int("expired", count).Msg("cache cleanup")
	}
}

// Stats returns cache statistics.
func (c *CacheManager) Stats() (entries, hits, misses int, hitRate float64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entries = len(c.entries)
	hits = int(c.hits)
	misses = int(c.misses)

	total := hits + misses
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}

	return
}

// cacheKey generates a cache key from qname and qtype.
// Uses a numeric fallback for unknown qtypes to avoid empty keys.
func cacheKey(qname string, qtype uint16) string {
	typeStr, ok := dns.TypeToString[qtype]
	if !ok {
		typeStr = fmt.Sprintf("%d", qtype)
	}
	return dns.CanonicalName(qname) + ":" + typeStr
}

// StartCleanupLoop starts a background goroutine to clean expired entries.
func (c *CacheManager) StartCleanupLoop(interval time.Duration, stopCh <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.Clean()
		case <-stopCh:
			return
		}
	}
}
