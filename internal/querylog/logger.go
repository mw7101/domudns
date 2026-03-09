package querylog

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	defaultChannelBuffer = 512
	defaultMemoryEntries = 5000
)

// Config holds the configuration for the QueryLogger.
type Config struct {
	Enabled       bool          `yaml:"enabled"`
	MemoryEntries int           `yaml:"memory_entries"` // Ring buffer size (default: 5000)
	PushInterval  time.Duration `yaml:"push_interval"`  // Slave→Master push interval (default: 30s)
	Persist       bool          `yaml:"persist"`        // Enable SQLite persistence
	PersistPath   string        `yaml:"persist_path"`   // Path to SQLite DB (default: data_dir/query.log.db)
	PersistDays   int           `yaml:"persist_days"`   // Retention in days (default: 7)
}

// PushFunc is a function that sends entries to the master (slave mode).
type PushFunc func(entries []QueryLogEntry) error

// QueryLogger receives DNS query entries non-blocking via a channel
// and writes them into an in-memory ring buffer.
type QueryLogger struct {
	cfg    Config
	nodeID string
	ch     chan QueryLogEntry
	ring   *RingBuffer
	sqlite *SQLiteStore // optional, nil if persist=false

	// pushFn is optional — only set on slaves
	pushFn       PushFunc
	lastPushTime time.Time // timestamp of the last successfully pushed entry
}

// New creates a new QueryLogger and starts the background loop.
// nodeID is the IP or hostname of this DNS node.
// Returns nil if cfg.Enabled == false.
func New(cfg Config, nodeID string) *QueryLogger {
	if !cfg.Enabled {
		return nil
	}
	if cfg.MemoryEntries <= 0 {
		cfg.MemoryEntries = defaultMemoryEntries
	}
	if cfg.PushInterval <= 0 {
		cfg.PushInterval = 30 * time.Second
	}

	return &QueryLogger{
		cfg:    cfg,
		nodeID: nodeID,
		ch:     make(chan QueryLogEntry, defaultChannelBuffer),
		ring:   NewRingBuffer(cfg.MemoryEntries),
	}
}

// SetPushFunc sets the push function for slave mode.
// Must be called before Run().
func (q *QueryLogger) SetPushFunc(fn PushFunc) {
	q.pushFn = fn
}

// Log writes an entry non-blocking into the channel.
// If the channel is full, the entry is dropped (never block the DNS path).
func (q *QueryLogger) Log(entry QueryLogEntry) {
	if q == nil {
		return
	}
	entry.NodeID = q.nodeID
	select {
	case q.ch <- entry:
	default:
		// Channel full → drop, never block
	}
}

// LogQuery is a helper method for directly logging a DNS query.
func (q *QueryLogger) LogQuery(
	clientIP, domain, qtype, result, upstream string,
	latency time.Duration,
	rcode int,
) {
	if q == nil {
		return
	}
	q.Log(QueryLogEntry{
		Timestamp: time.Now(),
		ClientIP:  clientIP,
		Domain:    domain,
		QType:     qtype,
		Result:    result,
		Latency:   latency.Microseconds(),
		Upstream:  upstream,
		Blocked:   result == ResultBlocked,
		Cached:    result == ResultCached,
		RCODE:     rcode,
	})
}

// Run starts the background loop. Blocks until ctx is cancelled.
// Must be started as a goroutine: go logger.Run(ctx)
func (q *QueryLogger) Run(ctx context.Context) {
	if q == nil {
		return
	}

	// Start SQLiteStore if persistence is enabled
	if q.cfg.Persist {
		store, err := NewSQLiteStore(q.cfg.PersistPath, "", q.cfg.PersistDays)
		if err != nil {
			log.Warn().Err(err).Msg("query log: failed to open sqlite, persistence disabled")
		} else {
			q.sqlite = store
			go store.Run(ctx)
			log.Info().Str("path", q.cfg.PersistPath).Msg("query log: sqlite persistence enabled")
		}
	}

	var pushTicker *time.Ticker
	var pushC <-chan time.Time

	if q.pushFn != nil {
		pushTicker = time.NewTicker(q.cfg.PushInterval)
		pushC = pushTicker.C
		defer pushTicker.Stop()
	}

	log.Info().
		Str("node", q.nodeID).
		Int("memory_entries", q.cfg.MemoryEntries).
		Bool("push_enabled", q.pushFn != nil).
		Msg("query logger started")

	for {
		select {
		case <-ctx.Done():
			// Write remaining entries in the channel to the ring buffer
			q.drainChannel()
			if q.sqlite != nil {
				_ = q.sqlite.Close()
			}
			log.Info().Msg("query logger stopped")
			return

		case entry := <-q.ch:
			q.ring.Add(entry)
			if q.sqlite != nil {
				q.sqlite.Add(entry)
			}

		case <-pushC:
			q.doPush()
		}
	}
}

// Query returns filtered and paginated entries from the ring buffer.
func (q *QueryLogger) Query(f QueryLogFilter) QueryLogPage {
	if q == nil {
		return QueryLogPage{Entries: []QueryLogEntry{}}
	}
	return q.ring.Query(f)
}

// Stats returns aggregated statistics.
func (q *QueryLogger) Stats() QueryLogStats {
	if q == nil {
		return QueryLogStats{
			TopClients:     []ClientStat{},
			TopDomains:     []DomainStat{},
			TopBlocked:     []DomainStat{},
			QueriesPerHour: []HourStat{},
		}
	}
	return q.ring.Stats()
}

// Len returns the current number of entries in the ring buffer.
func (q *QueryLogger) Len() int {
	if q == nil {
		return 0
	}
	return q.ring.Len()
}

// AddEntries inserts entries directly into the ring buffer (for slave receiving from master).
func (q *QueryLogger) AddEntries(entries []QueryLogEntry) {
	if q == nil {
		return
	}
	for _, e := range entries {
		q.ring.Add(e)
	}
}

// drainChannel reads all remaining entries from the channel into the ring buffer.
func (q *QueryLogger) drainChannel() {
	for {
		select {
		case entry := <-q.ch:
			q.ring.Add(entry)
			if q.sqlite != nil {
				q.sqlite.Add(entry)
			}
		default:
			return
		}
	}
}

// doPush sends only new entries (since the last successful push) to the master.
// On error, lastPushTime is NOT updated — the next tick will retry.
func (q *QueryLogger) doPush() {
	if q.pushFn == nil {
		return
	}
	entries := q.ring.Drain(q.lastPushTime, 1000)
	if len(entries) == 0 {
		return
	}
	if err := q.pushFn(entries); err != nil {
		log.Warn().Err(err).Msg("query log push to master failed")
		return // do not update lastPushTime → retry on next tick
	}
	// Remember the timestamp of the last pushed entry
	q.lastPushTime = entries[len(entries)-1].Timestamp
}
