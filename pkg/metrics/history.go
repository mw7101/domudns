package metrics

import (
	"sync"
	"time"

	dto "github.com/prometheus/client_model/go"
)

const (
	maxFineSnapshots   = 8640 // 24h at 10s interval (24*60*6)
	maxCoarseSnapshots = 8640 // 30 days at 5-min interval (30*24*12)
)

// Snapshot contains a metrics point in time.
type Snapshot struct {
	TS        int64   `json:"ts"`
	Queries   float64 `json:"queries"`
	Blocked   float64 `json:"blocked"`
	Cached    float64 `json:"cached"`
	Forwarded float64 `json:"forwarded"`
	Errors    float64 `json:"errors"`
}

var (
	fineHistoryMu sync.RWMutex
	fineHistory   []Snapshot // 10s interval, max. 24h

	coarseHistoryMu sync.RWMutex
	coarseHistory   []Snapshot // 5-min interval, max. 30 days
)

// RecordFineSnapshot reads current counter values and stores them in the fine ring buffer (10s interval).
func RecordFineSnapshot() {
	recordTo(&fineHistoryMu, &fineHistory, maxFineSnapshots)
}

// RecordCoarseSnapshot reads current counter values and stores them in the coarse ring buffer (5-min interval).
func RecordCoarseSnapshot() {
	recordTo(&coarseHistoryMu, &coarseHistory, maxCoarseSnapshots)
}

// GetFineHistory returns all stored fine snapshots (oldest first).
func GetFineHistory() []Snapshot {
	fineHistoryMu.RLock()
	defer fineHistoryMu.RUnlock()
	result := make([]Snapshot, len(fineHistory))
	copy(result, fineHistory)
	return result
}

// GetCoarseHistory returns all stored coarse snapshots (oldest first).
func GetCoarseHistory() []Snapshot {
	coarseHistoryMu.RLock()
	defer coarseHistoryMu.RUnlock()
	result := make([]Snapshot, len(coarseHistory))
	copy(result, coarseHistory)
	return result
}

// recordTo reads Prometheus metrics and appends a snapshot to the given buffer.
func recordTo(mu *sync.RWMutex, buf *[]Snapshot, max int) {
	snap := Snapshot{TS: time.Now().Unix()}

	mfs, err := Registry().Gather()
	if err != nil {
		return
	}

	for _, mf := range mfs {
		if mf.GetName() != "dns_queries_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			val := m.GetCounter().GetValue()
			result := labelValue(m.GetLabel(), "result")
			switch result {
			case "blocked":
				snap.Blocked += val
			case "cached":
				snap.Cached += val
			case "forwarded":
				snap.Forwarded += val
			case "error":
				snap.Errors += val
			}
			snap.Queries += val
		}
	}

	mu.Lock()
	*buf = append(*buf, snap)
	if len(*buf) > max {
		*buf = (*buf)[len(*buf)-max:]
	}
	mu.Unlock()
}

func labelValue(labels []*dto.LabelPair, name string) string {
	for _, l := range labels {
		if l.GetName() == name {
			return l.GetValue()
		}
	}
	return ""
}
