package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"

	"github.com/mw7101/domudns/internal/dns"
	"github.com/mw7101/domudns/internal/filestore"
)

// TestRecordsHandler_Update_ConcurrentNoLostUpdate exercises the actual
// vulnerable call site (PUT /api/zones/{domain}/records/{id}) end-to-end
// against a real filestore.FileStore (not a mock): n concurrent requests
// each update a different record in the same zone, and all n changes must
// be present afterward.
//
// Note on what this does and doesn't prove: with the fix (single lock via
// UpdateZone), this passes deterministically — there is no window left in
// which a lost update could occur, by construction. It is not, by itself, a
// reliable *detector* of the pre-fix bug: the old GetZone+PutRecord race
// window was microseconds wide, and without the race detector (unavailable
// in this sandbox, see CHANGELOG/report) or artificial delays this test can
// pass "by luck" even against the old code, since Go's scheduler doesn't
// reliably interleave at exactly the vulnerable point under normal load.
// TestFileStore_UpdateZone_ConcurrentNoLostUpdate (filestore package) is the
// test that was actually confirmed to fail against a reintroduced
// separate-lock version and pass against the fix — that one is the rigorous
// regression test for this finding; this one is a confirmatory end-to-end
// check on top.
func TestRecordsHandler_Update_ConcurrentNoLostUpdate(t *testing.T) {
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "records-concurrency-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	fs, err := filestore.NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	const n = 10
	zone := &dns.Zone{
		Domain: "concurrent-records.local",
		TTL:    3600,
		SOA:    &dns.SOA{Serial: 2020010100},
	}
	for i := 0; i < n; i++ {
		zone.Records = append(zone.Records, dns.Record{
			ID: i + 1, Name: recordName(i), Type: dns.TypeA, TTL: 300, Value: "192.0.2.1",
		})
	}
	if err := fs.PutZone(ctx, zone); err != nil {
		t.Fatalf("PutZone: %v", err)
	}

	h := NewRecordsHandler(fs, fs, nil)

	// n concurrent PUTs, each updating a different record's value. A lost
	// update would show up as one of these writes never landing because a
	// later PUT's save (based on a stale in-memory read) overwrote it.
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			body, _ := json.Marshal(dns.Record{
				Name: recordName(id - 1), Type: dns.TypeA, TTL: 300, Value: updatedValueFor(id),
			})
			req := httptest.NewRequest(http.MethodPut,
				"/api/zones/concurrent-records.local/records/"+strconv.Itoa(id), bytes.NewReader(body))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Errorf("PUT record %d: status = %d, want 200; body=%s", id, w.Code, w.Body.String())
			}
		}(i + 1)
	}
	wg.Wait()

	got, err := fs.GetZone(ctx, "concurrent-records.local")
	if err != nil {
		t.Fatalf("GetZone: %v", err)
	}
	if len(got.Records) != n {
		t.Fatalf("record count = %d, want %d (records disappeared)", len(got.Records), n)
	}
	for i := 0; i < n; i++ {
		id := i + 1
		rec := got.RecordByID(id)
		if rec == nil {
			t.Fatalf("record %d missing entirely", id)
		}
		if rec.Value != updatedValueFor(id) {
			t.Errorf("record %d value = %q, want %q (lost update)", id, rec.Value, updatedValueFor(id))
		}
	}
}

func recordName(i int) string {
	return "host" + strconv.Itoa(i)
}

func updatedValueFor(id int) string {
	return "10.0.0." + strconv.Itoa(id)
}
