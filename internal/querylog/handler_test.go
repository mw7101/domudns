package querylog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func startLogger(t *testing.T, cfg Config) (*QueryLogger, context.CancelFunc) {
	t.Helper()
	q := New(cfg, "test-node")
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		q.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	return q, cancel
}

func TestHandler_List_Empty(t *testing.T) {
	q, _ := startLogger(t, testConfig())
	h := NewHandler(q)

	req := httptest.NewRequest(http.MethodGet, "/api/query-log", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["success"] != true {
		t.Error("expected success=true")
	}
}

func TestHandler_List_WithEntries(t *testing.T) {
	q, _ := startLogger(t, testConfig())
	h := NewHandler(q)

	q.LogQuery("192.168.1.1", "example.com", "A", ResultForwarded, "1.1.1.1", time.Millisecond, 0)
	q.LogQuery("192.168.1.2", "ads.bad.com", "A", ResultBlocked, "", 0, 0)
	time.Sleep(20 * time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/api/query-log", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	data := resp["data"].(map[string]interface{})
	total := int(data["total"].(float64))
	if total != 2 {
		t.Errorf("expected total=2, got %d", total)
	}
}

func TestHandler_List_FilterByResult(t *testing.T) {
	q, _ := startLogger(t, testConfig())
	h := NewHandler(q)

	q.LogQuery("1.1.1.1", "ads.com", "A", ResultBlocked, "", 0, 0)
	q.LogQuery("1.1.1.1", "google.com", "A", ResultForwarded, "8.8.8.8", time.Millisecond, 0)
	time.Sleep(20 * time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/api/query-log?result=blocked", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	var resp map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	data := resp["data"].(map[string]interface{})
	if int(data["total"].(float64)) != 1 {
		t.Errorf("expected 1 blocked entry, got %v", data["total"])
	}
}

func TestHandler_List_InvalidResult(t *testing.T) {
	q, _ := startLogger(t, testConfig())
	h := NewHandler(q)

	req := httptest.NewRequest(http.MethodGet, "/api/query-log?result=invalid", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid result, got %d", rr.Code)
	}
}

func TestHandler_List_InvalidLimit(t *testing.T) {
	q, _ := startLogger(t, testConfig())
	h := NewHandler(q)

	req := httptest.NewRequest(http.MethodGet, "/api/query-log?limit=abc", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid limit, got %d", rr.Code)
	}
}

func TestHandler_List_InvalidSince(t *testing.T) {
	q, _ := startLogger(t, testConfig())
	h := NewHandler(q)

	req := httptest.NewRequest(http.MethodGet, "/api/query-log?since=not-a-date", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid since, got %d", rr.Code)
	}
}

func TestHandler_Stats(t *testing.T) {
	q, _ := startLogger(t, testConfig())
	h := NewHandler(q)

	q.LogQuery("10.0.0.1", "ads.com", "A", ResultBlocked, "", 0, 0)
	q.LogQuery("10.0.0.1", "ads.com", "A", ResultBlocked, "", 0, 0)
	q.LogQuery("10.0.0.2", "google.com", "A", ResultForwarded, "1.1.1.1", time.Millisecond, 0)
	time.Sleep(20 * time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/api/query-log/stats", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	data := resp["data"].(map[string]interface{})

	total := int(data["total_queries"].(float64))
	if total != 3 {
		t.Errorf("expected 3 queries, got %d", total)
	}

	blockRate := data["block_rate"].(float64)
	expected := 2.0 / 3.0
	if blockRate < expected-0.01 || blockRate > expected+0.01 {
		t.Errorf("expected block_rate %.2f, got %.2f", expected, blockRate)
	}
}

func TestHandler_MethodNotAllowed(t *testing.T) {
	q, _ := startLogger(t, testConfig())
	h := NewHandler(q)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/api/query-log", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("method %s: expected 405, got %d", method, rr.Code)
		}
	}
}

func TestHandler_NilLogger(t *testing.T) {
	h := NewHandler(nil)

	req := httptest.NewRequest(http.MethodGet, "/api/query-log", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	// nil logger returns empty response, no panic
	if rr.Code != http.StatusOK {
		t.Errorf("nil-Logger: expected 200, got %d", rr.Code)
	}
}
