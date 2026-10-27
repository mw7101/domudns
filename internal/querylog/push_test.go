package querylog

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewPushFunc_SendsEntries(t *testing.T) {
	var received []QueryLogEntry

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/internal/query-log-sync" {
			t.Errorf("unerwarteter Pfad: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("erwartet POST, got %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		var payload SyncPayload
		_ = json.Unmarshal(body, &payload)
		received = payload.Entries
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	push := NewPushFunc(server.URL, "test-secret", "slave-node")
	entries := []QueryLogEntry{
		{Domain: "example.com", QType: "A", Result: ResultForwarded, NodeID: "slave-node"},
	}

	if err := push(entries); err != nil {
		t.Fatalf("push fehlgeschlagen: %v", err)
	}

	if len(received) != 1 {
		t.Errorf("erwartet 1 Eintrag empfangen, got %d", len(received))
	}
	if received[0].Domain != "example.com" {
		t.Errorf("erwartet Domain 'example.com', got '%s'", received[0].Domain)
	}
}

func TestNewPushFunc_EmptyEntries(t *testing.T) {
	// Kein HTTP-Call bei leerer Liste
	push := NewPushFunc("http://should-not-be-called", "secret", "node")
	if err := push(nil); err != nil {
		t.Errorf("push mit nil-Entries sollte kein Fehler sein: %v", err)
	}
	if err := push([]QueryLogEntry{}); err != nil {
		t.Errorf("push mit leerer Liste sollte kein Fehler sein: %v", err)
	}
}

func TestSyncHandler_ValidRequest(t *testing.T) {
	q := New(testConfig(), "master")

	handler := NewSyncHandler(q, "test-secret")

	entries := []QueryLogEntry{
		{Domain: "ads.com", QType: "A", Result: ResultBlocked, NodeID: "slave1", Timestamp: time.Now()},
		{Domain: "google.com", QType: "A", Result: ResultForwarded, NodeID: "slave1", Timestamp: time.Now()},
	}

	// Payload wie Slave es sendet
	payloadBody := map[string]interface{}{
		"node":    "slave1",
		"entries": entries,
	}
	cleanBody, _ := json.Marshal(payloadBody)
	sig := computeHMAC("test-secret", cleanBody)

	signed := SyncPayload{HMAC: sig, NodeID: "slave1", Entries: entries}
	body, _ := json.Marshal(signed)

	req := httptest.NewRequest(http.MethodPost, "/api/internal/query-log-sync", bytesReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("erwartet 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if q.Len() != 2 {
		t.Errorf("erwartet 2 Einträge im Logger, got %d", q.Len())
	}
}

func TestSyncHandler_InvalidHMAC(t *testing.T) {
	q := New(testConfig(), "master")
	handler := NewSyncHandler(q, "correct-secret")

	payload := SyncPayload{
		HMAC:    "aabbccdd", // falscher HMAC
		NodeID:  "slave1",
		Entries: []QueryLogEntry{{Domain: "test.com"}},
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/internal/query-log-sync", bytesReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("erwartet 401 bei falschem HMAC, got %d", rr.Code)
	}
	if q.Len() != 0 {
		t.Error("keine Einträge bei fehlgeschlagenem HMAC erwartet")
	}
}

func TestSyncHandler_NoSecret(t *testing.T) {
	// Ohne Secret wird keine HMAC-Prüfung durchgeführt
	q := New(testConfig(), "master")
	handler := NewSyncHandler(q, "")

	entries := []QueryLogEntry{{Domain: "example.com", QType: "A", Result: ResultCached}}
	payload := SyncPayload{NodeID: "slave1", Entries: entries}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/internal/query-log-sync", bytesReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("erwartet 204 ohne Secret-Prüfung, got %d", rr.Code)
	}
	if q.Len() != 1 {
		t.Errorf("erwartet 1 Eintrag, got %d", q.Len())
	}
}

func TestSyncHandler_MethodNotAllowed(t *testing.T) {
	handler := NewSyncHandler(nil, "")
	req := httptest.NewRequest(http.MethodGet, "/api/internal/query-log-sync", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("erwartet 405, got %d", rr.Code)
	}
}

func TestPushFuncRoundtrip(t *testing.T) {
	// Vollständiger Roundtrip: Push sendet, SyncHandler empfängt und verifiziert
	secret := "roundtrip-secret"
	master := New(testConfig(), "master")
	handler := NewSyncHandler(master, secret)

	server := httptest.NewServer(handler)
	defer server.Close()

	push := NewPushFunc(server.URL, secret, "slave-node")
	entries := []QueryLogEntry{
		{Domain: "blocked.com", QType: "A", Result: ResultBlocked, NodeID: "slave-node", Timestamp: time.Now()},
		{Domain: "ok.com", QType: "AAAA", Result: ResultForwarded, NodeID: "slave-node", Timestamp: time.Now()},
	}

	if err := push(entries); err != nil {
		t.Fatalf("push fehlgeschlagen: %v", err)
	}

	if master.Len() != 2 {
		t.Errorf("erwartet 2 Einträge auf Master, got %d", master.Len())
	}
}

// bytesReader ist ein kleiner Helfer für Tests.
func bytesReader(b []byte) io.Reader {
	return bytes.NewReader(b)
}
