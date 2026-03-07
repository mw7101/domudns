package querylog

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

const syncEventType = "query_log_sync"

// NewPushFunc creates a PushFunc that sends entries via HTTP to the master.
// masterURL is the base URL of the master (e.g. "http://192.0.2.1").
// secret is the shared HMAC secret (DNS_STACK_SYNC_SECRET).
// nodeID identifies this slave in the payload.
func NewPushFunc(masterURL, secret, nodeID string) PushFunc {
	client := &http.Client{Timeout: 10 * time.Second}
	endpoint := masterURL + "/api/internal/query-log-sync"

	return func(entries []QueryLogEntry) error {
		if len(entries) == 0 {
			return nil
		}

		// Serialize payload without HMAC → compute HMAC → re-serialize with HMAC.
		// Order exactly mirrors the verification in SyncHandler.
		payloadBody := map[string]interface{}{
			"node":    nodeID,
			"entries": entries,
		}
		cleanBody, err := json.Marshal(payloadBody)
		if err != nil {
			return fmt.Errorf("marshal payload: %w", err)
		}

		sig := computeHMAC(secret, cleanBody)

		signed := SyncPayload{
			HMAC:    sig,
			NodeID:  nodeID,
			Entries: entries,
		}
		body, err := json.Marshal(signed)
		if err != nil {
			return fmt.Errorf("marshal signed payload: %w", err)
		}

		req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("push to master: %w", err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("master returned %d", resp.StatusCode)
		}

		log.Debug().
			Str("master", masterURL).
			Int("entries", len(entries)).
			Msg("query log: pushed entries to master")

		return nil
	}
}

// SyncHandler implements POST /api/internal/query-log-sync (master side).
// Receives batch pushes from slaves and writes them to the local QueryLogger.
type SyncHandler struct {
	logger *QueryLogger
	secret string
}

// NewSyncHandler creates a new SyncHandler.
func NewSyncHandler(logger *QueryLogger, secret string) *SyncHandler {
	return &SyncHandler{logger: logger, secret: secret}
}

// ServeHTTP implements http.Handler for POST /api/internal/query-log-sync.
func (h *SyncHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 5<<20)) // max 5 MB
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	var payload SyncPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// Validate HMAC (only if secret is configured).
	// Strategy: extract HMAC from payload, then re-serialize body without
	// the HMAC field as a map and verify against it.
	if h.secret != "" {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(body, &raw); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		var providedHMAC string
		if hmacRaw, ok := raw["hmac"]; ok {
			_ = json.Unmarshal(hmacRaw, &providedHMAC)
		}
		delete(raw, "hmac")
		cleanBody, _ := json.Marshal(raw)
		if !validateHMAC(h.secret, cleanBody, providedHMAC) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	if h.logger != nil && len(payload.Entries) > 0 {
		h.logger.AddEntries(payload.Entries)
		log.Debug().
			Str("node", payload.NodeID).
			Int("entries", len(payload.Entries)).
			Msg("query log: received entries from slave")
	}

	w.WriteHeader(http.StatusNoContent)
}

// computeHMAC computes HMAC-SHA256 over the data.
func computeHMAC(secret string, data []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(syncEventType + ":"))
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// validateHMAC verifies the HMAC constant-time.
func validateHMAC(secret string, data []byte, provided string) bool {
	expected := computeHMAC(secret, data)
	expectedBytes, _ := hex.DecodeString(expected)
	providedBytes, err := hex.DecodeString(provided)
	if err != nil || len(providedBytes) == 0 {
		return false
	}
	return hmac.Equal(expectedBytes, providedBytes)
}
