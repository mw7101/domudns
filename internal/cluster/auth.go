package cluster

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
)

// computeHMAC calculates HMAC-SHA256 over eventType + ":" + timestamp + ":" + nonce + ":" + data.
// timestamp is Unix nanoseconds; nonce is a 16-byte random hex string.
// Both are bound into the MAC to prevent replay attacks.
func computeHMAC(secret string, eventType SyncEventType, timestamp int64, nonce string, data []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(string(eventType) + ":"))
	_, _ = mac.Write([]byte(strconv.FormatInt(timestamp, 10) + ":"))
	_, _ = mac.Write([]byte(nonce + ":"))
	_, _ = mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// validateHMAC verifies the HMAC in constant-time (prevents timing attacks).
func validateHMAC(secret string, eventType SyncEventType, timestamp int64, nonce string, data []byte, providedHMAC string) error {
	expected := computeHMAC(secret, eventType, timestamp, nonce, data)
	providedBytes, err := hex.DecodeString(providedHMAC)
	if err != nil {
		return fmt.Errorf("invalid hmac format")
	}
	expectedBytes, err := hex.DecodeString(expected)
	if err != nil {
		// Should never happen, since computeHMAC always returns valid hex.EncodeToString output.
		return fmt.Errorf("internal hmac encoding error")
	}
	if !hmac.Equal(expectedBytes, providedBytes) {
		return fmt.Errorf("hmac mismatch")
	}
	return nil
}
