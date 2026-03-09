package cluster

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// computeHMAC calculates HMAC-SHA256 over the combined bytes of eventType + ":" + data.
func computeHMAC(secret string, eventType SyncEventType, data []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(string(eventType) + ":"))
	_, _ = mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// validateHMAC verifies the HMAC in constant-time (prevents timing attacks).
func validateHMAC(secret string, eventType SyncEventType, data []byte, providedHMAC string) error {
	expected := computeHMAC(secret, eventType, data)
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
