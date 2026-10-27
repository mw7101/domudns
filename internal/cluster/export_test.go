package cluster

import "context"

// ComputeHMACForTest exposes computeHMAC for use in external test packages.
func ComputeHMACForTest(secret string, eventType SyncEventType, timestamp int64, nonce string, data []byte) string {
	return computeHMAC(secret, eventType, timestamp, nonce, data)
}

// StatePullEvent exposes statePullEvent for tests.
const StatePullEvent = statePullEvent

// NewNonceForTest exposes newNonce for tests.
func NewNonceForTest() (string, error) {
	return newNonce()
}

// ApplyEventForTest exposes applyEvent for use in external test packages.
func (h *ReceiverHandler) ApplyEventForTest(ctx context.Context, req SyncRequest) error {
	return h.applyEvent(ctx, req)
}
