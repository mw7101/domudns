package cluster

// ComputeHMACForTest exposes computeHMAC for use in external test packages.
func ComputeHMACForTest(secret string, eventType SyncEventType, timestamp int64, nonce string, data []byte) string {
	return computeHMAC(secret, eventType, timestamp, nonce, data)
}
