package dnsserver

import "context"

// ACMEChallengeReader provides TXT values for ACME DNS-01 challenges.
// Implemented by *filestore.FileStore.
type ACMEChallengeReader interface {
	GetACMEChallenge(ctx context.Context, fqdn string) (string, bool)
}
