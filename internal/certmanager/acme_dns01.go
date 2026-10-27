package certmanager

import (
	"context"
	"fmt"
	"time"
)

// acmeChallengeStore is the minimal interface needed from FileStore for DNS-01.
type acmeChallengeStore interface {
	PutACMEChallenge(ctx context.Context, fqdn, value string, ttl time.Duration) error
	DeleteACMEChallenge(ctx context.Context, fqdn string) error
}

// dns01Solver satisfies the DNS-01 challenge for a domain using the filestore.
type dns01Solver struct {
	store acmeChallengeStore
}

func newDNS01Solver(store acmeChallengeStore) *dns01Solver {
	return &dns01Solver{store: store}
}

// present sets the _acme-challenge.<domain> TXT record.
// The DNS pipeline (Phase 2.9) serves it automatically.
func (s *dns01Solver) present(ctx context.Context, domain, keyAuth string) error {
	fqdn := fmt.Sprintf("_acme-challenge.%s", domain)
	if err := s.store.PutACMEChallenge(ctx, fqdn, keyAuth, 10*time.Minute); err != nil {
		return fmt.Errorf("dns01 present %s: %w", domain, err)
	}
	return nil
}

// cleanup removes the _acme-challenge TXT record.
// Called via defer to ensure cleanup in all code paths (success and error).
func (s *dns01Solver) cleanup(ctx context.Context, domain string) error {
	fqdn := fmt.Sprintf("_acme-challenge.%s", domain)
	if err := s.store.DeleteACMEChallenge(ctx, fqdn); err != nil {
		return fmt.Errorf("dns01 cleanup %s: %w", domain, err)
	}
	return nil
}
