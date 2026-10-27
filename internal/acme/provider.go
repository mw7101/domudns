package acme

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"
)

// ACMEStore abstracts ACME challenge storage (PutACMEChallenge, DeleteACMEChallenge).
type ACMEStore interface {
	PutACMEChallenge(ctx context.Context, fqdn, value string, ttl time.Duration) error
	DeleteACMEChallenge(ctx context.Context, fqdn string) error
}

// Provider implements the DNS-01 challenge interface for ACME.
type Provider struct {
	store ACMEStore
	ttl   time.Duration
}

// NewProvider creates a new ACME DNS-01 provider.
func NewProvider(store ACMEStore, ttlSeconds int) *Provider {
	ttl := 60 * time.Second
	if ttlSeconds > 0 {
		ttl = time.Duration(ttlSeconds) * time.Second
	}
	return &Provider{
		store: store,
		ttl:   ttl,
	}
}

// Present creates a TXT record for the ACME DNS-01 challenge.
func (p *Provider) Present(domain, token, keyAuth string) error {
	fqdn := fmt.Sprintf("_acme-challenge.%s", domain)
	value := computeKeyAuth(keyAuth)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return p.store.PutACMEChallenge(ctx, fqdn, value, p.ttl)
}

// CleanUp removes the TXT record after validation.
func (p *Provider) CleanUp(domain, token, keyAuth string) error {
	fqdn := fmt.Sprintf("_acme-challenge.%s", domain)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return p.store.DeleteACMEChallenge(ctx, fqdn)
}

// computeKeyAuth computes the ACME key authorization digest for DNS-01.
func computeKeyAuth(keyAuth string) string {
	h := sha256.Sum256([]byte(keyAuth))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
