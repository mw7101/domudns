package certmanager

import (
	"context"
	"testing"
	"time"
)

type mockACMEChallengeStore struct {
	challenges map[string]string
	deleted    []string
}

func (m *mockACMEChallengeStore) PutACMEChallenge(_ context.Context, fqdn, value string, ttl time.Duration) error {
	if m.challenges == nil {
		m.challenges = make(map[string]string)
	}
	m.challenges[fqdn] = value
	return nil
}

func (m *mockACMEChallengeStore) DeleteACMEChallenge(_ context.Context, fqdn string) error {
	m.deleted = append(m.deleted, fqdn)
	delete(m.challenges, fqdn)
	return nil
}

func TestDNS01Present(t *testing.T) {
	mock := &mockACMEChallengeStore{}
	solver := newDNS01Solver(mock)

	ctx := context.Background()
	if err := solver.present(ctx, "dns.example.com", "token123"); err != nil {
		t.Fatalf("present: %v", err)
	}
	// _acme-challenge.dns.example.com must be set
	if val, ok := mock.challenges["_acme-challenge.dns.example.com"]; !ok || val != "token123" {
		t.Fatalf("expected challenge set, got: %v", mock.challenges)
	}
}

func TestDNS01Cleanup(t *testing.T) {
	mock := &mockACMEChallengeStore{}
	mock.challenges = map[string]string{"_acme-challenge.dns.example.com": "token123"}
	solver := newDNS01Solver(mock)

	ctx := context.Background()
	if err := solver.cleanup(ctx, "dns.example.com"); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if len(mock.challenges) != 0 {
		t.Fatalf("expected challenge deleted, got: %v", mock.challenges)
	}
}
