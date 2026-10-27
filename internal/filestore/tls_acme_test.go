package filestore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/mw7101/domudns/internal/store"
)

func TestTLSACMEConfig(t *testing.T) {
	s, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Not present → returns nil, no error
	cfg, err := s.GetTLSACMEConfig(ctx)
	if err != nil {
		t.Fatalf("GetTLSACMEConfig: %v", err)
	}
	if cfg != nil {
		t.Fatalf("expected nil, got %+v", cfg)
	}

	// Set and get
	want := &store.TLSACMEConfig{Enabled: true, Domain: "dns.example.com", Email: "admin@example.com"}
	if err := s.SetTLSACMEConfig(ctx, want); err != nil {
		t.Fatalf("SetTLSACMEConfig: %v", err)
	}
	got, err := s.GetTLSACMEConfig(ctx)
	if err != nil {
		t.Fatalf("GetTLSACMEConfig after set: %v", err)
	}
	if got.Domain != want.Domain || got.Email != want.Email || !got.Enabled {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestTLSCert(t *testing.T) {
	s, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Not present → returns nil, no error
	payload, err := s.GetTLSCert(ctx)
	if err != nil {
		t.Fatalf("GetTLSCert: %v", err)
	}
	if payload != nil {
		t.Fatalf("expected nil, got %+v", payload)
	}

	// Set and get
	want := &store.TLSCertPayload{CertPEM: "cert-data", KeyPEM: "key-data"}
	if err := s.SetTLSCert(ctx, want); err != nil {
		t.Fatalf("SetTLSCert: %v", err)
	}
	got, err := s.GetTLSCert(ctx)
	if err != nil {
		t.Fatalf("GetTLSCert after set: %v", err)
	}
	if got.CertPEM != want.CertPEM || got.KeyPEM != want.KeyPEM {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestACMEAccountKey(t *testing.T) {
	s, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Not present → returns nil, no error
	key, err := s.GetACMEAccountKey(ctx)
	if err != nil {
		t.Fatalf("GetACMEAccountKey: %v", err)
	}
	if key != nil {
		t.Fatalf("expected nil, got %v", key)
	}

	// Generate, store and retrieve
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetACMEAccountKey(ctx, privKey); err != nil {
		t.Fatalf("SetACMEAccountKey: %v", err)
	}
	got, err := s.GetACMEAccountKey(ctx)
	if err != nil {
		t.Fatalf("GetACMEAccountKey after set: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil key")
	}
	// Check that both keys have same public part
	gotEC, ok := got.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", got)
	}
	if !privKey.PublicKey.Equal(&gotEC.PublicKey) {
		t.Fatal("stored and retrieved key mismatch")
	}
}
