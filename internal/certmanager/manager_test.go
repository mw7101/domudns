package certmanager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/mw7101/domudns/internal/store"
)

// generateSelfSignedCert generates a test cert valid for given duration.
func generateSelfSignedCert(t *testing.T, domain string, valid time.Duration) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(valid),
		DNSNames:     []string{domain},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return
}

func TestGetCertificate_NoCert(t *testing.T) {
	cm := &CertManager{}
	// No cert stored — GetCertificate returns error
	_, err := cm.GetCertificate(&tls.ClientHelloInfo{})
	if err == nil {
		t.Fatal("expected error when no cert available")
	}
}

func TestGetCertificate_WithCert(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t, "dns.example.com", 90*24*time.Hour)

	cm := &CertManager{}
	if err := cm.storeCert(certPEM, keyPEM); err != nil {
		t.Fatalf("storeCert: %v", err)
	}
	cert, err := cm.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil cert")
	}
}

func TestNeedsRenewal(t *testing.T) {
	// Cert valid for 29 days → needs renewal
	certPEM, keyPEM := generateSelfSignedCert(t, "dns.example.com", 29*24*time.Hour)
	cm := &CertManager{}
	if err := cm.storeCert(certPEM, keyPEM); err != nil {
		t.Fatalf("storeCert: %v", err)
	}
	if !cm.needsRenewal() {
		t.Fatal("expected needsRenewal=true for 29-day cert")
	}

	// Cert valid for 60 days → no renewal needed
	certPEM2, keyPEM2 := generateSelfSignedCert(t, "dns.example.com", 60*24*time.Hour)
	if err := cm.storeCert(certPEM2, keyPEM2); err != nil {
		t.Fatalf("storeCert: %v", err)
	}
	if cm.needsRenewal() {
		t.Fatal("expected needsRenewal=false for 60-day cert")
	}
}

// Compile-time check: CertStore interface is satisfied by mockCertStore.
var _ CertStore = (*mockCertStore)(nil)

// mockCertStore is a minimal in-memory implementation of CertStore for tests.
type mockCertStore struct {
	cfg        *store.TLSACMEConfig
	cert       *store.TLSCertPayload
	accountKey crypto.Signer
}

func (m *mockCertStore) GetTLSACMEConfig(_ context.Context) (*store.TLSACMEConfig, error) {
	return m.cfg, nil
}
func (m *mockCertStore) SetTLSACMEConfig(_ context.Context, cfg *store.TLSACMEConfig) error {
	m.cfg = cfg
	return nil
}
func (m *mockCertStore) GetTLSCert(_ context.Context) (*store.TLSCertPayload, error) {
	return m.cert, nil
}
func (m *mockCertStore) SetTLSCert(_ context.Context, payload *store.TLSCertPayload) error {
	m.cert = payload
	return nil
}
func (m *mockCertStore) GetACMEAccountKey(_ context.Context) (crypto.Signer, error) {
	return m.accountKey, nil
}
func (m *mockCertStore) SetACMEAccountKey(_ context.Context, key crypto.Signer) error {
	m.accountKey = key
	return nil
}
func (m *mockCertStore) PutACMEChallenge(_ context.Context, fqdn, value string, ttl time.Duration) error {
	return nil
}
func (m *mockCertStore) DeleteACMEChallenge(_ context.Context, fqdn string) error {
	return nil
}
