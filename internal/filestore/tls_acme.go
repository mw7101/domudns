package filestore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/mw7101/domudns/internal/store"
)

// GetTLSACMEConfig reads the ACME config. Returns nil (no error) if not yet stored.
func (s *FileStore) GetTLSACMEConfig(_ context.Context) (*store.TLSACMEConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Use os.ReadFile + json.Unmarshal directly to distinguish "file not found"
	// from parse errors. readJSON silently returns nil on os.IsNotExist which
	// would yield an indistinguishable zero-value struct.
	data, err := os.ReadFile(s.tlsACMEConfigPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read tls_acme config: %w", err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	var cfg store.TLSACMEConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse tls_acme config: %w", err)
	}
	return &cfg, nil
}

// SetTLSACMEConfig stores the ACME config atomically.
func (s *FileStore) SetTLSACMEConfig(_ context.Context, cfg *store.TLSACMEConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return atomicWriteJSON(s.tlsACMEConfigPath(), cfg)
}

// GetTLSCert reads the TLS certificate and private key from disk.
// Returns nil (no error) if no cert is present.
func (s *FileStore) GetTLSCert(_ context.Context) (*store.TLSCertPayload, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	certPEM, err := os.ReadFile(s.tlsCertPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read cert.pem: %w", err)
	}
	keyPEM, err := os.ReadFile(s.tlsKeyPath())
	if err != nil {
		return nil, fmt.Errorf("read key.pem: %w", err)
	}
	return &store.TLSCertPayload{
		CertPEM: string(certPEM),
		KeyPEM:  string(keyPEM),
	}, nil
}

// SetTLSCert writes cert.pem (0644) and key.pem (0600) to the tls directory.
func (s *FileStore) SetTLSCert(_ context.Context, payload *store.TLSCertPayload) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.WriteFile(s.tlsCertPath(), []byte(payload.CertPEM), 0644); err != nil {
		return fmt.Errorf("write cert.pem: %w", err)
	}
	if err := os.WriteFile(s.tlsKeyPath(), []byte(payload.KeyPEM), 0600); err != nil {
		return fmt.Errorf("write key.pem: %w", err)
	}
	return nil
}

// GetACMEAccountKey reads the ACME account key (EC P-256) from disk.
// Returns nil (no error) if not present.
func (s *FileStore) GetACMEAccountKey(_ context.Context) (crypto.Signer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := os.ReadFile(s.acmeAccountKeyPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read acme account key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("acme account key: invalid PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse acme account key: %w", err)
	}
	return key, nil
}

// SetACMEAccountKey writes the ACME account key (EC P-256) to disk with 0600 permissions.
func (s *FileStore) SetACMEAccountKey(_ context.Context, key crypto.Signer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return errors.New("acme account key: expected *ecdsa.PrivateKey")
	}
	der, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		return fmt.Errorf("marshal acme account key: %w", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(s.acmeAccountKeyPath(), pemData, 0600); err != nil {
		return fmt.Errorf("write acme account key: %w", err)
	}
	return nil
}
