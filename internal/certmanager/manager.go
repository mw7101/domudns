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
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mw7101/domudns/internal/store"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/acme"
)

const (
	renewalThreshold = 30 * 24 * time.Hour // renew when < 30 days remaining
	checkInterval    = 24 * time.Hour
	maxBackoff       = 24 * time.Hour
	letsEncryptURL   = "https://acme-v02.api.letsencrypt.org/directory"
	letsEncryptStage = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// CertStore is the minimal store interface needed by CertManager.
type CertStore interface {
	GetTLSACMEConfig(ctx context.Context) (*store.TLSACMEConfig, error)
	SetTLSACMEConfig(ctx context.Context, cfg *store.TLSACMEConfig) error
	GetTLSCert(ctx context.Context) (*store.TLSCertPayload, error)
	SetTLSCert(ctx context.Context, payload *store.TLSCertPayload) error
	GetACMEAccountKey(ctx context.Context) (crypto.Signer, error)
	SetACMEAccountKey(ctx context.Context, key crypto.Signer) error
	PutACMEChallenge(ctx context.Context, fqdn, value string, ttl time.Duration) error
	DeleteACMEChallenge(ctx context.Context, fqdn string) error
}

// OnCertRenewed is called after a successful renewal with the new cert payload.
// Used to push the cert to cluster slaves.
type OnCertRenewed func(payload *store.TLSCertPayload)

// CertManager manages Let's Encrypt certificate lifecycle.
// Zero value is valid (no cert, TLS disabled).
// Uses store.TLSCertStatus (defined in internal/store/types.go) to avoid import cycles.
type CertManager struct {
	cert      atomic.Value // stores *tls.Certificate; nil = no cert loaded
	statusMu  sync.RWMutex
	status    store.TLSCertStatus
	store     CertStore
	onRenewed OnCertRenewed
	solver    *dns01Solver
}

// NewCertManager creates a CertManager backed by the given store.
// onRenewed is called after each successful renewal (may be nil).
func NewCertManager(s CertStore, onRenewed OnCertRenewed) *CertManager {
	cm := &CertManager{
		store:     s,
		onRenewed: onRenewed,
		solver:    newDNS01Solver(s),
	}
	return cm
}

// LoadFromDisk loads an existing cert from the store (no ACME call).
// Called on startup and by TLSReloader on slaves.
func (cm *CertManager) LoadFromDisk(ctx context.Context) error {
	payload, err := cm.store.GetTLSCert(ctx)
	if err != nil {
		return fmt.Errorf("certmanager: load cert: %w", err)
	}
	if payload == nil {
		return nil // no cert yet, that's ok
	}
	return cm.storeCert(payload.CertPEM, payload.KeyPEM)
}

// GetCertificate implements tls.Config.GetCertificate.
// Returns an error if no certificate is loaded yet.
func (cm *CertManager) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	val := cm.cert.Load()
	if val == nil {
		return nil, errors.New("certmanager: no TLS certificate loaded")
	}
	return val.(*tls.Certificate), nil
}

// Status returns the current certificate status.
func (cm *CertManager) Status() store.TLSCertStatus {
	cm.statusMu.RLock()
	defer cm.statusMu.RUnlock()
	return cm.status
}

// TriggerRenewal forces an immediate renewal attempt (async).
func (cm *CertManager) TriggerRenewal(ctx context.Context) {
	go cm.tryRenew(ctx)
}

// Start loads the existing cert, checks if renewal is needed immediately,
// then starts the 24h renewal loop. Blocks until ctx is cancelled.
func (cm *CertManager) Start(ctx context.Context) {
	if err := cm.LoadFromDisk(ctx); err != nil {
		log.Warn().Err(err).Msg("certmanager: failed to load cert from disk")
	}

	// Startup check: renew immediately if needed (async — does not block the ticker loop)
	if cm.needsRenewal() {
		go cm.tryRenew(ctx)
	}

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if cm.needsRenewal() {
				go cm.tryRenew(ctx)
			}
		}
	}
}

// needsRenewal returns true if no cert is loaded or the cert expires within renewalThreshold.
func (cm *CertManager) needsRenewal() bool {
	val := cm.cert.Load()
	if val == nil {
		return true
	}
	cert := val.(*tls.Certificate)
	if len(cert.Certificate) == 0 {
		return true
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return true
	}
	return time.Until(leaf.NotAfter) < renewalThreshold
}

// storeCert parses PEM cert+key and atomically stores the *tls.Certificate.
// SECURITY: keyPEM must never appear in log output at any log level.
func (cm *CertManager) storeCert(certPEM, keyPEM string) error {
	tlsCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return fmt.Errorf("certmanager: parse cert/key: %w", err)
	}
	cm.cert.Store(&tlsCert)
	// Update status (valid_until from leaf cert)
	if len(tlsCert.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(tlsCert.Certificate[0]); err == nil {
			cm.statusMu.Lock()
			cm.status.ValidUntil = leaf.NotAfter
			cm.status.Domain = leaf.Subject.CommonName
			cm.statusMu.Unlock()
		}
	}
	return nil
}

// tryRenew attempts a certificate renewal with exponential backoff on failure.
func (cm *CertManager) tryRenew(ctx context.Context) {
	backoff := time.Hour
	for {
		err := cm.renew(ctx)
		if err == nil {
			return
		}
		cm.statusMu.Lock()
		cm.status.Error = err.Error()
		cm.statusMu.Unlock()
		log.Warn().Err(err).Dur("backoff", backoff).Msg("certmanager: renewal failed, retrying")
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// renew performs a full ACME DNS-01 certificate renewal.
// SECURITY: the certificate's private key (payload.KeyPEM) must never
// appear in log output — every log line below names only the domain.
func (cm *CertManager) renew(ctx context.Context) error {
	cfg, err := cm.loadEnabledACMEConfig(ctx)
	if err != nil {
		return err
	}

	accountKey, err := cm.getOrCreateAccountKey(ctx)
	if err != nil {
		return err
	}
	client := newACMEClient(accountKey, cfg.Staging)

	if err := registerACMEAccount(ctx, client, cfg.Email); err != nil {
		return err
	}

	certPEM, keyPEM, err := cm.orderCertificate(ctx, client, cfg.Domain)
	if err != nil {
		return err
	}

	payload := &store.TLSCertPayload{CertPEM: certPEM, KeyPEM: keyPEM}
	if err := cm.storeCert(payload.CertPEM, payload.KeyPEM); err != nil {
		return err
	}
	if err := cm.store.SetTLSCert(ctx, payload); err != nil {
		return fmt.Errorf("persist cert: %w", err)
	}

	cm.statusMu.Lock()
	cm.status.LastRenewed = time.Now()
	cm.status.Error = ""
	cm.statusMu.Unlock()

	log.Info().Str("domain", cfg.Domain).Msg("certmanager: certificate renewed")

	// Notify cluster (async push to slaves)
	if cm.onRenewed != nil {
		cm.onRenewed(payload)
	}
	return nil
}

// loadEnabledACMEConfig loads the ACME config and rejects it unless fully
// configured and enabled.
func (cm *CertManager) loadEnabledACMEConfig(ctx context.Context) (*store.TLSACMEConfig, error) {
	cfg, err := cm.store.GetTLSACMEConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("get acme config: %w", err)
	}
	if cfg == nil || !cfg.Enabled || cfg.Domain == "" || cfg.Email == "" {
		return nil, errors.New("acme not configured or disabled")
	}
	return cfg, nil
}

// getOrCreateAccountKey returns the persisted ACME account key, generating
// and storing a new one on first use.
func (cm *CertManager) getOrCreateAccountKey(ctx context.Context) (crypto.Signer, error) {
	accountKey, err := cm.store.GetACMEAccountKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("get account key: %w", err)
	}
	if accountKey != nil {
		return accountKey, nil
	}
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate account key: %w", err)
	}
	if err := cm.store.SetACMEAccountKey(ctx, newKey); err != nil {
		return nil, fmt.Errorf("store account key: %w", err)
	}
	return newKey, nil
}

// newACMEClient builds an ACME client for accountKey, pointed at the
// staging or production Let's Encrypt directory.
func newACMEClient(accountKey crypto.Signer, staging bool) *acme.Client {
	directoryURL := letsEncryptURL
	if staging {
		directoryURL = letsEncryptStage
	}
	return &acme.Client{Key: accountKey, DirectoryURL: directoryURL}
}

// registerACMEAccount registers the ACME account. Registration is
// idempotent — an HTTP 409 Conflict (account already exists) is not an
// error for us.
func registerACMEAccount(ctx context.Context, client *acme.Client, email string) error {
	acctCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	acct := &acme.Account{Contact: []string{"mailto:" + email}}
	if _, err := client.Register(acctCtx, acct, acme.AcceptTOS); err != nil {
		var acmeErr *acme.Error
		if !errors.As(err, &acmeErr) || acmeErr.StatusCode != 409 {
			return fmt.Errorf("acme register: %w", err)
		}
	}
	return nil
}

// orderCertificate runs the DNS-01 order/authorize/finalize flow for domain
// and returns the PEM-encoded certificate chain and private key.
func (cm *CertManager) orderCertificate(ctx context.Context, client *acme.Client, domain string) (certPEM, keyPEM string, err error) {
	orderCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	order, err := client.AuthorizeOrder(orderCtx, acme.DomainIDs(domain))
	if err != nil {
		return "", "", fmt.Errorf("authorize order: %w", err)
	}
	for _, authURL := range order.AuthzURLs {
		if err := cm.solveDNS01(orderCtx, client, authURL, domain); err != nil {
			return "", "", err
		}
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate cert key: %w", err)
	}
	csrTemplate := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, certKey)
	if err != nil {
		return "", "", fmt.Errorf("create csr: %w", err)
	}

	certs, _, err := client.CreateOrderCert(orderCtx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return "", "", fmt.Errorf("create cert: %w", err)
	}

	var certPEMBuf []byte
	for _, c := range certs {
		certPEMBuf = append(certPEMBuf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})...)
	}
	keyDER, _ := x509.MarshalECPrivateKey(certKey)
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return string(certPEMBuf), string(keyPEMBytes), nil
}

// solveDNS01 handles a single DNS-01 authorization.
func (cm *CertManager) solveDNS01(ctx context.Context, client *acme.Client, authURL, domain string) error {
	auth, err := client.GetAuthorization(ctx, authURL)
	if err != nil {
		return fmt.Errorf("get auth: %w", err)
	}
	if auth.Status == "valid" {
		return nil // already authorized
	}

	var chal *acme.Challenge
	for _, c := range auth.Challenges {
		if c.Type == "dns-01" {
			chal = c
			break
		}
	}
	if chal == nil {
		return errors.New("no dns-01 challenge offered")
	}

	keyAuth, err := client.DNS01ChallengeRecord(chal.Token)
	if err != nil {
		return fmt.Errorf("dns01 key auth: %w", err)
	}

	// Place TXT record — defer cleanup in ALL code paths
	if err := cm.solver.present(ctx, domain, keyAuth); err != nil {
		return err
	}
	defer func() {
		// Use context.Background() so cleanup runs even if ctx is cancelled
		if err := cm.solver.cleanup(context.Background(), domain); err != nil {
			log.Warn().Err(err).Str("domain", domain).Msg("certmanager: dns01 cleanup failed")
		}
	}()

	// Accept challenge
	if _, err := client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("accept challenge: %w", err)
	}

	// Wait for authorization
	if _, err := client.WaitAuthorization(ctx, authURL); err != nil {
		return fmt.Errorf("wait authorization: %w", err)
	}
	return nil
}
