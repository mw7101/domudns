package dnsserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// generateSelfSignedCert erstellt ein temporäres selbst-signiertes TLS-Zertifikat für Tests.
func generateSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	certTmp, err := os.CreateTemp("", "dot-cert-*.pem")
	if err != nil {
		t.Fatalf("CreateTemp cert: %v", err)
	}
	t.Cleanup(func() { os.Remove(certTmp.Name()) })
	if err := pem.Encode(certTmp, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("pem.Encode cert: %v", err)
	}
	certTmp.Close()

	keyTmp, err := os.CreateTemp("", "dot-key-*.pem")
	if err != nil {
		t.Fatalf("CreateTemp key: %v", err)
	}
	t.Cleanup(func() { os.Remove(keyTmp.Name()) })
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	if err := pem.Encode(keyTmp, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}); err != nil {
		t.Fatalf("pem.Encode key: %v", err)
	}
	keyTmp.Close()

	return certTmp.Name(), keyTmp.Name()
}

// TestNewServer_DoT_Disabled prüft, dass kein dotServer erstellt wird, wenn DoT deaktiviert ist.
func TestNewServer_DoT_Disabled(t *testing.T) {
	s := New(Config{
		Listen:   "[::1]:0",
		Upstream: []string{"1.1.1.1"},
	})
	if s.dotServer != nil {
		t.Error("dotServer sollte nil sein wenn DoT deaktiviert")
	}
}

// TestNewServer_DoT_MissingCert prüft, dass kein dotServer erstellt wird, wenn Zertifikat fehlt.
func TestNewServer_DoT_MissingCert(t *testing.T) {
	s := New(Config{
		Listen:     "[::1]:0",
		Upstream:   []string{"1.1.1.1"},
		DoTEnabled: true,
		DoTListen:  "[::1]:0",
		// CertFile/KeyFile leer
	})
	if s.dotServer != nil {
		t.Error("dotServer sollte nil sein wenn CertFile/KeyFile fehlen")
	}
}

// TestNewServer_DoT_InvalidCert prüft, dass kein dotServer erstellt wird, wenn Zertifikat ungültig ist.
func TestNewServer_DoT_InvalidCert(t *testing.T) {
	s := New(Config{
		Listen:      "[::1]:0",
		Upstream:    []string{"1.1.1.1"},
		DoTEnabled:  true,
		DoTListen:   "[::1]:0",
		DoTCertFile: "/nonexistent/cert.pem",
		DoTKeyFile:  "/nonexistent/key.pem",
	})
	if s.dotServer != nil {
		t.Error("dotServer sollte nil sein bei ungültigem Zertifikat")
	}
}

// TestNewServer_DoT_ValidCert prüft, dass dotServer erstellt wird, wenn gültiges Zertifikat vorhanden.
func TestNewServer_DoT_ValidCert(t *testing.T) {
	certFile, keyFile := generateSelfSignedCert(t)

	s := New(Config{
		Listen:      "[::1]:0",
		Upstream:    []string{"1.1.1.1"},
		DoTEnabled:  true,
		DoTListen:   "127.0.0.1:0",
		DoTCertFile: certFile,
		DoTKeyFile:  keyFile,
	})
	if s.dotServer == nil {
		t.Fatal("dotServer sollte erstellt worden sein")
	}
	if s.dotServer.Net != "tcp-tls" {
		t.Errorf("dotServer.Net = %q, wollen tcp-tls", s.dotServer.Net)
	}
	if s.dotServer.TLSConfig == nil {
		t.Error("dotServer.TLSConfig sollte nicht nil sein")
	}
	if len(s.dotServer.TLSConfig.Certificates) == 0 {
		t.Error("dotServer.TLSConfig.Certificates sollte mindestens ein Zertifikat enthalten")
	}
	if s.dotServer.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, wollen TLS 1.2 (%d)", s.dotServer.TLSConfig.MinVersion, tls.VersionTLS12)
	}
}

// TestDoT_QueryEndToEnd startet einen DoT-Server und sendet eine echte DNS-Query.
func TestDoT_QueryEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("End-to-End-Test übersprungen (Short-Modus)")
	}

	certFile, keyFile := generateSelfSignedCert(t)

	s := New(Config{
		Listen:      "127.0.0.1:0",
		Upstream:    []string{"1.1.1.1"},
		DoTEnabled:  true,
		DoTListen:   "127.0.0.1:0",
		DoTCertFile: certFile,
		DoTKeyFile:  keyFile,
	})

	// dotServer auf freiem Port starten
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	s.dotServer.Addr = addr

	// Server in Goroutine starten
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.dotServer.ListenAndServe()
	}()

	// Kurz warten bis Server bereit
	time.Sleep(50 * time.Millisecond)

	// TLS-Client mit InsecureSkipVerify (self-signed Cert)
	tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // Test-Only
	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer conn.Close()

	// DNS-Query senden
	m := new(dns.Msg)
	m.SetQuestion("google.com.", dns.TypeA)
	dnsConn := &dns.Conn{Conn: conn}
	if err := dnsConn.WriteMsg(m); err != nil {
		t.Fatalf("WriteMsg: %v", err)
	}
	resp, err := dnsConn.ReadMsg()
	if err != nil {
		t.Fatalf("ReadMsg: %v", err)
	}
	if resp.Id != m.Id {
		t.Errorf("Response ID = %d, wollen %d", resp.Id, m.Id)
	}

	// Server herunterfahren
	_ = s.dotServer.Shutdown()
}
