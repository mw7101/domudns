package dnsserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/mw7101/domudns/internal/querylog"
	"github.com/mw7101/domudns/internal/store"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// Server is the custom DNS server
type Server struct {
	listen      string
	upstream    []string
	udpServer   *dns.Server
	tcpServer   *dns.Server
	dotServer   *dns.Server // DNS over TLS (RFC 7858), nil when disabled
	handler     *Handler
	blocklist   *BlocklistManager
	zones       *ZoneManager
	cache       *CacheManager
	cacheStopCh chan struct{}
	mu          sync.Mutex
}

// Config holds DNS server configuration
type Config struct {
	Listen              string
	Upstream            []string
	UDPSize             int
	TCPTimeout          time.Duration
	BlockIP4            string
	BlockIP6            string
	CacheEnabled        bool
	CacheMaxSize        int
	CacheTTL            time.Duration
	CacheNegTTL         time.Duration
	QueryLogger         *querylog.QueryLogger
	ConditionalForwards []ConditionalForwardRule
	// DoT (DNS over TLS, RFC 7858)
	DoTEnabled  bool
	DoTListen   string
	DoTCertFile string
	DoTKeyFile  string
	// DNSSECEnabled enables DNSSEC AD-flag delegation (stub resolver mode, RFC 4035).
	// Set DO-bit on upstream requests, propagate AD-bit from responses.
	DNSSECEnabled bool
	// RebindingProtection blocks upstream responses that resolve external domains to
	// private/RFC1918 IPs. Opt-in, default: false.
	RebindingProtection bool
	// RebindingProtectionWhitelist contains domain suffixes excluded from the check
	// (e.g. "fritz.box", "corp.internal").
	RebindingProtectionWhitelist []string
}

// New creates a new DNS server instance
func New(cfg Config) *Server {
	if cfg.UDPSize == 0 {
		cfg.UDPSize = 4096
	}
	if cfg.TCPTimeout == 0 {
		cfg.TCPTimeout = 5 * time.Second
	}

	blocklist := NewBlocklistManager()
	zones := NewZoneManager()

	var cache *CacheManager
	if cfg.CacheEnabled {
		cache = NewCacheManager(cfg.CacheMaxSize, cfg.CacheTTL, cfg.CacheNegTTL)
	}

	handler := NewHandler(cfg.Upstream, blocklist, zones, cache, cfg.BlockIP4, cfg.BlockIP6, cfg.QueryLogger, cfg.DNSSECEnabled)
	if len(cfg.ConditionalForwards) > 0 {
		handler.conditionalForwarder = NewConditionalForwarder(cfg.ConditionalForwards)
	}
	if cfg.RebindingProtection {
		handler.UpdateRebindingProtection(true, cfg.RebindingProtectionWhitelist)
	}

	s := &Server{
		listen:      cfg.Listen,
		upstream:    cfg.Upstream,
		handler:     handler,
		blocklist:   blocklist,
		zones:       zones,
		cache:       cache,
		cacheStopCh: make(chan struct{}),
	}

	// UDP server
	s.udpServer = &dns.Server{
		Addr:          cfg.Listen,
		Net:           "udp",
		Handler:       handler,
		UDPSize:       cfg.UDPSize,
		MsgAcceptFunc: ddnsMsgAcceptFunc,
	}

	// TCP server
	s.tcpServer = &dns.Server{
		Addr:          cfg.Listen,
		Net:           "tcp",
		Handler:       handler,
		ReadTimeout:   cfg.TCPTimeout,
		WriteTimeout:  cfg.TCPTimeout,
		MsgAcceptFunc: ddnsMsgAcceptFunc,
	}

	// DoT server (DNS over TLS, RFC 7858) — only when enabled + certificate present
	if cfg.DoTEnabled && cfg.DoTCertFile != "" && cfg.DoTKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.DoTCertFile, cfg.DoTKeyFile)
		if err != nil {
			log.Warn().Err(err).Msg("DoT: Zertifikat konnte nicht geladen werden — DoT deaktiviert")
		} else {
			tlsCfg := &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}
			s.dotServer = &dns.Server{
				Addr:          cfg.DoTListen,
				Net:           "tcp-tls",
				Handler:       handler,
				TLSConfig:     tlsCfg,
				MsgAcceptFunc: ddnsMsgAcceptFunc,
			}
		}
	} else if cfg.DoTEnabled {
		log.Warn().Msg("DoT aktiviert, aber cert_file/key_file fehlen — DoT deaktiviert")
	}

	return s
}

// GetHandler returns the internal DNS handler (for DoH integration).
func (s *Server) GetHandler() *Handler { return s.handler }

// SetSplitHorizonResolver sets the split-horizon resolver (nil = disabled).
func (s *Server) SetSplitHorizonResolver(r *SplitHorizonResolver) {
	s.handler.SetSplitHorizonResolver(r)
}

// SetAXFRHandler sets the AXFR/IXFR handler (nil = disabled).
func (s *Server) SetAXFRHandler(a *AXFRHandler) {
	s.handler.SetAXFRHandler(a)
}

// SetACMEChallengeReader sets the ACME challenge reader (nil = disabled).
func (s *Server) SetACMEChallengeReader(r ACMEChallengeReader) {
	s.handler.SetACMEChallengeReader(r)
}

// UpdateAXFRAllowedIPs replaces the allowed AXFR client IPs/CIDRs at runtime.
func (s *Server) UpdateAXFRAllowedIPs(ips []string) error {
	if s.handler.axfr == nil {
		return nil
	}
	return s.handler.axfr.Update(ips)
}

// GetZones returns the ZoneManager (for AXFRHandler wiring).
func (s *Server) GetZones() *ZoneManager {
	return s.zones
}

// UpdateTSIGKeys updates TSIG keys at runtime (implements api.DDNSKeyUpdater).
func (s *Server) UpdateTSIGKeys(keys []store.TSIGKey) {
	if s.handler.ddns != nil {
		s.handler.ddns.UpdateKeys(keys)
	}
}

// SetDDNSHandler sets the RFC 2136 DDNS handler (nil = disabled).
// Also registers a keyUpdater callback so the server can update TsigSecret live.
func (s *Server) SetDDNSHandler(d *DDNSHandler) {
	s.handler.SetDDNSHandler(d)
	if d != nil {
		d.keyUpdater = func(secrets map[string]string) {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.udpServer.TsigSecret = secrets
			s.tcpServer.TsigSecret = secrets
			if s.dotServer != nil {
				s.dotServer.TsigSecret = secrets
			}
		}
		// Set initial secrets (if keys already present)
		initial := d.GetSecrets()
		if len(initial) > 0 {
			s.mu.Lock()
			s.udpServer.TsigSecret = initial
			s.tcpServer.TsigSecret = initial
			if s.dotServer != nil {
				s.dotServer.TsigSecret = initial
			}
			s.mu.Unlock()
		}
	}
}

// UpdateBlockMode sets the block response mode at runtime (no restart needed).
// Valid values: "zero_ip" (default) | "nxdomain"
func (s *Server) UpdateBlockMode(mode string) {
	s.handler.UpdateBlockMode(mode)
}

// UpdateUpstream replaces the upstream DNS servers at runtime (no restart needed).
func (s *Server) UpdateUpstream(upstream []string) {
	s.handler.forwarder.UpdateUpstream(upstream)
}

// UpdateRebindingProtection updates rebinding protection settings at runtime.
func (s *Server) UpdateRebindingProtection(enabled bool, whitelist []string) {
	s.handler.UpdateRebindingProtection(enabled, whitelist)
}

// UpdateConditionalForwards replaces conditional forwarding rules at runtime (no restart needed).
func (s *Server) UpdateConditionalForwards(rules []ConditionalForwardRule) {
	if s.handler.conditionalForwarder == nil {
		if len(rules) > 0 {
			s.handler.conditionalForwarder = NewConditionalForwarder(rules)
		}
		return
	}
	s.handler.conditionalForwarder.UpdateRules(rules)
}

// LoadBlocklist loads blocklist domains and whitelist IPs from the store.
func (s *Server) LoadBlocklist(ctx context.Context, store BlocklistStore) error {
	return s.blocklist.Load(ctx, store)
}

// ReloadWhitelist reloads only whitelist IPs (lightweight cluster sync).
func (s *Server) ReloadWhitelist(ctx context.Context, store BlocklistStore) error {
	return s.blocklist.ReloadWhitelist(ctx, store)
}

// LoadZones loads authoritative zones from the store.
func (s *Server) LoadZones(ctx context.Context, store ZoneStore) error {
	return s.zones.Load(ctx, store)
}

// Start starts the DNS server (UDP and TCP)
func (s *Server) Start(ctx context.Context) error {
	log.Info().Str("addr", s.listen).Msg("starting DNS server")

	// Start cache cleanup loop if cache is enabled
	if s.cache != nil {
		go s.cache.StartCleanupLoop(5*time.Minute, s.cacheStopCh)
		log.Info().Msg("cache cleanup loop started")
	}

	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	// Start UDP server
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info().Str("proto", "udp").Str("addr", s.listen).Msg("DNS server listening")
		if err := s.udpServer.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("udp server: %w", err)
		}
	}()

	// Start TCP server
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info().Str("proto", "tcp").Str("addr", s.listen).Msg("DNS server listening")
		if err := s.tcpServer.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("tcp server: %w", err)
		}
	}()

	// Start DoT server (DNS over TLS, RFC 7858)
	if s.dotServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Info().Str("proto", "tcp-tls").Str("addr", s.dotServer.Addr).Msg("DoT server listening")
			if err := s.dotServer.ListenAndServe(); err != nil {
				errChan <- fmt.Errorf("dot server: %w", err)
			}
		}()
	}

	// Graceful shutdown on context cancel
	go func() {
		<-ctx.Done()
		log.Info().Msg("shutting down DNS server")

		// Stop cache cleanup loop
		if s.cache != nil {
			close(s.cacheStopCh)
		}

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.udpServer.ShutdownContext(shutdownCtx); err != nil {
			log.Error().Err(err).Msg("UDP server shutdown error")
		}
		if err := s.tcpServer.ShutdownContext(shutdownCtx); err != nil {
			log.Error().Err(err).Msg("TCP server shutdown error")
		}
		if s.dotServer != nil {
			if err := s.dotServer.ShutdownContext(shutdownCtx); err != nil {
				log.Error().Err(err).Msg("DoT server shutdown error")
			}
		}
	}()

	// Wait for servers or return first error
	go func() {
		wg.Wait()
		close(errChan)
	}()

	// Return first error or block until shutdown
	select {
	case err := <-errChan:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		return nil
	}

	return nil
}

// ddnsMsgAcceptFunc extends DefaultMsgAcceptFunc to also accept RFC 2136 UPDATE messages.
// miekg/dns DefaultMsgAcceptFunc explicitly rejects OpcodeUpdate with RcodeNotImplemented,
// because the section count semantics differ from regular queries.
// We override this so our DDNSHandler receives UPDATE packets.
func ddnsMsgAcceptFunc(dh dns.Header) dns.MsgAcceptAction {
	// Ignore responses (QR bit set) — same as DefaultMsgAcceptFunc
	if dh.Bits&(1<<15) != 0 {
		return dns.MsgIgnore
	}
	// Accept RFC 2136 UPDATE messages (OpcodeUpdate = 5)
	opcode := int(dh.Bits>>11) & 0xF
	if opcode == dns.OpcodeUpdate {
		return dns.MsgAccept
	}
	return dns.DefaultMsgAcceptFunc(dh)
}
