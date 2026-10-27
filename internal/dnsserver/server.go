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
	// RateLimitEnabled enables per-client-IP DNS query rate limiting.
	RateLimitEnabled bool
	// RateLimitDNSQueries is the sustained allowance of queries per minute per
	// client IP (initial burst is the same value). Ignored unless RateLimitEnabled.
	RateLimitDNSQueries int
	// RateLimitExemptNetworks lists CIDRs/bare IPs (e.g. the LAN router that
	// forwards all household queries) that bypass DNS rate limiting entirely.
	RateLimitExemptNetworks []string
	// AllowedNetworks is a client-network allowlist: when non-empty, only
	// queries from these CIDRs/bare IPs are answered; every other client gets
	// REFUSED. Empty (default) allows all clients.
	AllowedNetworks []string
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

	// Per-client-IP DNS query rate limiting (system.rate_limit.dns_queries).
	s.UpdateRateLimit(cfg.RateLimitEnabled, cfg.RateLimitDNSQueries, cfg.RateLimitExemptNetworks)
	// Client-network access control (dnsserver.allowed_networks).
	s.UpdateAccessControl(cfg.AllowedNetworks)

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

	s.dotServer = newDoTServer(cfg, handler)

	return s
}

// newDoTServer builds the DNS-over-TLS server (RFC 7858) when enabled with
// a certificate configured, logging a warning and returning nil otherwise.
func newDoTServer(cfg Config, handler *Handler) *dns.Server {
	if !cfg.DoTEnabled {
		return nil
	}
	if cfg.DoTCertFile == "" || cfg.DoTKeyFile == "" {
		log.Warn().Msg("DoT aktiviert, aber cert_file/key_file fehlen — DoT deaktiviert")
		return nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.DoTCertFile, cfg.DoTKeyFile)
	if err != nil {
		log.Warn().Err(err).Msg("DoT: Zertifikat konnte nicht geladen werden — DoT deaktiviert")
		return nil
	}
	return &dns.Server{
		Addr:    cfg.DoTListen,
		Net:     "tcp-tls",
		Handler: handler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		MsgAcceptFunc: ddnsMsgAcceptFunc,
	}
}

// GetHandler returns the internal DNS handler (for DoH integration).
func (s *Server) GetHandler() *Handler { return s.handler }

// SetSplitHorizonResolver sets the split-horizon resolver (nil = disabled).
func (s *Server) SetSplitHorizonResolver(r *SplitHorizonResolver) {
	s.handler.SetSplitHorizonResolver(r)
}

// SetClientGroupResolver sets the client group resolver on the DNS handler.
func (s *Server) SetClientGroupResolver(r *ClientGroupResolver) {
	s.handler.SetClientGroupResolver(r)
}

// SetAXFRHandler sets the AXFR/IXFR handler (nil = disabled).
func (s *Server) SetAXFRHandler(a *AXFRHandler) {
	s.handler.SetAXFRHandler(a)
}

// SetACMEChallengeReader sets the ACME challenge reader (nil = disabled).
func (s *Server) SetACMEChallengeReader(r ACMEChallengeReader) {
	s.handler.SetACMEChallengeReader(r)
}

// UpdateRateLimit enables/disables per-client-IP DNS query rate limiting and
// sets the sustained queries-per-minute allowance. Applies live without restart.
func (s *Server) UpdateRateLimit(enabled bool, queriesPerMinute int, exemptNetworks []string) {
	if !enabled {
		s.handler.SetRateLimiter(nil)
		log.Info().Msg("DNS query rate limiting disabled")
		return
	}
	lim := NewQueryRateLimiter(queriesPerMinute, exemptNetworks)
	if lim == nil {
		s.handler.SetRateLimiter(nil)
		log.Warn().Msg("rate_limit.enabled is true but dns_queries <= 0 — DNS rate limiting disabled")
		return
	}
	s.handler.SetRateLimiter(lim)
	log.Info().Int("queries_per_minute", queriesPerMinute).Msg("DNS query rate limiting enabled")
}

// UpdateAccessControl replaces the client-network allowlist for DNS queries.
// Empty (default) allows every client. Applies live without restart.
func (s *Server) UpdateAccessControl(allowedNetworks []string) {
	nets := parseNetworks(allowedNetworks, "dnsserver.allowed_networks")
	s.handler.SetAccessControl(nets)
	if len(nets) > 0 {
		log.Info().Int("networks", len(nets)).Msg("DNS access control enabled (allowed_networks)")
	} else {
		log.Debug().Msg("DNS access control disabled (all clients allowed)")
	}
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

// GetCache returns the CacheManager, or nil if cache is disabled.
func (s *Server) GetCache() *CacheManager {
	return s.cache
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

// LoadBlocklist loads blocklist domains and whitelist IPs from the store.
func (s *Server) LoadBlocklist(ctx context.Context, store BlocklistProvider) error {
	return s.blocklist.Load(ctx, store)
}

// ReloadWhitelist reloads only whitelist IPs (lightweight cluster sync).
func (s *Server) ReloadWhitelist(ctx context.Context, store BlocklistProvider) error {
	return s.blocklist.ReloadWhitelist(ctx, store)
}

// ApplyBlocklistURLDomains updates the in-memory blocklist for a single URL without disk I/O.
// Called by the cluster receiver after an EventURLDomains sync event.
func (s *Server) ApplyBlocklistURLDomains(urlID int, category string, domains []string) {
	s.blocklist.ApplyURLDomains(urlID, category, domains)
}

// LoadZones loads authoritative zones from the store.
func (s *Server) LoadZones(ctx context.Context, store ZoneProvider) error {
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

	s.startListener(&wg, errChan, "udp", "udp", s.udpServer)
	s.startListener(&wg, errChan, "tcp", "tcp", s.tcpServer)
	if s.dotServer != nil {
		s.startListener(&wg, errChan, "tcp-tls", "dot", s.dotServer)
	}

	go s.shutdownOnDone(ctx)

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

// startListener runs srv.ListenAndServe() in a goroutine tracked by wg,
// logging under logProto and, on failure, sending an error labeled
// errLabel to errChan.
func (s *Server) startListener(wg *sync.WaitGroup, errChan chan<- error, logProto, errLabel string, srv *dns.Server) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info().Str("proto", logProto).Str("addr", srv.Addr).Msg("DNS server listening")
		if err := srv.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("%s server: %w", errLabel, err)
		}
	}()
}

// shutdownOnDone waits for ctx to be cancelled, then gracefully shuts down
// every listener and stops the cache cleanup loop.
func (s *Server) shutdownOnDone(ctx context.Context) {
	<-ctx.Done()
	log.Info().Msg("shutting down DNS server")

	// Stop cache cleanup loop
	if s.cache != nil {
		close(s.cacheStopCh)
	}

	// Stop rate limiter cleanup goroutine
	s.handler.SetRateLimiter(nil)

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
