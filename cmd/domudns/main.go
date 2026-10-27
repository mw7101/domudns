package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/mw7101/domudns/internal/blocklist"
	"github.com/mw7101/domudns/internal/caddy"
	"github.com/mw7101/domudns/internal/caddy/api"
	"github.com/mw7101/domudns/internal/certmanager"
	"github.com/mw7101/domudns/internal/cluster"
	"github.com/mw7101/domudns/internal/config"
	"github.com/mw7101/domudns/internal/dhcp"
	"github.com/mw7101/domudns/internal/dnsserver"
	"github.com/mw7101/domudns/internal/filestore"
	"github.com/mw7101/domudns/internal/querylog"
	"github.com/mw7101/domudns/pkg/logger"
	"github.com/mw7101/domudns/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
	cfgPath   = flag.String("config", "configs/config.yaml", "Path to configuration file")
)

// main wires up and starts every DomU DNS component, in dependency order:
// file backend -> auth -> DNS server -> feature handlers (DHCP, split-horizon,
// cluster) -> HTTP server -> background loops. Each step is delegated to a
// setupX/buildX/startX helper below so this function reads as the sequence
// of steps rather than their implementation.
func main() {
	flag.Parse()

	cfg := loadConfigOrExit()
	logger.Init(logger.Config{Level: cfg.System.LogLevel, Format: cfg.System.LogFormat})
	log.Info().Str("version", Version).Str("build_time", BuildTime).Msg("starting lightweight dns stack")

	ctx, cancel := setupShutdownContext()
	defer cancel()

	fs, store, propagator, clusterHandler, slaveMode, err := setupFileBackend(ctx, cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to setup file backend")
	}

	registerDefaultBlocklistURLs(ctx, cfg, fs, store)
	applyConfigOverrides(ctx, cfg, fs)

	configStore := &api.FileConfigStore{Store: fs}
	authManager := setupAuthManager(ctx, store)

	regenerateHostsFileAsync(ctx, cfg, store)

	nodeID := resolveNodeID(cfg)
	qLogger := setupQueryLogger(cfg, nodeID)

	dnsServer := setupDNSServer(cfg, qLogger)
	setupAXFR(dnsServer, cfg)
	ddnsHandler := setupDDNSHandler(ctx, store, dnsServer)

	blocklistStore := loadBlocklist(ctx, cfg, dnsServer, store)
	zoneStore := loadZones(ctx, dnsServer, store)
	wireACMEChallengeReader(dnsServer, store)

	blocklistReloader := buildBlocklistReloader(cfg, dnsServer, blocklistStore)
	zoneReloader := buildZoneReloader(dnsServer, zoneStore)
	wireDDNSZoneReloader(ddnsHandler, zoneReloader)

	dhcpSyncManager := setupDHCPSync(cfg, store, zoneReloader)

	shState := &splitHorizonState{}
	splitHorizonHandler := api.NewSplitHorizonHandler(cfg, configStore, func(newCfg config.SplitHorizonConfig) error {
		return shState.update(dnsServer, newCfg)
	})

	ddnsAPIHandler := api.NewDDNSAPIHandler(store, dnsServer)
	ddnsAPIHandler.SetStatsProvider(&ddnsStatsAdapter{handler: ddnsHandler})

	clientGroupResolver := setupClientGroupResolver(store, dnsServer)
	certMgr := setupCertManager(ctx, store)

	// reloadCallbacks is shared by the master's cluster push receiver and the
	// slave's poll loop — both apply the same reload logic to the same
	// components; only the trigger (push vs. periodic poll) differs.
	// BlocklistURLDomainsUpdater is only ever invoked by the push receiver,
	// so wiring it here too is harmless for the poll loop.
	// GetTSIGKeys/GetClientGroups go through the api.Store interface rather
	// than the concrete FileStore: on a master, store may be a
	// PropagatingStore, but it embeds FileStore and doesn't override these
	// two read methods, so the result is identical either way.
	reloadCallbacks := cluster.ReloadCallbacks{
		ZoneReloader: func() error {
			if zoneReloader != nil {
				return zoneReloader()
			}
			return nil
		},
		BlocklistReloader: func() error {
			if blocklistReloader != nil {
				return blocklistReloader()
			}
			return nil
		},
		BlocklistURLDomainsUpdater: func(urlID int, category string, domains []string) {
			dnsServer.ApplyBlocklistURLDomains(urlID, category, domains)
		},
		AuthReloader: func() error {
			reloadCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return authManager.Reload(reloadCtx)
		},
		DDNSKeyReloader: func() error {
			reloadCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			keys, err := store.GetTSIGKeys(reloadCtx)
			if err != nil {
				return err
			}
			dnsServer.UpdateTSIGKeys(keys)
			return nil
		},
		ClientGroupsReloader: func() error {
			groups, err := store.GetClientGroups(context.Background())
			if err != nil {
				return err
			}
			return clientGroupResolver.Update(groups)
		},
		TLSReloader: func() error {
			return certMgr.LoadFromDisk(context.Background())
		},
	}.WithSharedReloadScheduler()
	if clusterHandler != nil {
		updateClusterCallbacks(clusterHandler, reloadCallbacks)
	}

	wireQueryLogCluster(cfg, qLogger, clusterHandler, nodeID)

	blockMode := cfg.Blocklist.BlockMode
	dnsServer.ApplyConfig(dnsserver.ConfigUpdate{BlockMode: &blockMode})

	if cfg.DNSServer.SplitHorizon.Enabled {
		if err := shState.update(dnsServer, cfg.DNSServer.SplitHorizon); err != nil {
			log.Fatal().Err(err).Msg("split-horizon: invalid CIDR configuration")
		}
		log.Info().Int("views", len(cfg.DNSServer.SplitHorizon.Views)).Msg("Split-Horizon DNS enabled")
	}

	configReloader := buildConfigReloader(dnsServer, shState)
	doHHandler := setupDoH(cfg, dnsServer)
	logProtocolStatus(cfg)
	dhcpAPIHandler, cacheAPIHandler := setupOptionalAPIHandlers(cfg, dhcpSyncManager, dnsServer)

	opts := caddy.ServerOptions{
		ClusterHandler:      clusterHandler,
		SlaveMode:           slaveMode,
		MasterURL:           cfg.Cluster.MasterURL,
		ConfigReloader:      configReloader,
		QueryLogger:         qLogger,
		DoHHandler:          doHHandler,
		DoHPath:             cfg.DNSServer.DoH.Path,
		DDNSAPIHandler:      ddnsAPIHandler,
		SplitHorizonHandler: splitHorizonHandler,
		DHCPHandler:         dhcpAPIHandler,
		CacheHandler:        cacheAPIHandler,
		ClientGroupResolver: clientGroupResolver,
		CertManager:         certMgr,
	}
	httpServer := caddy.NewServerWithOptions(cfg, authManager, store, configStore, blocklistReloader, zoneReloader, opts)

	g, gctx := errgroup.WithContext(ctx)

	go certMgr.Start(gctx)
	startQueryLoggerLoop(g, gctx, qLogger)
	g.Go(func() error { return dnsServer.Start(gctx) })
	startCacheWarmup(gctx, cfg, dnsServer, qLogger)
	startHTTPServer(g, gctx, httpServer)
	startMetricsServer(g, gctx, cfg)
	startMetricsHistoryLoop(g, gctx)
	startBlocklistFetchLoop(g, gctx, cfg, store, fs, dnsServer, blocklistStore, propagator)
	startDHCPSyncLoop(g, gctx, cfg, dhcpSyncManager)
	startSlavePollLoop(g, gctx, cfg, fs, reloadCallbacks)

	if err := g.Wait(); err != nil {
		log.Error().Err(err).Msg("server error")
		os.Exit(1)
	}

	log.Info().Msg("shutdown complete")
}

// loadConfigOrExit loads the YAML config, exiting the process on failure
// (logger isn't initialized yet, so this reports via stderr directly).
func loadConfigOrExit() *config.Config {
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}
	return cfg
}

// setupShutdownContext returns a context that's cancelled on SIGINT/SIGTERM.
func setupShutdownContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Info().Str("signal", sig.String()).Msg("received shutdown signal")
		cancel()
	}()
	return ctx, cancel
}

// registerDefaultBlocklistURLs seeds the configured default blocklist URLs,
// but only on master/standalone (slaves receive URLs via cluster sync) and
// only when the FileStore doesn't have any URLs registered yet.
func registerDefaultBlocklistURLs(ctx context.Context, cfg *config.Config, fs *filestore.FileStore, store api.Store) {
	if !cfg.Blocklist.Enabled || len(cfg.Blocklist.DefaultURLs) == 0 || cfg.Cluster.Role == "slave" {
		return
	}
	existing, err := fs.ListBlocklistURLs(ctx)
	if err != nil || len(existing) != 0 {
		return
	}
	for _, u := range cfg.Blocklist.DefaultURLs {
		if _, err := store.AddBlocklistURL(ctx, u, "", true); err != nil {
			log.Warn().Err(err).Str("url", u).Msg("blocklist: failed to register default URL")
		} else {
			log.Info().Str("url", u).Msg("blocklist: default URL registered")
		}
	}
}

// applyConfigOverrides merges persisted config_overrides.json into cfg
// in-place (see config.MergeOverrides).
func applyConfigOverrides(ctx context.Context, cfg *config.Config, fs *filestore.FileStore) {
	overrides, err := fs.GetConfigOverrides(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("failed to load config overrides, using YAML only")
		return
	}
	if len(overrides) == 0 {
		return
	}
	if err := config.MergeOverrides(cfg, overrides); err != nil {
		log.Warn().Err(err).Msg("failed to merge config overrides")
		return
	}
	log.Info().Msg("config overrides applied")
}

// setupAuthManager initializes the AuthManager and wires the named-API-key
// store needed for ValidateAnyKey. Fatal on initialization failure.
func setupAuthManager(ctx context.Context, store api.Store) *api.AuthManager {
	authManager, err := api.NewAuthManager(ctx, store)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize auth manager")
	}
	authManager.SetNamedKeyStore(store)
	if !authManager.IsSetupCompleted() {
		log.Info().Msg("setup wizard active — open http://<host>/setup to complete initial configuration")
	}
	return authManager
}

// regenerateHostsFileAsync regenerates the external hosts file in the
// background. Non-blocking: the hosts file is for external tools only
// (e.g. dnsmasq) — the in-memory blocklist is loaded separately via
// loadBlocklist. On SD card hardware this can take 30-35s, which would
// block the HTTP server from starting and cause CI health checks to time out.
func regenerateHostsFileAsync(ctx context.Context, cfg *config.Config, store api.Store) {
	if !cfg.Blocklist.Enabled || cfg.Blocklist.FilePath == "" {
		return
	}
	go func() {
		if err := blocklist.RegenerateHostsFile(ctx, store, cfg.Blocklist.FilePath, cfg.Blocklist.BlockIP4, cfg.Blocklist.BlockIP6); err != nil {
			log.Warn().Err(err).Msg("initial blocklist regenerate failed")
		}
	}()
}

// setupQueryLogger builds the QueryLogger from config.
func setupQueryLogger(cfg *config.Config, nodeID string) *querylog.QueryLogger {
	persistPath := cfg.System.QueryLog.PersistPath
	if persistPath == "" && cfg.System.QueryLog.Persist {
		persistPath = cfg.Cluster.DataDir + "/query.log.db"
	}
	qlCfg := querylog.Config{
		Enabled:       cfg.System.QueryLog.Enabled,
		MemoryEntries: cfg.System.QueryLog.MemoryEntries,
		Persist:       cfg.System.QueryLog.Persist,
		PersistPath:   persistPath,
		PersistDays:   cfg.System.QueryLog.PersistDays,
	}
	if d := cfg.System.QueryLog.PushInterval; d != "" {
		if parsed, err := time.ParseDuration(d); err == nil {
			qlCfg.PushInterval = parsed
		}
	}
	return querylog.New(qlCfg, nodeID)
}

// setupDNSServer builds the dnsserver.Config from cfg and constructs the
// DNS server. DoT certificates: own fields, fallback to caddy.tls.*.
func setupDNSServer(cfg *config.Config, qLogger *querylog.QueryLogger) *dnsserver.Server {
	dotCertFile := cfg.DNSServer.DoT.CertFile
	dotKeyFile := cfg.DNSServer.DoT.KeyFile
	if dotCertFile == "" {
		dotCertFile = cfg.Caddy.TLS.CertFile
		dotKeyFile = cfg.Caddy.TLS.KeyFile
	}

	dnsConfig := dnsserver.Config{
		Listen:                       cfg.DNSServer.Listen,
		Upstream:                     cfg.DNSServer.Upstream,
		UDPSize:                      cfg.DNSServer.UDPSize,
		TCPTimeout:                   cfg.DNSServer.TCPTimeout.Duration(),
		BlockIP4:                     cfg.Blocklist.BlockIP4,
		BlockIP6:                     cfg.Blocklist.BlockIP6,
		CacheEnabled:                 cfg.DNSServer.Cache.Enabled,
		CacheMaxSize:                 cfg.DNSServer.Cache.Size,
		CacheTTL:                     time.Duration(cfg.DNSServer.Cache.TTL) * time.Second,
		CacheNegTTL:                  time.Duration(cfg.DNSServer.Cache.NegativeTTL) * time.Second,
		QueryLogger:                  qLogger,
		ConditionalForwards:          toConditionalForwardRules(cfg.DNSServer.ConditionalForwards),
		DoTEnabled:                   cfg.DNSServer.DoT.Enabled,
		DoTListen:                    cfg.DNSServer.DoT.Listen,
		DoTCertFile:                  dotCertFile,
		DoTKeyFile:                   dotKeyFile,
		DNSSECEnabled:                cfg.System.Security.DNSSEC,
		RebindingProtection:          cfg.System.Security.RebindingProtection,
		RebindingProtectionWhitelist: cfg.System.Security.RebindingProtectionWhitelist,
		RateLimitEnabled:             cfg.System.RateLimit.Enabled,
		RateLimitDNSQueries:          cfg.System.RateLimit.DNSQueries,
		RateLimitExemptNetworks:      cfg.System.RateLimit.ExemptNetworks,
		AllowedNetworks:              cfg.DNSServer.AllowedNetworks,
	}
	return dnsserver.New(dnsConfig)
}

// setupAXFR enables the AXFR/IXFR handler (RFC 5936/1995) when configured.
// Fatal if AllowedIPs doesn't parse — an AXFR handler with a broken allowlist
// must not start.
func setupAXFR(dnsServer *dnsserver.Server, cfg *config.Config) {
	if !cfg.DNSServer.AXFR.Enabled {
		return
	}
	axfrHandler, err := dnsserver.NewAXFRHandler(dnsServer.GetZones(), cfg.DNSServer.AXFR.AllowedIPs)
	if err != nil {
		log.Fatal().Err(err).Msg("AXFR: invalid AllowedIPs in configuration")
	}
	dnsServer.SetAXFRHandler(axfrHandler)
	log.Info().Strs("allowed_ips", cfg.DNSServer.AXFR.AllowedIPs).Msg("Zone Transfer (AXFR/IXFR) enabled")
}

// setupDDNSHandler creates the RFC 2136 DDNS handler and loads its TSIG
// keys. Its zoneReloader is wired later via wireDDNSZoneReloader, once the
// zone reloader itself exists.
func setupDDNSHandler(ctx context.Context, store api.Store, dnsServer *dnsserver.Server) *dnsserver.DDNSHandler {
	ddnsHandler := dnsserver.NewDDNSHandler(store, nil)
	if keys, err := store.GetTSIGKeys(ctx); err == nil && len(keys) > 0 {
		ddnsHandler.UpdateKeys(keys)
	}
	dnsServer.SetDDNSHandler(ddnsHandler)
	return ddnsHandler
}

// storeAsBlocklistProvider narrows the api.Store to the concrete FileStore
// that implements dnsserver.BlocklistProvider (both *filestore.FileStore and
// *cluster.PropagatingStore, which embeds one, qualify).
func storeAsBlocklistProvider(store api.Store) dnsserver.BlocklistProvider {
	switch s := store.(type) {
	case *cluster.PropagatingStore:
		return s.FileStore
	case *filestore.FileStore:
		return s
	}
	return nil
}

// loadBlocklist loads the in-memory blocklist from store, when enabled.
func loadBlocklist(ctx context.Context, cfg *config.Config, dnsServer *dnsserver.Server, store api.Store) dnsserver.BlocklistProvider {
	if !cfg.Blocklist.Enabled {
		return nil
	}
	blocklistStore := storeAsBlocklistProvider(store)
	if blocklistStore == nil {
		return nil
	}
	if err := dnsServer.LoadBlocklist(ctx, blocklistStore); err != nil {
		log.Warn().Err(err).Msg("failed to load blocklist, DNS will forward all queries")
	}
	return blocklistStore
}

// loadZones loads authoritative zones from store.
func loadZones(ctx context.Context, dnsServer *dnsserver.Server, store api.Store) dnsserver.ZoneProvider {
	var zoneStore dnsserver.ZoneProvider
	switch s := store.(type) {
	case *cluster.PropagatingStore:
		zoneStore = s.FileStore
	case *filestore.FileStore:
		zoneStore = s
	}
	if zoneStore == nil {
		return nil
	}
	if err := dnsServer.LoadZones(ctx, zoneStore); err != nil {
		log.Warn().Err(err).Msg("failed to load zones, DNS will not serve authoritative zones")
	}
	return zoneStore
}

// wireACMEChallengeReader wires up _acme-challenge.* TXT answering so the
// DNS server can answer ACME DNS-01 challenges directly from the zone store.
func wireACMEChallengeReader(dnsServer *dnsserver.Server, store api.Store) {
	switch s := store.(type) {
	case *cluster.PropagatingStore:
		dnsServer.SetACMEChallengeReader(s.FileStore)
	case *filestore.FileStore:
		dnsServer.SetACMEChallengeReader(s)
	}
}

// buildBlocklistReloader returns a reloader that reloads the in-memory
// blocklist with a bounded timeout, or nil when blocklist reload isn't
// applicable (disabled, or no compatible store).
func buildBlocklistReloader(cfg *config.Config, dnsServer *dnsserver.Server, blocklistStore dnsserver.BlocklistProvider) api.CoreDNSReloader {
	if !cfg.Blocklist.Enabled || blocklistStore == nil {
		return nil
	}
	return func() error {
		reloadCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return dnsServer.LoadBlocklist(reloadCtx, blocklistStore)
	}
}

// buildZoneReloader returns a reloader that reloads authoritative zones with
// a bounded timeout, or nil when there's no compatible zone store.
func buildZoneReloader(dnsServer *dnsserver.Server, zoneStore dnsserver.ZoneProvider) api.ZoneReloader {
	if zoneStore == nil {
		return nil
	}
	return func() error {
		reloadCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return dnsServer.LoadZones(reloadCtx, zoneStore)
	}
}

// wireDDNSZoneReloader hooks the zone reloader into the DDNS handler so an
// RFC 2136 UPDATE triggers an authoritative zone reload.
func wireDDNSZoneReloader(ddnsHandler *dnsserver.DDNSHandler, zoneReloader api.ZoneReloader) {
	if zoneReloader == nil {
		return
	}
	ddnsHandler.SetZoneReloader(func() {
		if err := zoneReloader(); err != nil {
			log.Warn().Err(err).Msg("ddns: zone reload after UPDATE failed")
		}
	})
}

// setupDHCPSync initializes DHCP lease sync — only on master/standalone.
// Fatal on parser or manager initialization failure: a misconfigured lease
// source must not start silently disabled.
func setupDHCPSync(cfg *config.Config, store api.Store, zoneReloader api.ZoneReloader) *dhcp.SyncManager {
	if !cfg.DHCPLeaseSync.Enabled || cfg.Cluster.Role == "slave" {
		return nil
	}
	parser, err := dhcp.NewParser(
		cfg.DHCPLeaseSync.Source,
		cfg.DHCPLeaseSync.SourcePath,
		cfg.DHCPLeaseSync.FritzBoxURL,
		cfg.DHCPLeaseSync.FritzBoxUser,
		cfg.DHCPLeaseSync.FritzBoxPassword,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("DHCP lease sync: parser initialization failed")
	}

	var zoneReloadFn func()
	if zoneReloader != nil {
		zoneReloadFn = func() {
			if err := zoneReloader(); err != nil {
				log.Warn().Err(err).Msg("dhcp sync: Zone-Reload fehlgeschlagen")
			}
		}
	}

	dhcpSyncManager, err := dhcp.NewSyncManager(dhcp.SyncManagerConfig{
		Parser:       parser,
		Store:        store,
		Zone:         cfg.DHCPLeaseSync.Zone,
		ReverseZone:  cfg.DHCPLeaseSync.ReverseZone,
		TTL:          cfg.DHCPLeaseSync.TTL,
		AutoCreate:   cfg.DHCPLeaseSync.AutoCreateZone,
		ZoneReloader: zoneReloadFn,
		DataDir:      cfg.Cluster.DataDir,
		Source:       cfg.DHCPLeaseSync.Source,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("DHCP lease sync: initialization failed")
	}

	log.Info().
		Str("source", cfg.DHCPLeaseSync.Source).
		Str("zone", cfg.DHCPLeaseSync.Zone).
		Msg("DHCP lease sync configured")
	return dhcpSyncManager
}

// splitHorizonState holds the runtime split-horizon resolver, which is
// created lazily (on first enable via the API, or eagerly at startup if
// already enabled in config) and updated concurrently afterwards by the
// config-reload and split-horizon API handlers. mu guards resolver because
// both handlers run on the HTTP server's goroutines.
type splitHorizonState struct {
	mu       sync.Mutex
	resolver *dnsserver.SplitHorizonResolver
}

// get returns the current resolver, or nil if split-horizon was never enabled.
func (s *splitHorizonState) get() *dnsserver.SplitHorizonResolver {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resolver
}

// update applies newCfg, creating the resolver (and wiring it into
// dnsServer) on first enable, or updating the existing one in place.
func (s *splitHorizonState) update(dnsServer *dnsserver.Server, newCfg config.SplitHorizonConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.resolver == nil && newCfg.Enabled {
		views, err := toSplitHorizonViews(newCfg.Views)
		if err != nil {
			return fmt.Errorf("split-horizon: invalid CIDR: %w", err)
		}
		s.resolver = dnsserver.NewSplitHorizonResolver(true, views)
		dnsServer.SetSplitHorizonResolver(s.resolver)
		return nil
	}
	if s.resolver != nil {
		views, err := toSplitHorizonViews(newCfg.Views)
		if err != nil {
			return fmt.Errorf("split-horizon: invalid CIDR: %w", err)
		}
		s.resolver.Update(newCfg.Enabled, views)
	}
	return nil
}

// setupClientGroupResolver creates the ClientGroupResolver — shared by the
// HTTP handler and the DNS server — and loads its initial state.
func setupClientGroupResolver(store api.Store, dnsServer *dnsserver.Server) *dnsserver.ClientGroupResolver {
	clientGroupResolver := dnsserver.NewClientGroupResolver()
	if groups, err := store.GetClientGroups(context.Background()); err != nil {
		log.Warn().Err(err).Msg("client-groups: failed to load at startup, using defaults")
	} else if err := clientGroupResolver.Update(groups); err != nil {
		log.Warn().Err(err).Msg("client-groups: failed to apply at startup")
	} else {
		log.Info().Int("groups", len(groups)).Msg("client-groups: loaded")
	}
	dnsServer.SetClientGroupResolver(clientGroupResolver)
	return clientGroupResolver
}

// setupCertManager creates the Let's Encrypt CertManager (master/standalone
// and slaves alike — slaves receive the certificate via cluster push, hence
// onRenewed=nil: PropagatingStore.SetTLSCert pushes automatically) and
// pre-loads any certificate already on disk synchronously, so the HTTP
// server auto-detects the correct port at construction time: cert on disk ->
// HTTPS :443; no cert yet -> HTTP :80 (switches on next restart after ACME
// provisioning).
func setupCertManager(ctx context.Context, store api.Store) *certmanager.CertManager {
	certMgr := certmanager.NewCertManager(store, nil)
	if err := certMgr.LoadFromDisk(ctx); err != nil {
		log.Warn().Err(err).Msg("certmanager: pre-load cert failed, starting without TLS")
	}
	return certMgr
}

// wireQueryLogCluster wires the query logger into the cluster: a slave
// pushes its entries to the master every PushInterval; the master registers
// a sync handler to receive them.
func wireQueryLogCluster(cfg *config.Config, qLogger *querylog.QueryLogger, clusterHandler http.Handler, nodeID string) {
	if qLogger == nil {
		return
	}
	syncSecret := cfg.Cluster.SyncSecret
	if cfg.Cluster.Role == "slave" && cfg.Cluster.MasterURL != "" {
		qLogger.SetPushFunc(querylog.NewPushFunc(cfg.Cluster.MasterURL, syncSecret, nodeID))
		log.Info().Str("master", cfg.Cluster.MasterURL).Msg("query log: slave push enabled")
	}
	if cfg.Cluster.Role != "slave" && clusterHandler != nil {
		setQueryLogSyncHandler(clusterHandler, querylog.NewSyncHandler(qLogger, syncSecret))
	}
}

// buildConfigReloader returns the live-reload handler for PATCH /api/config:
// upstream, conditional_forwards, block_mode, rebinding, split_horizon, axfr,
// and log_level are all applicable without a restart.
func buildConfigReloader(dnsServer *dnsserver.Server, shState *splitHorizonState) api.ConfigReloader {
	return func(updatedCfg *config.Config) error {
		// Apply upstream, conditional forwards, rebinding and block mode atomically
		// under a single Server.mu to eliminate the race window between individual calls.
		rebindingEnabled := updatedCfg.System.Security.RebindingProtection
		blockMode := updatedCfg.Blocklist.BlockMode
		logLevel := updatedCfg.System.LogLevel
		dnsServer.ApplyConfig(dnsserver.ConfigUpdate{
			Upstream:            updatedCfg.DNSServer.Upstream,
			ConditionalForwards: toConditionalForwardRules(updatedCfg.DNSServer.ConditionalForwards),
			RebindingEnabled:    &rebindingEnabled,
			RebindingWhitelist:  updatedCfg.System.Security.RebindingProtectionWhitelist,
			BlockMode:           &blockMode,
			LogLevel:            &logLevel,
		})
		// DNS query rate limiting live-reload (independent of the atomic group above).
		dnsServer.UpdateRateLimit(updatedCfg.System.RateLimit.Enabled, updatedCfg.System.RateLimit.DNSQueries, updatedCfg.System.RateLimit.ExemptNetworks)
		// Client-network allowlist live-reload (dnsserver.allowed_networks).
		dnsServer.UpdateAccessControl(updatedCfg.DNSServer.AllowedNetworks)

		if localResolver := shState.get(); localResolver != nil {
			views, err := toSplitHorizonViews(updatedCfg.DNSServer.SplitHorizon.Views)
			if err == nil {
				localResolver.Update(updatedCfg.DNSServer.SplitHorizon.Enabled, views)
			}
		}
		// AXFR AllowedIPs live-reload (nur wenn AXFR aktiviert)
		if updatedCfg.DNSServer.AXFR.Enabled {
			if err := dnsServer.UpdateAXFRAllowedIPs(updatedCfg.DNSServer.AXFR.AllowedIPs); err != nil {
				log.Warn().Err(err).Msg("AXFR: failed to update AllowedIPs")
			}
		}
		return nil
	}
}

// setupDoH enables the DoH handler (public, no auth, analogous to port 53
// UDP/TCP) when configured.
func setupDoH(cfg *config.Config, dnsServer *dnsserver.Server) *api.DoHHandler {
	if !cfg.DNSServer.DoH.Enabled {
		return nil
	}
	doHHandler := api.NewDoHHandler(dnsServer.GetHandler(), cfg.DNSServer.DoH.Path)
	log.Info().Str("path", cfg.DNSServer.DoH.Path).Msg("DNS over HTTPS (DoH) enabled")
	return doHHandler
}

// logProtocolStatus logs which optional protocols/protections are active.
// DoT itself is started directly in dnsServer.Start().
func logProtocolStatus(cfg *config.Config) {
	if cfg.DNSServer.DoT.Enabled {
		log.Info().Str("addr", cfg.DNSServer.DoT.Listen).Msg("DNS over TLS (DoT) enabled")
	}
	if cfg.System.Security.DNSSEC {
		log.Info().Msg("DNSSEC AD-flag delegation enabled (stub resolver mode, RFC 4035)")
	}
	if cfg.System.Security.RebindingProtection {
		log.Info().
			Strs("whitelist", cfg.System.Security.RebindingProtectionWhitelist).
			Msg("DNS rebinding protection enabled")
	}
}

// setupOptionalAPIHandlers creates the DHCP and cache management API
// handlers, each only when its underlying feature is active.
func setupOptionalAPIHandlers(cfg *config.Config, dhcpSyncManager *dhcp.SyncManager, dnsServer *dnsserver.Server) (*api.DHCPHandler, *api.CacheHandler) {
	var dhcpAPIHandler *api.DHCPHandler
	if dhcpSyncManager != nil {
		dhcpAPIHandler = api.NewDHCPHandler(dhcpSyncManager)
	}
	var cacheAPIHandler *api.CacheHandler
	if cfg.DNSServer.Cache.Enabled {
		cacheAPIHandler = api.NewCacheHandler(dnsServer.GetCache())
	}
	return dhcpAPIHandler, cacheAPIHandler
}

// startQueryLoggerLoop starts the query logger's background batch-write loop.
func startQueryLoggerLoop(g *errgroup.Group, gctx context.Context, qLogger *querylog.QueryLogger) {
	if qLogger == nil {
		return
	}
	g.Go(func() error {
		qLogger.Run(gctx)
		return nil
	})
}

// startCacheWarmup runs cache warming in the background (does not block
// server startup) unless disabled or the cache itself is off.
func startCacheWarmup(gctx context.Context, cfg *config.Config, dnsServer *dnsserver.Server, qLogger *querylog.QueryLogger) {
	if !cfg.DNSServer.Cache.Enabled || cfg.DNSServer.Cache.WarmupDisabled {
		return
	}
	count := cfg.DNSServer.Cache.WarmupCount
	if count == 0 {
		count = 200
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error().Interface("panic", r).Msg("cache warmup: recovered panic")
			}
		}()
		dnsServer.WarmCache(gctx, qLogger, count)
	}()
}

// startHTTPServer starts the Caddy-embedded HTTP/API server.
func startHTTPServer(g *errgroup.Group, gctx context.Context, httpServer *caddy.Server) {
	g.Go(func() error {
		if err := httpServer.Start(gctx); err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	})
}

// startMetricsServer starts the standalone Prometheus /metrics server, when
// configured with a listen address.
func startMetricsServer(g *errgroup.Group, gctx context.Context, cfg *config.Config) {
	if !cfg.System.Metrics.Enabled || cfg.System.Metrics.Listen == "" {
		return
	}
	metricsAddr := cfg.System.Metrics.Listen
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.HandlerFor(metrics.Registry(), promhttp.HandlerOpts{}))
	metricsServer := &http.Server{
		Addr:         metricsAddr,
		Handler:      metricsMux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	g.Go(func() error {
		log.Info().Str("addr", metricsAddr).Msg("metrics server starting")
		go func() {
			<-gctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = metricsServer.Shutdown(shutdownCtx)
		}()
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	})
}

// startMetricsHistoryLoop records metrics snapshots: a fine buffer (10s,
// 24h) and a coarse buffer (5min, 30d).
func startMetricsHistoryLoop(g *errgroup.Group, gctx context.Context) {
	g.Go(func() error {
		fine := time.NewTicker(10 * time.Second)
		coarse := time.NewTicker(5 * time.Minute)
		defer fine.Stop()
		defer coarse.Stop()
		for {
			select {
			case <-gctx.Done():
				return nil
			case <-fine.C:
				metrics.RecordFineSnapshot()
			case <-coarse.C:
				metrics.RecordCoarseSnapshot()
			}
		}
	})
}

// startBlocklistFetchLoop starts the periodic blocklist-URL fetch loop —
// master/standalone only (not on slave, which receives blocklist state via
// cluster sync).
func startBlocklistFetchLoop(
	g *errgroup.Group,
	gctx context.Context,
	cfg *config.Config,
	store api.Store,
	fs *filestore.FileStore,
	dnsServer *dnsserver.Server,
	blocklistStore dnsserver.BlocklistProvider,
	propagator *cluster.Propagator,
) {
	startFetchLoop := cfg.Blocklist.Enabled && cfg.Blocklist.FilePath != "" && cfg.Cluster.Role != "slave"
	if !startFetchLoop {
		return
	}

	// Use PropagatingStore when available: SetBlocklistURLDomains automatically pushes domains to slaves.
	// On standalone/solo-master: use fs directly.
	var fetchBackend blocklist.FetchStoreBackend
	if ps, ok := store.(*cluster.PropagatingStore); ok {
		fetchBackend = ps
	} else {
		fetchBackend = fs
	}
	fetchStore := &blocklist.FileFetchAdapter{Store: fetchBackend}

	regen := func(c context.Context) {
		_ = blocklist.RegenerateHostsFile(c, store, cfg.Blocklist.FilePath, cfg.Blocklist.BlockIP4, cfg.Blocklist.BlockIP6)
		if blocklistStore != nil {
			if err := dnsServer.LoadBlocklist(c, blocklistStore); err != nil {
				log.Warn().Err(err).Msg("failed to reload in-memory blocklist after fetch")
			}
		}
	}
	// After fetch, propagate URL metadata to slaves (only when cluster-master)
	if propagator != nil {
		origRegen := regen
		regen = func(c context.Context) {
			origRegen(c)
			urls, err := fs.ListBlocklistURLs(c)
			if err == nil {
				propagator.PushAsync(cluster.EventBlocklistURLs, urls)
			}
		}
	}
	g.Go(func() error {
		return blocklist.RunFetchLoop(gctx, fetchStore, cfg.Blocklist.FetchInterval.Duration(), regen)
	})
}

// startDHCPSyncLoop starts the periodic DHCP lease sync loop, when enabled.
func startDHCPSyncLoop(g *errgroup.Group, gctx context.Context, cfg *config.Config, dhcpSyncManager *dhcp.SyncManager) {
	if dhcpSyncManager == nil {
		return
	}
	g.Go(func() error {
		return dhcpSyncManager.Run(gctx, cfg.DHCPLeaseSync.PollInterval.Duration())
	})
}

// startSlavePollLoop starts the slave's fallback poll loop (polls the master
// every PollInterval), when this node is a slave with a configured master.
func startSlavePollLoop(g *errgroup.Group, gctx context.Context, cfg *config.Config, fs *filestore.FileStore, callbacks cluster.ReloadCallbacks) {
	if cfg.Cluster.Role != "slave" || cfg.Cluster.MasterURL == "" {
		return
	}
	g.Go(func() error {
		return cluster.RunPollLoop(gctx, cfg.Cluster.MasterURL, cfg.Cluster.SyncSecret, fs, cfg.Cluster.PollInterval.Duration(), callbacks)
	})
}

// setupFileBackend initializes the file-based backend and optionally the cluster.
func setupFileBackend(ctx context.Context, cfg *config.Config) (*filestore.FileStore, api.Store, *cluster.Propagator, http.Handler, bool, error) {
	fs, err := filestore.NewFileStore(cfg.Cluster.DataDir)
	if err != nil {
		return nil, nil, nil, nil, false, fmt.Errorf("create file store: %w", err)
	}

	log.Info().
		Str("data_dir", cfg.Cluster.DataDir).
		Str("role", cfg.Cluster.Role).
		Msg("file backend initialized")

	receiver := cluster.NewReceiverHandler(fs, cfg.Cluster.SyncSecret, cluster.ReloadCallbacks{})
	clusterHandler := cluster.NewHandler(receiver, fs)

	var propagator *cluster.Propagator
	var store api.Store = fs
	slaveMode := cfg.Cluster.Role == "slave"

	if cfg.Cluster.Role == "master" && len(cfg.Cluster.Slaves) > 0 {
		propagator = cluster.NewPropagator(
			cfg.Cluster.Slaves,
			cfg.Cluster.SyncSecret,
			cfg.Cluster.PushTimeout.Duration(),
		)
		store = cluster.NewPropagatingStore(fs, propagator)
		log.Info().
			Strs("slaves", cfg.Cluster.Slaves).
			Msg("cluster: master mode, propagating changes to slaves")
	} else if cfg.Cluster.Role == "slave" {
		if cfg.Cluster.SyncSecret == "" {
			log.Fatal().Msg("cluster: slave mode requires DOMUDNS_SYNC_SECRET — set it in /etc/domudns/env")
		}
		log.Info().
			Str("master", cfg.Cluster.MasterURL).
			Msg("cluster: slave mode, read-only API")
	}

	return fs, store, propagator, clusterHandler, slaveMode, nil
}

// resolveNodeID determines the node ID for the QueryLogger.
// Prefers the configured listen host, falls back to hostname.
func resolveNodeID(cfg *config.Config) string {
	if host, _, err := net.SplitHostPort(cfg.DNSServer.Listen); err == nil && host != "" && host != "::" && host != "0.0.0.0" {
		return host
	}
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}
	return "unknown"
}

// setQueryLogSyncHandler registers the query log sync handler in the cluster handler.
func setQueryLogSyncHandler(h http.Handler, syncHandler http.Handler) {
	type queryLogSyncer interface {
		SetQueryLogSyncHandler(http.Handler)
	}
	if s, ok := h.(queryLogSyncer); ok {
		s.SetQueryLogSyncHandler(syncHandler)
	}
}

// toSplitHorizonViews converts config.SplitHorizonView → dnsserver.SplitHorizonView (with parsed CIDRs).
func toSplitHorizonViews(cfgViews []config.SplitHorizonView) ([]dnsserver.SplitHorizonView, error) {
	views := make([]dnsserver.SplitHorizonView, 0, len(cfgViews))
	for _, v := range cfgViews {
		nets := make([]*net.IPNet, 0, len(v.Subnets))
		for _, s := range v.Subnets {
			_, ipNet, err := net.ParseCIDR(s)
			if err != nil {
				return nil, fmt.Errorf("view %q: invalid subnet %q: %w", v.Name, s, err)
			}
			nets = append(nets, ipNet)
		}
		views = append(views, dnsserver.SplitHorizonView{
			Name:    v.Name,
			Subnets: nets,
		})
	}
	return views, nil
}

// toConditionalForwardRules converts config.ConditionalForward → dnsserver.ConditionalForwardRule.
func toConditionalForwardRules(cfgs []config.ConditionalForward) []dnsserver.ConditionalForwardRule {
	rules := make([]dnsserver.ConditionalForwardRule, len(cfgs))
	for i, c := range cfgs {
		rules[i] = dnsserver.ConditionalForwardRule{
			Domain:  c.Domain,
			Servers: c.Servers,
		}
	}
	return rules
}

// ddnsStatsAdapter verbindet DDNSHandler-Stats mit dem DDNSAPIHandler (vermeidet Zirkelimport).
type ddnsStatsAdapter struct {
	handler *dnsserver.DDNSHandler
}

func (a *ddnsStatsAdapter) GetDDNSStats() api.DDNSRuntimeStats {
	s := a.handler.GetStats()
	return api.DDNSRuntimeStats{
		TotalUpdates:       s.TotalUpdates,
		LastUpdateAt:       s.LastUpdateAt,
		TotalFailed:        s.TotalFailed,
		LastError:          s.LastError,
		LastErrorAt:        s.LastErrorAt,
		LastRejectedReason: s.LastRejectedReason,
		LastRejectedAt:     s.LastRejectedAt,
	}
}

// updateClusterCallbacks wires reload callbacks with the cluster handler.
func updateClusterCallbacks(h http.Handler, callbacks cluster.ReloadCallbacks) {
	type callbackUpdater interface {
		UpdateCallbacks(cluster.ReloadCallbacks)
	}
	if updater, ok := h.(callbackUpdater); ok {
		updater.UpdateCallbacks(callbacks)
	}
}
