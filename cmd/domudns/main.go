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

func main() {
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	logger.Init(logger.Config{
		Level:  cfg.System.LogLevel,
		Format: cfg.System.LogFormat,
	})

	log.Info().
		Str("version", Version).
		Str("build_time", BuildTime).
		Msg("starting lightweight dns stack")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Info().Str("signal", sig.String()).Msg("received shutdown signal")
		cancel()
	}()

	// Initialize file backend
	fs, store, propagator, clusterHandler, slaveMode, err := setupFileBackend(ctx, cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to setup file backend")
	}

	// Register default blocklist URLs — only on master/standalone, only when FileStore is empty
	if cfg.Blocklist.Enabled && len(cfg.Blocklist.DefaultURLs) > 0 && cfg.Cluster.Role != "slave" {
		existing, err := fs.ListBlocklistURLs(ctx)
		if err == nil && len(existing) == 0 {
			for _, u := range cfg.Blocklist.DefaultURLs {
				if _, err := store.AddBlocklistURL(ctx, u, true); err != nil {
					log.Warn().Err(err).Str("url", u).Msg("blocklist: failed to register default URL")
				} else {
					log.Info().Str("url", u).Msg("blocklist: default URL registered")
				}
			}
		}
	}

	// Load and apply config overrides
	overrides, err := fs.GetConfigOverrides(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("failed to load config overrides, using YAML only")
	}
	if len(overrides) > 0 {
		if err := config.MergeOverrides(cfg, overrides); err != nil {
			log.Warn().Err(err).Msg("failed to merge config overrides")
		} else {
			log.Info().Msg("config overrides applied")
		}
	}

	// ConfigStore for API
	configStore := &api.FileConfigStore{Store: fs}

	// Initialize AuthManager
	authManager, err := api.NewAuthManager(ctx, store)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize auth manager")
	}

	// Wire named API key store into AuthManager for ValidateAnyKey
	authManager.SetNamedKeyStore(store)

	if !authManager.IsSetupCompleted() {
		log.Info().Msg("setup wizard active — open http://<host>/setup to complete initial configuration")
	}

	if cfg.Blocklist.Enabled && cfg.Blocklist.FilePath != "" {
		if err := blocklist.RegenerateHostsFile(ctx, store, cfg.Blocklist.FilePath, cfg.Blocklist.BlockIP4, cfg.Blocklist.BlockIP6); err != nil {
			log.Warn().Err(err).Msg("initial blocklist regenerate failed")
		}
	}

	// Initialize QueryLogger
	nodeID := resolveNodeID(cfg)
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
	qLogger := querylog.New(qlCfg, nodeID)

	// Initialize DNS server
	// DoT certificates: own fields, fallback to caddy.tls.*
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
	}

	dnsServer := dnsserver.New(dnsConfig)

	// Initialize AXFR handler (RFC 5936/1995) — only when enabled
	if cfg.DNSServer.AXFR.Enabled {
		axfrHandler, err := dnsserver.NewAXFRHandler(dnsServer.GetZones(), cfg.DNSServer.AXFR.AllowedIPs)
		if err != nil {
			log.Fatal().Err(err).Msg("AXFR: invalid AllowedIPs in configuration")
		}
		dnsServer.SetAXFRHandler(axfrHandler)
		log.Info().
			Strs("allowed_ips", cfg.DNSServer.AXFR.AllowedIPs).
			Msg("Zone Transfer (AXFR/IXFR) enabled")
	}

	// Initialize DDNS handler (RFC 2136) — zoneReloader will be set later
	ddnsHandler := dnsserver.NewDDNSHandler(store, nil)
	if keys, err := store.GetTSIGKeys(ctx); err == nil && len(keys) > 0 {
		ddnsHandler.UpdateKeys(keys)
	}
	dnsServer.SetDDNSHandler(ddnsHandler)

	// Load blocklist (FileStore implements BlocklistStore directly)
	var blocklistStore dnsserver.BlocklistStore
	if cfg.Blocklist.Enabled {
		// PropagatingStore or FileStore: both implement BlocklistStore via FileStore
		switch s := store.(type) {
		case *cluster.PropagatingStore:
			blocklistStore = s.FileStore
		case *filestore.FileStore:
			blocklistStore = s
		}
		if blocklistStore != nil {
			if err := dnsServer.LoadBlocklist(ctx, blocklistStore); err != nil {
				log.Warn().Err(err).Msg("failed to load blocklist, DNS will forward all queries")
			}
		}
	}

	// Load authoritative zones
	var zoneStore dnsserver.ZoneStore
	switch s := store.(type) {
	case *cluster.PropagatingStore:
		zoneStore = s.FileStore
	case *filestore.FileStore:
		zoneStore = s
	}
	if zoneStore != nil {
		if err := dnsServer.LoadZones(ctx, zoneStore); err != nil {
			log.Warn().Err(err).Msg("failed to load zones, DNS will not serve authoritative zones")
		}
	}

	// Wire ACME challenge reader so _acme-challenge.* TXT queries are answered directly
	switch s := store.(type) {
	case *cluster.PropagatingStore:
		dnsServer.SetACMEChallengeReader(s.FileStore)
	case *filestore.FileStore:
		dnsServer.SetACMEChallengeReader(s)
	}

	// Reload callbacks
	var blocklistReloader api.CoreDNSReloader
	if cfg.Blocklist.Enabled && blocklistStore != nil {
		capturedStore := blocklistStore
		blocklistReloader = func() error {
			reloadCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return dnsServer.LoadBlocklist(reloadCtx, capturedStore)
		}
	}

	var zoneReloader api.ZoneReloader
	if zoneStore != nil {
		capturedZoneStore := zoneStore
		zoneReloader = func() error {
			reloadCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return dnsServer.LoadZones(reloadCtx, capturedZoneStore)
		}
	}

	// Set DDNS handler zoneReloader now (after definition)
	if zoneReloader != nil {
		ddnsHandler.SetZoneReloader(func() {
			if err := zoneReloader(); err != nil {
				log.Warn().Err(err).Msg("ddns: zone reload after UPDATE failed")
			}
		})
	}

	// Initialize DHCP lease sync — only on master/standalone
	var dhcpSyncManager *dhcp.SyncManager
	if cfg.DHCPLeaseSync.Enabled && cfg.Cluster.Role != "slave" {
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

		dhcpSyncManager, err = dhcp.NewSyncManager(dhcp.SyncManagerConfig{
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
	}

	// splitHorizonResolver is guarded by splitHorizonMu because both
	// splitHorizonUpdater (HTTP handler) and configReloader (HTTP handler)
	// may access it concurrently after server start.
	var splitHorizonMu sync.Mutex
	var splitHorizonResolver *dnsserver.SplitHorizonResolver

	// Split-Horizon-API-Handler
	splitHorizonUpdater := func(newCfg config.SplitHorizonConfig) error {
		splitHorizonMu.Lock()
		defer splitHorizonMu.Unlock()
		if splitHorizonResolver == nil && newCfg.Enabled {
			// Lazy initialization: create resolver when first enabled via API
			views, err := toSplitHorizonViews(newCfg.Views)
			if err != nil {
				return fmt.Errorf("split-horizon: invalid CIDR: %w", err)
			}
			splitHorizonResolver = dnsserver.NewSplitHorizonResolver(true, views)
			dnsServer.SetSplitHorizonResolver(splitHorizonResolver)
			return nil
		}
		if splitHorizonResolver != nil {
			views, err := toSplitHorizonViews(newCfg.Views)
			if err != nil {
				return fmt.Errorf("split-horizon: invalid CIDR: %w", err)
			}
			splitHorizonResolver.Update(newCfg.Enabled, views)
		}
		return nil
	}
	splitHorizonHandler := api.NewSplitHorizonHandler(cfg, configStore, splitHorizonUpdater)

	// DDNS API handler for REST API
	ddnsAPIHandler := api.NewDDNSAPIHandler(store, dnsServer)
	ddnsAPIHandler.SetStatsProvider(&ddnsStatsAdapter{handler: ddnsHandler})

	// Connect cluster handler with reload callbacks
	if clusterHandler != nil {
		updateClusterCallbacks(clusterHandler, cluster.ReloadCallbacks{
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
		})
	}

	// Query-log cluster integration
	if qLogger != nil {
		syncSecret := cfg.Cluster.SyncSecret
		if cfg.Cluster.Role == "slave" && cfg.Cluster.MasterURL != "" {
			// Slave: set PushFunc → sends entries every 30s to master
			qLogger.SetPushFunc(querylog.NewPushFunc(cfg.Cluster.MasterURL, syncSecret, nodeID))
			log.Info().Str("master", cfg.Cluster.MasterURL).Msg("query log: slave push enabled")
		}
		if cfg.Cluster.Role != "slave" && clusterHandler != nil {
			// Master: register SyncHandler for incoming slave pushes
			setQueryLogSyncHandler(clusterHandler, querylog.NewSyncHandler(qLogger, syncSecret))
		}
	}

	// Set initial block mode from config
	dnsServer.UpdateBlockMode(cfg.Blocklist.BlockMode)

	// Initialize split-horizon resolver (nil when disabled)
	if cfg.DNSServer.SplitHorizon.Enabled {
		views, err := toSplitHorizonViews(cfg.DNSServer.SplitHorizon.Views)
		if err != nil {
			log.Fatal().Err(err).Msg("split-horizon: invalid CIDR configuration")
		}
		splitHorizonResolver = dnsserver.NewSplitHorizonResolver(true, views)
		dnsServer.SetSplitHorizonResolver(splitHorizonResolver)
		log.Info().
			Int("views", len(cfg.DNSServer.SplitHorizon.Views)).
			Msg("Split-Horizon DNS enabled")
	}

	// Config live-reload: upstream, conditional_forwards, block_mode, rebinding, split_horizon, axfr + log_level applicable without restart
	configReloader := func(updatedCfg *config.Config) error {
		dnsServer.UpdateUpstream(updatedCfg.DNSServer.Upstream)
		dnsServer.UpdateConditionalForwards(toConditionalForwardRules(updatedCfg.DNSServer.ConditionalForwards))
		dnsServer.UpdateBlockMode(updatedCfg.Blocklist.BlockMode)
		dnsServer.UpdateRebindingProtection(
			updatedCfg.System.Security.RebindingProtection,
			updatedCfg.System.Security.RebindingProtectionWhitelist,
		)
		splitHorizonMu.Lock()
		localResolver := splitHorizonResolver
		splitHorizonMu.Unlock()
		if localResolver != nil {
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
		logger.SetLevel(updatedCfg.System.LogLevel)
		return nil
	}

	// Initialize DoH handler (public, no auth, analogous to port 53 UDP/TCP)
	var doHHandler *api.DoHHandler
	if cfg.DNSServer.DoH.Enabled {
		doHHandler = api.NewDoHHandler(dnsServer.GetHandler(), cfg.DNSServer.DoH.Path)
		log.Info().
			Str("path", cfg.DNSServer.DoH.Path).
			Msg("DNS over HTTPS (DoH) enabled")
	}

	// Log DoT status (server is started directly in dnsServer.Start())
	if cfg.DNSServer.DoT.Enabled {
		log.Info().
			Str("addr", cfg.DNSServer.DoT.Listen).
			Msg("DNS over TLS (DoT) enabled")
	}

	if cfg.System.Security.DNSSEC {
		log.Info().Msg("DNSSEC AD-flag delegation enabled (stub resolver mode, RFC 4035)")
	}
	if cfg.System.Security.RebindingProtection {
		log.Info().
			Strs("whitelist", cfg.System.Security.RebindingProtectionWhitelist).
			Msg("DNS rebinding protection enabled")
	}

	// DHCP API handler
	var dhcpAPIHandler *api.DHCPHandler
	if dhcpSyncManager != nil {
		dhcpAPIHandler = api.NewDHCPHandler(dhcpSyncManager)
	}

	// HTTP Server
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
	}
	httpServer := caddy.NewServerWithOptions(cfg, authManager, store, configStore, blocklistReloader, zoneReloader, opts)

	g, gctx := errgroup.WithContext(ctx)

	// Start QueryLogger
	if qLogger != nil {
		g.Go(func() error {
			qLogger.Run(gctx)
			return nil
		})
	}

	// Start DNS server
	g.Go(func() error {
		return dnsServer.Start(gctx)
	})

	// Cache warming (asynchronous, does not block server startup)
	if cfg.DNSServer.Cache.Enabled && !cfg.DNSServer.Cache.WarmupDisabled {
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

	// Start HTTP server
	g.Go(func() error {
		if err := httpServer.Start(gctx); err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	})

	// Prometheus Metrics Server
	if cfg.System.Metrics.Enabled && cfg.System.Metrics.Listen != "" {
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

	// Metrics history: fine buffer (10s, 24h) + coarse buffer (5min, 30d)
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

	// Blocklist fetch loop — start only on master (not on slave)
	startFetchLoop := cfg.Blocklist.Enabled && cfg.Blocklist.FilePath != "" && cfg.Cluster.Role != "slave"
	if startFetchLoop {
		// Use PropagatingStore when available: SetBlocklistURLDomains automatically pushes domains to slaves.
		// On standalone/solo-master: use fs directly.
		var fetchBackend blocklist.FetchStoreBackend
		if ps, ok := store.(*cluster.PropagatingStore); ok {
			fetchBackend = ps
		} else {
			fetchBackend = fs
		}
		fetchStore := &blocklist.FileFetchAdapter{Store: fetchBackend}
		capturedBlocklistStore := blocklistStore
		regen := func(c context.Context) {
			_ = blocklist.RegenerateHostsFile(c, store, cfg.Blocklist.FilePath, cfg.Blocklist.BlockIP4, cfg.Blocklist.BlockIP6)
			if capturedBlocklistStore != nil {
				if err := dnsServer.LoadBlocklist(c, capturedBlocklistStore); err != nil {
					log.Warn().Err(err).Msg("failed to reload in-memory blocklist after fetch")
				}
			}
		}
		// After fetch, propagate URL metadata to slaves (only when cluster-master)
		if propagator != nil {
			capturedPropagator := propagator
			capturedFS := fs
			origRegen := regen
			regen = func(c context.Context) {
				origRegen(c)
				urls, err := capturedFS.ListBlocklistURLs(c)
				if err == nil {
					capturedPropagator.PushAsync(cluster.EventBlocklistURLs, urls)
				}
			}
		}
		g.Go(func() error {
			return blocklist.RunFetchLoop(gctx, fetchStore, cfg.Blocklist.FetchInterval.Duration(), regen)
		})
	}

	// DHCP lease sync loop — only on master/standalone
	if dhcpSyncManager != nil {
		capturedSyncMgr := dhcpSyncManager
		capturedInterval := cfg.DHCPLeaseSync.PollInterval.Duration()
		g.Go(func() error {
			return capturedSyncMgr.Run(gctx, capturedInterval)
		})
	}

	// Slave poll loop (fallback: poll master every 30s)
	if cfg.Cluster.Role == "slave" && cfg.Cluster.MasterURL != "" {
		capturedFS := fs
		capturedCallbacks := cluster.ReloadCallbacks{
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
			AuthReloader: func() error {
				reloadCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				return authManager.Reload(reloadCtx)
			},
			DDNSKeyReloader: func() error {
				reloadCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				keys, err := fs.GetTSIGKeys(reloadCtx)
				if err != nil {
					return err
				}
				dnsServer.UpdateTSIGKeys(keys)
				return nil
			},
		}
		g.Go(func() error {
			return cluster.RunPollLoop(gctx, cfg.Cluster.MasterURL, capturedFS,
				cfg.Cluster.PollInterval.Duration(), capturedCallbacks)
		})
	}

	if err := g.Wait(); err != nil {
		log.Error().Err(err).Msg("server error")
		os.Exit(1)
	}

	log.Info().Msg("shutdown complete")
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
