package caddy

import (
	"context"
	"crypto/tls"
	"embed"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/mw7101/domudns/internal/caddy/api"
	"github.com/mw7101/domudns/internal/config"
	"github.com/mw7101/domudns/internal/dnsserver"
	"github.com/mw7101/domudns/internal/querylog"
	"github.com/mw7101/domudns/internal/store"
	"github.com/rs/zerolog/log"
)

//go:embed web/*
var webAssets embed.FS

// Server is the HTTP/API server.
type Server struct {
	config           *config.CaddyConfig
	server           *http.Server
	cancelMiddleware context.CancelFunc // stops background goroutines (rate limiter cleanup)
	certManager      CertManager        // non-nil when ACME TLS is active
}

// CertManager provides TLS certificates via GetCertificate (nil = use static cert files).
type CertManager interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
	TriggerRenewal(ctx context.Context)
	Status() store.TLSCertStatus
}

// ServerOptions holds optional parameters for NewServer.
type ServerOptions struct {
	// ClusterHandler is the HTTP handler for /api/internal/* (nil if no cluster).
	ClusterHandler http.Handler
	// SlaveMode enables read-only mode (true when this node is a slave).
	SlaveMode bool
	// MasterURL is the URL of the master (only relevant when SlaveMode == true).
	MasterURL string
	// ConfigReloader is called after a successful PATCH /api/config.
	// Enables live-reload without service restart (e.g. upstream DNS, log level).
	ConfigReloader api.ConfigReloader
	// QueryLogger enables GET /api/query-log (nil = disabled).
	QueryLogger *querylog.QueryLogger
	// DoHHandler enables DNS over HTTPS (RFC 8484) on the configured path.
	DoHHandler *api.DoHHandler
	// DoHPath is the HTTP path for DoH (e.g. "/dns-query").
	DoHPath string
	// DDNSAPIHandler enables TSIG key management via the REST API.
	DDNSAPIHandler *api.DDNSAPIHandler
	// SplitHorizonHandler enables GET/PUT /api/split-horizon.
	SplitHorizonHandler *api.SplitHorizonHandler
	// DHCPHandler enables GET /api/dhcp/leases and GET /api/dhcp/status.
	DHCPHandler *api.DHCPHandler
	// CacheHandler enables /api/cache endpoints (nil = cache disabled).
	CacheHandler *api.CacheHandler
	// ClientGroupResolver holds the resolver for client-group policy lookups.
	// If nil, a default (no-op) resolver is created automatically.
	ClientGroupResolver *dnsserver.ClientGroupResolver
	// CertManager provides TLS certificates via GetCertificate (nil = use static cert files).
	CertManager CertManager
}

// NewServer creates a new HTTP server with API and Web UI.
// authManager is created by main.go and used for the auth sync loop.
// corednsReload is an optional callback for whitelist changes.
func NewServer(cfg *config.Config, authManager *api.AuthManager, store api.Store, configStore api.ConfigStore, corednsReload api.CoreDNSReloader, zoneReload api.ZoneReloader) *Server {
	return newServerWithOpts(cfg, authManager, store, configStore, corednsReload, zoneReload, ServerOptions{})
}

// NewServerWithOptions creates an HTTP server with additional cluster options.
func NewServerWithOptions(cfg *config.Config, authManager *api.AuthManager, store api.Store, configStore api.ConfigStore, corednsReload api.CoreDNSReloader, zoneReload api.ZoneReloader, opts ServerOptions) *Server {
	return newServerWithOpts(cfg, authManager, store, configStore, corednsReload, zoneReload, opts)
}

func newServerWithOpts(cfg *config.Config, authManager *api.AuthManager, store api.Store, configStore api.ConfigStore, corednsReload api.CoreDNSReloader, zoneReload api.ZoneReloader, opts ServerOptions) *Server {
	router, apiRateLimit := buildRouter(cfg, authManager, store, configStore, corednsReload, zoneReload, opts)

	// middlewareCtx is used to stop background goroutines (e.g. rate limiter cleanup) on shutdown.
	// cancelMiddleware is called in Shutdown() to release resources.
	middlewareCtx, cancelMiddleware := context.WithCancel(context.Background())
	var apiHandler http.Handler = router
	if cfg.System.RateLimit.Enabled {
		apiHandler = api.RateLimitMiddleware(middlewareCtx, apiRateLimit, cfg.Caddy.API.TrustProxy, router)
	}

	mux := http.NewServeMux()
	registerDoHHandler(mux, cfg, opts, middlewareCtx)
	mux.Handle("/", buildRootHandler(cfg, apiHandler))

	handler := api.CORSMiddleware(cfg.Caddy.API.CORSAllowedOrigins, api.MaxBytesMiddleware(mux))

	srv := &Server{
		config:           &cfg.Caddy,
		cancelMiddleware: cancelMiddleware,
		certManager:      opts.CertManager,
		server: &http.Server{
			Addr:         resolveListenAddr(cfg, opts),
			Handler:      handler,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
	}
	if opts.CertManager != nil {
		srv.server.TLSConfig = &tls.Config{
			GetCertificate: opts.CertManager.GetCertificate,
		}
	}
	return srv
}

// buildRouter wires every API sub-handler into a Router. Returns the
// configured API rate limit alongside the router, since the caller needs
// it for the outer rate-limit middleware too.
func buildRouter(cfg *config.Config, authManager *api.AuthManager, store api.Store, configStore api.ConfigStore, corednsReload api.CoreDNSReloader, zoneReload api.ZoneReloader, opts ServerOptions) (*api.Router, int) {
	acmeTTL := cfg.Acme.ChallengeTTL
	if acmeTTL <= 0 {
		acmeTTL = 60
	}

	health := api.NewHealthHandler(store.HealthCheck)
	if cfg.Cluster.Role == "slave" {
		syncSecret := cfg.Cluster.SyncSecret
		health.SetClusterCheck(func() bool { return syncSecret != "" })
	}
	metricsHandler := api.NewMetricsHandler()
	configHandler := api.NewConfigHandler(cfg, configStore)
	if opts.ConfigReloader != nil {
		configHandler.SetReloader(opts.ConfigReloader)
	}
	zones := api.NewZonesHandler(store, zoneReload)
	records := api.NewRecordsHandler(store, store, zoneReload)
	acmeHandler := api.NewACMEHandler(store, acmeTTL)
	blocklistHandler := api.NewBlocklistHandler(store, cfg, corednsReload)

	setupHandler := api.NewSetupHandler(authManager)
	authHandler := api.NewAuthHandler(authManager)

	metricsEnabled := cfg.System.Metrics.Enabled
	apiRateLimit := cfg.System.RateLimit.APIRequests
	if apiRateLimit <= 0 {
		apiRateLimit = 100
	}
	sessions := api.NewSessionManager(context.Background())
	router := api.NewRouter(
		health, metricsHandler, configHandler, zones, records, acmeHandler, blocklistHandler,
		authManager, setupHandler, authHandler, sessions, metricsEnabled,
	)

	registerOptionalRouterHandlers(router, cfg, store, zoneReload, opts)

	return router, apiRateLimit
}

// registerOptionalRouterHandlers wires the sub-handlers that depend on a
// ServerOptions field (nil/zero = feature disabled or not configured on
// this node), plus the always-on ones that don't need one.
func registerOptionalRouterHandlers(router *api.Router, cfg *config.Config, store api.Store, zoneReload api.ZoneReloader, opts ServerOptions) {
	if opts.ClusterHandler != nil {
		router.SetClusterHandler(opts.ClusterHandler)
	}
	// Cluster info handler returns topology info for the frontend.
	router.SetClusterInfoHandler(api.NewClusterInfoHandler(cfg))
	if opts.SlaveMode {
		router.SetSlaveMode(opts.MasterURL)
	}
	if opts.QueryLogger != nil {
		router.SetQueryLogHandler(querylog.NewHandler(opts.QueryLogger))
	}
	if opts.DDNSAPIHandler != nil {
		router.SetDDNSHandler(opts.DDNSAPIHandler)
	}
	if opts.SplitHorizonHandler != nil {
		router.SetSplitHorizonHandler(opts.SplitHorizonHandler)
	}
	if opts.DHCPHandler != nil {
		router.SetDHCPHandler(opts.DHCPHandler)
	}
	router.SetAPIKeysHandler(api.NewAPIKeysHandler(store))
	router.SetPDNSCompatHandler(api.NewPDNSCompatHandler(store, zoneReload))
	router.SetImportExportHandler(api.NewImportExportHandler(store, zoneReload))
	router.SetCloneHandler(api.NewZoneCloneHandler(store, zoneReload))
	if opts.CacheHandler != nil {
		router.SetCacheHandler(opts.CacheHandler)
	}
	if opts.ClientGroupResolver != nil {
		router.SetClientGroupsHandler(api.NewClientGroupsHandler(store, opts.ClientGroupResolver))
	} else {
		// No resolver provided: the handler uses its own isolated instance.
		// Changes via PUT /api/client-groups will not affect the DNS pipeline
		// in this configuration. Production always passes a non-nil resolver.
		router.SetClientGroupsHandler(api.NewClientGroupsHandler(store, dnsserver.NewClientGroupResolver()))
	}
	if opts.CertManager != nil {
		tlsHandler := api.NewTLSACMEHandler(store, opts.CertManager)
		if opts.SlaveMode {
			tlsHandler.SetSlaveMode(true)
		}
		router.SetTLSACMEHandler(tlsHandler)
	}
}

// buildRootHandler serves the dashboard's static export (Next.js) at "/"
// with an SPA fallback to index.html, delegating "/api/*" to apiHandler.
// When the web UI is disabled, apiHandler serves everything at "/".
func buildRootHandler(cfg *config.Config, apiHandler http.Handler) http.Handler {
	if !cfg.Caddy.WebUI.Enabled {
		return apiHandler
	}

	webFS, _ := fs.Sub(webAssets, "web")
	fileServer := http.FileServer(http.FS(webFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /api/* is handled by the router
		if strings.HasPrefix(r.URL.Path, "/api") {
			apiHandler.ServeHTTP(w, r)
			return
		}

		// SPA fallback for Next.js Static Export (trailingSlash: true):
		// Next.js exports /dashboard/overview/ → dashboard/overview/index.html
		// embed.FS does not know trailing slashes, so explicitly look for index.html.
		p := strings.TrimPrefix(r.URL.Path, "/")

		// Root request: FileServer (GET / → serves index.html without redirect)
		if p == "" {
			fileServer.ServeHTTP(w, r)
			return
		}

		// Directory route (trailing slash): look directly for index.html
		// e.g. dashboard/overview/ → dashboard/overview/index.html
		if strings.HasSuffix(p, "/") {
			indexPath := p + "index.html"
			if data, err := fs.ReadFile(webFS, indexPath); err == nil {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(data)
				return
			}
		}

		// Known resource in FS (file or directory without trailing slash): FileServer
		if _, err := fs.Stat(webFS, p); err == nil {
			fileServer.ServeHTTP(w, r)
			return
		}

		// SPA fallback: path not in FS → serve index.html (Next.js router takes over client-side)
		data, err := fs.ReadFile(webFS, "index.html")
		if err != nil {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})
}

// registerDoHHandler mounts the DoH endpoint directly on mux (public, no
// auth, no API prefix) when configured, rate-limited more generously than
// the API to allow for legitimate query bursts while still bounding
// amplification/DoS risk.
func registerDoHHandler(mux *http.ServeMux, cfg *config.Config, opts ServerOptions, middlewareCtx context.Context) {
	if opts.DoHHandler == nil {
		return
	}
	dohPath := opts.DoHPath
	if dohPath == "" {
		dohPath = "/dns-query"
	}
	log.Info().Str("path", dohPath).Msg("DoH server enabled")
	var dohHandler http.Handler = opts.DoHHandler
	if cfg.System.RateLimit.Enabled {
		dohRateLimit := cfg.System.RateLimit.APIRequests * 3 // more generous than API
		dohHandler = api.RateLimitMiddleware(middlewareCtx, dohRateLimit, cfg.Caddy.API.TrustProxy, opts.DoHHandler)
	}
	mux.Handle(dohPath, dohHandler)
}

// resolveListenAddr returns the configured Caddy listen address, or
// auto-detects HTTPS :443 (TLS ready) vs HTTP :80 otherwise. "TLS ready"
// means static cert files are configured OR the CertManager already has a
// certificate loaded.
func resolveListenAddr(cfg *config.Config, opts ServerOptions) string {
	if cfg.Caddy.Listen != "" {
		return cfg.Caddy.Listen
	}
	tlsReady := cfg.Caddy.TLS.CertFile != "" && cfg.Caddy.TLS.KeyFile != ""
	if !tlsReady && opts.CertManager != nil {
		if _, err := opts.CertManager.GetCertificate(nil); err == nil {
			tlsReady = true
		}
	}
	if tlsReady {
		return "0.0.0.0:443"
	}
	return "0.0.0.0:80"
}

// Start starts the HTTP server. It blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.server.Shutdown(shutdownCtx); err != nil {
			log.Debug().Err(err).Msg("HTTP server shutdown")
		}
	}()
	if s.certManager != nil {
		if _, err := s.certManager.GetCertificate(nil); err == nil {
			// Certificate loaded — start HTTPS (GetCertificate handles hot-reload via atomic.Value)
			log.Info().Str("addr", s.server.Addr).Bool("tls", true).Msg("HTTP server starting (ACME TLS)")
			if err := s.server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				return err
			}
			return nil
		}
		// No certificate yet (ACME pending or not configured) — start HTTP.
		// The server restarts via systemd after the cert is provisioned, activating HTTPS.
		log.Info().Str("addr", s.server.Addr).Bool("tls", false).Msg("HTTP server starting (no TLS cert yet, ACME pending)")
		s.server.TLSConfig = nil
	}
	certFile := s.config.TLS.CertFile
	keyFile := s.config.TLS.KeyFile
	if certFile != "" && keyFile != "" {
		log.Info().Str("addr", s.server.Addr).Bool("tls", true).Msg("HTTP server starting")
		err := s.server.ListenAndServeTLS(certFile, keyFile)
		if err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	}
	log.Info().Str("addr", s.server.Addr).Msg("HTTP server starting (no TLS)")
	err := s.server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Shutdown gracefully stops the server and cancels background middleware goroutines.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.cancelMiddleware != nil {
		s.cancelMiddleware()
	}
	return s.server.Shutdown(ctx)
}
