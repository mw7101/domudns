package caddy

import (
	"context"
	"embed"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/mw7101/domudns/internal/caddy/api"
	"github.com/mw7101/domudns/internal/config"
	"github.com/mw7101/domudns/internal/querylog"
	"github.com/rs/zerolog/log"
)

//go:embed web/*
var webAssets embed.FS

// Server is the HTTP/API server.
type Server struct {
	config           *config.CaddyConfig
	server           *http.Server
	cancelMiddleware context.CancelFunc // stops background goroutines (rate limiter cleanup)
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
	acmeTTL := cfg.Acme.ChallengeTTL
	if acmeTTL <= 0 {
		acmeTTL = 60
	}

	health := api.NewHealthHandler(store.HealthCheck)
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
	sessions := api.NewSessionManager()
	router := api.NewRouter(
		health, metricsHandler, configHandler, zones, records, acmeHandler, blocklistHandler,
		authManager, setupHandler, authHandler, sessions, metricsEnabled,
	)
	// Register cluster handler
	if opts.ClusterHandler != nil {
		router.SetClusterHandler(opts.ClusterHandler)
	}
	// Register cluster info handler (returns topology info for the frontend)
	router.SetClusterInfoHandler(api.NewClusterInfoHandler(cfg))
	// Enable slave mode
	if opts.SlaveMode {
		router.SetSlaveMode(opts.MasterURL)
	}
	// Register query log handler
	if opts.QueryLogger != nil {
		router.SetQueryLogHandler(querylog.NewHandler(opts.QueryLogger))
	}
	// Register DDNS API handler
	if opts.DDNSAPIHandler != nil {
		router.SetDDNSHandler(opts.DDNSAPIHandler)
	}
	// Register split-horizon handler
	if opts.SplitHorizonHandler != nil {
		router.SetSplitHorizonHandler(opts.SplitHorizonHandler)
	}
	// Register DHCP handler
	if opts.DHCPHandler != nil {
		router.SetDHCPHandler(opts.DHCPHandler)
	}
	// Register named API keys handler
	apiKeysHandler := api.NewAPIKeysHandler(store)
	router.SetAPIKeysHandler(apiKeysHandler)
	// Register zone import/export handler
	router.SetImportExportHandler(api.NewImportExportHandler(store, zoneReload))
	// Register cache handler
	if opts.CacheHandler != nil {
		router.SetCacheHandler(opts.CacheHandler)
	}
	// middlewareCtx is used to stop background goroutines (e.g. rate limiter cleanup) on shutdown.
	// cancelMiddleware is called in Shutdown() to release resources.
	middlewareCtx, cancelMiddleware := context.WithCancel(context.Background())
	var apiHandler http.Handler = router
	if cfg.System.RateLimit.Enabled {
		trustProxy := cfg.Caddy.API.TrustProxy
		apiHandler = api.RateLimitMiddleware(middlewareCtx, apiRateLimit, trustProxy, router)
	}

	var rootHandler http.Handler
	if cfg.Caddy.WebUI.Enabled {
		webFS, _ := fs.Sub(webAssets, "web")
		fileServer := http.FileServer(http.FS(webFS))
		rootHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	} else {
		rootHandler = apiHandler
	}
	mux := http.NewServeMux()
	// Register DoH endpoint directly at the mux (public, no auth, no API prefix).
	// Apply rate limiting to DoH to prevent amplification / DoS attacks.
	if opts.DoHHandler != nil {
		dohPath := opts.DoHPath
		if dohPath == "" {
			dohPath = "/dns-query"
		}
		log.Info().Str("path", dohPath).Msg("DoH server enabled")
		var dohHandler http.Handler = opts.DoHHandler
		if cfg.System.RateLimit.Enabled {
			trustProxy := cfg.Caddy.API.TrustProxy
			dohRateLimit := cfg.System.RateLimit.APIRequests * 3 // more generous than API
			dohHandler = api.RateLimitMiddleware(middlewareCtx, dohRateLimit, trustProxy, opts.DoHHandler)
		}
		mux.Handle(dohPath, dohHandler)
	}
	mux.Handle("/", rootHandler)

	addr := cfg.Caddy.Listen
	if addr == "" {
		// Default: port 80 for HTTP, port 443 only when TLS certificates are configured
		if cfg.Caddy.TLS.CertFile != "" && cfg.Caddy.TLS.KeyFile != "" {
			addr = "0.0.0.0:443"
		} else {
			addr = "0.0.0.0:80"
		}
	}

	handler := api.CORSMiddleware(cfg.Caddy.API.CORSAllowedOrigins, api.MaxBytesMiddleware(mux))

	return &Server{
		config:           &cfg.Caddy,
		cancelMiddleware: cancelMiddleware,
		server: &http.Server{
			Addr:         addr,
			Handler:      handler,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
	}
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
