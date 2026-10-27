package api

import (
	"net/http"
	"strings"

	"github.com/mw7101/domudns/internal/querylog"
)

// Router routes HTTP requests to handlers.
type Router struct {
	health              *HealthHandler
	metrics             *MetricsHandler
	config              *ConfigHandler
	zones               *ZonesHandler
	records             *RecordsHandler
	acme                *ACMEHandler
	blocklist           *BlocklistHandler
	queryLog            *querylog.Handler
	ddns                *DDNSAPIHandler
	splitHorizon        *SplitHorizonHandler // /api/split-horizon (nil if not configured)
	dhcpHandler         *DHCPHandler         // /api/dhcp/* (nil if not configured)
	apiKeys             *APIKeysHandler      // /api/auth/api-keys (nil if not configured)
	auth                *AuthManager
	setup               *SetupHandler
	authHandler         *AuthHandler
	sessions            *SessionManager
	metricsEnabled      bool
	clusterHandler      http.Handler         // /api/internal/* (nil if no cluster)
	clusterInfoHandler  *ClusterInfoHandler  // /api/cluster (nil if not configured)
	importExport        *ImportExportHandler // /api/zones/import, /api/zones/{domain}/export
	cloneHandler        *ZoneCloneHandler    // /api/zones/{domain}/clone
	cacheHandler        *CacheHandler        // /api/cache (nil if cache disabled)
	clientGroupsHandler *ClientGroupsHandler // /api/client-groups
	tlsACMEHandler      *TLSACMEHandler      // /api/tls/acme (nil if not configured)
	pdnsCompatHandler   *PDNSCompatHandler   // /api/v1/servers/* + /api/pdns/* alias (PowerDNS-compat, nil if not configured)
	slaveMode           bool                 // true when this node is a slave
	masterURL           string               // master URL for slave error messages
}

// NewRouter creates a new API router.
func NewRouter(
	health *HealthHandler,
	metrics *MetricsHandler,
	config *ConfigHandler,
	zones *ZonesHandler,
	records *RecordsHandler,
	acme *ACMEHandler,
	blocklist *BlocklistHandler,
	auth *AuthManager,
	setup *SetupHandler,
	authHandler *AuthHandler,
	sessions *SessionManager,
	metricsEnabled bool,
) *Router {
	return &Router{
		health:         health,
		metrics:        metrics,
		config:         config,
		zones:          zones,
		records:        records,
		acme:           acme,
		blocklist:      blocklist,
		auth:           auth,
		setup:          setup,
		authHandler:    authHandler,
		sessions:       sessions,
		metricsEnabled: metricsEnabled,
	}
}

// SetQueryLogHandler sets the query log handler.
func (r *Router) SetQueryLogHandler(h *querylog.Handler) {
	r.queryLog = h
}

// SetDDNSHandler sets the DDNS API handler.
func (r *Router) SetDDNSHandler(h *DDNSAPIHandler) {
	r.ddns = h
}

// SetSplitHorizonHandler sets the split-horizon handler.
func (r *Router) SetSplitHorizonHandler(h *SplitHorizonHandler) {
	r.splitHorizon = h
}

// SetDHCPHandler sets the DHCP lease sync handler.
func (r *Router) SetDHCPHandler(h *DHCPHandler) {
	r.dhcpHandler = h
}

// SetAPIKeysHandler sets the named API keys handler.
func (r *Router) SetAPIKeysHandler(h *APIKeysHandler) {
	r.apiKeys = h
}

// SetClusterHandler sets the cluster handler for /api/internal/*.
func (r *Router) SetClusterHandler(h http.Handler) {
	r.clusterHandler = h
}

// SetClusterInfoHandler sets the handler for GET /api/cluster.
func (r *Router) SetClusterInfoHandler(h *ClusterInfoHandler) {
	r.clusterInfoHandler = h
}

// SetImportExportHandler sets the handler for zone import/export endpoints.
func (r *Router) SetImportExportHandler(h *ImportExportHandler) {
	r.importExport = h
}

// SetCloneHandler sets the handler for zone clone endpoint.
func (r *Router) SetCloneHandler(h *ZoneCloneHandler) {
	r.cloneHandler = h
}

// SetCacheHandler sets the handler for /api/cache endpoints.
func (r *Router) SetCacheHandler(h *CacheHandler) {
	r.cacheHandler = h
}

// SetClientGroupsHandler sets the handler for /api/client-groups.
func (r *Router) SetClientGroupsHandler(h *ClientGroupsHandler) {
	r.clientGroupsHandler = h
}

// SetTLSACMEHandler sets the TLS ACME handler.
func (r *Router) SetTLSACMEHandler(h *TLSACMEHandler) {
	r.tlsACMEHandler = h
}

// SetPDNSCompatHandler sets the PowerDNS-compat handler for /api/v1/servers/*
// (canonical) and the legacy /api/pdns/* alias.
func (r *Router) SetPDNSCompatHandler(h *PDNSCompatHandler) {
	r.pdnsCompatHandler = h
}

// SetSlaveMode enables read-only mode for this node.
// All mutating API requests are rejected with HTTP 403.
func (r *Router) SetSlaveMode(masterURL string) {
	r.slaveMode = true
	r.masterURL = masterURL
}

// isMutatingMethod returns true for HTTP methods that write data.
func isMutatingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// isReadOnlyAllowed returns true for paths that are allowed to be mutating on slaves as well.
func isReadOnlyAllowed(path string) bool {
	// Login, setup and cluster sync are allowed on slaves too.
	// Cache flush/delete is local-only (not cluster-propagated), so allowed on slaves.
	return path == "/api/login" ||
		path == "/api/logout" ||
		strings.HasPrefix(path, "/api/setup/") ||
		strings.HasPrefix(path, "/api/internal/") ||
		path == "/api/cache" ||
		strings.HasPrefix(path, "/api/cache/")
}

// ServeHTTP implements http.Handler.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	path := req.URL.Path

	// Cluster-internal routes (no auth, HMAC-secured by ReceiverHandler)
	if r.clusterHandler != nil && strings.HasPrefix(path, "/api/internal/") {
		r.clusterHandler.ServeHTTP(w, req)
		return
	}

	// Slave protection: reject mutating requests (except Auth/Setup/Internal)
	if r.slaveMode && isMutatingMethod(req.Method) && !isReadOnlyAllowed(path) {
		writeError(w, http.StatusForbidden, "SLAVE_READ_ONLY",
			"This node is read-only. Please use the master node to make changes.")
		return
	}

	// Public routes without auth
	switch {
	case path == "/api/login" && req.Method == http.MethodPost:
		LoginHandler(r.auth, r.sessions)(w, req)
		return
	case path == "/api/logout":
		LogoutHandler(r.sessions)(w, req)
		return
	case path == "/api/health" || strings.HasPrefix(path, "/api/health/"):
		r.health.ServeHTTP(w, req)
		return
	case path == "/api/setup/status" || strings.HasPrefix(path, "/api/setup/"):
		r.setup.ServeHTTP(w, req)
		return
	}

	// Protected routes
	var handler http.Handler
	if r.metricsEnabled && r.metrics != nil && (path == "/api/metrics" || strings.HasPrefix(path, "/api/metrics/")) {
		handler = r.metrics
	} else if r.apiKeys != nil && (path == "/api/auth/api-keys" || strings.HasPrefix(path, "/api/auth/api-keys/")) {
		handler = r.apiKeys
	} else if strings.HasPrefix(path, "/api/auth/") {
		handler = r.authHandler
	} else {
		handler = r.apiHandler(req)
	}

	AuthMiddleware(r.auth, r.sessions, handler).ServeHTTP(w, req)
}

// apiHandler picks the /api/* handler for req. Optional features that
// aren't configured on this node fall back to a 404 via their own
// *OrNotConfigured method rather than a nested nil check here, keeping this
// switch a flat list of routes.
func (r *Router) apiHandler(req *http.Request) http.Handler {
	path := req.URL.Path
	switch {
	case path == "/api/zones" || strings.HasPrefix(path, "/api/zones/"):
		return r.zonesHandler(path)
	case strings.HasPrefix(path, "/api/acme/dns-01"), strings.HasPrefix(path, "/api/acme/httpreq/"):
		return r.acme
	case path == "/api/config":
		return r.config
	case path == "/api/cluster":
		return r.clusterHandlerOrNotConfigured()
	case strings.HasPrefix(path, "/api/blocklist"):
		return r.blocklistHandlerOrNotConfigured()
	case path == "/api/query-log" || strings.HasPrefix(path, "/api/query-log/"):
		return r.queryLogHandlerOrNotConfigured()
	case strings.HasPrefix(path, "/api/ddns/"):
		return r.ddnsHandlerOrNotConfigured()
	case path == "/api/split-horizon":
		return r.splitHorizonHandlerOrNotConfigured()
	case strings.HasPrefix(path, "/api/dhcp/"):
		return r.dhcpHandlerOrNotConfigured()
	case path == "/api/cache" || strings.HasPrefix(path, "/api/cache/"):
		return r.cacheHandlerOrNotConfigured()
	case path == "/api/client-groups":
		return r.clientGroupsHandlerOrNotConfigured()
	case strings.HasPrefix(path, "/api/tls/"):
		return r.tlsACMEHandlerOrNotConfigured()
	case strings.HasPrefix(path, "/api/v1/servers/"), strings.HasPrefix(path, "/api/pdns/"):
		return r.pdnsCompatHandlerOrNotConfigured()
	default:
		return notConfiguredHandler("Unknown endpoint")
	}
}

// notConfiguredHandler returns a 404 handler for a feature that isn't
// enabled/configured on this node.
func notConfiguredHandler(msg string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "NOT_FOUND", msg)
	})
}

// zonesHandler picks the zones-family handler for path: records, then
// import/export or clone (both take priority over the general zone
// handler), then the general zone handler.
func (r *Router) zonesHandler(path string) http.Handler {
	if strings.Contains(path, "/records") {
		return r.records
	}
	if r.importExport != nil && (strings.HasSuffix(path, "/export") ||
		path == "/api/zones/import" ||
		path == "/api/zones/import/axfr") {
		return r.importExport
	}
	if r.cloneHandler != nil && strings.HasSuffix(path, "/clone") {
		return r.cloneHandler
	}
	return r.zones
}

// handlerOrNotConfigured returns h as an http.Handler, or a 404 handler with
// msg if h is the zero value of T (nil, for the pointer types every caller
// below passes). T is compared against its zero value at its own static
// type — not after converting to http.Handler — because a nil *FooHandler
// stored in an http.Handler interface value is itself non-nil (the classic
// typed-nil pitfall), which would defeat a plain "h != nil" interface check.
func handlerOrNotConfigured[T comparable](h T, msg string) http.Handler {
	var zero T
	if h == zero {
		return notConfiguredHandler(msg)
	}
	if handler, ok := any(h).(http.Handler); ok {
		return handler
	}
	return notConfiguredHandler(msg)
}

func (r *Router) clusterHandlerOrNotConfigured() http.Handler {
	return handlerOrNotConfigured(r.clusterInfoHandler, "Cluster not configured")
}

func (r *Router) blocklistHandlerOrNotConfigured() http.Handler {
	return handlerOrNotConfigured(r.blocklist, "Blocklist not configured")
}

func (r *Router) queryLogHandlerOrNotConfigured() http.Handler {
	return handlerOrNotConfigured(r.queryLog, "Query log not enabled")
}

func (r *Router) ddnsHandlerOrNotConfigured() http.Handler {
	return handlerOrNotConfigured(r.ddns, "DDNS not configured")
}

func (r *Router) splitHorizonHandlerOrNotConfigured() http.Handler {
	return handlerOrNotConfigured(r.splitHorizon, "Split-Horizon not configured")
}

func (r *Router) dhcpHandlerOrNotConfigured() http.Handler {
	return handlerOrNotConfigured(r.dhcpHandler, "DHCP-Lease-Sync not configured")
}

func (r *Router) cacheHandlerOrNotConfigured() http.Handler {
	return handlerOrNotConfigured(r.cacheHandler, "Cache not enabled")
}

func (r *Router) clientGroupsHandlerOrNotConfigured() http.Handler {
	return handlerOrNotConfigured(r.clientGroupsHandler, "Client groups not configured")
}

func (r *Router) tlsACMEHandlerOrNotConfigured() http.Handler {
	return handlerOrNotConfigured(r.tlsACMEHandler, "TLS/ACME not configured")
}

func (r *Router) pdnsCompatHandlerOrNotConfigured() http.Handler {
	return handlerOrNotConfigured(r.pdnsCompatHandler, "PowerDNS-compat API not configured")
}
