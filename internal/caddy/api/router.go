package api

import (
	"net/http"
	"strings"

	"github.com/mw7101/domudns/internal/querylog"
)

// Router routes HTTP requests to handlers.
type Router struct {
	health             *HealthHandler
	metrics            *MetricsHandler
	config             *ConfigHandler
	zones              *ZonesHandler
	records            *RecordsHandler
	acme               *ACMEHandler
	blocklist          *BlocklistHandler
	queryLog           *querylog.Handler
	ddns               *DDNSAPIHandler
	splitHorizon       *SplitHorizonHandler // /api/split-horizon (nil if not configured)
	dhcpHandler        *DHCPHandler         // /api/dhcp/* (nil if not configured)
	apiKeys            *APIKeysHandler      // /api/auth/api-keys (nil if not configured)
	auth               *AuthManager
	setup              *SetupHandler
	authHandler        *AuthHandler
	sessions           *SessionManager
	metricsEnabled     bool
	clusterHandler     http.Handler        // /api/internal/* (nil if no cluster)
	clusterInfoHandler *ClusterInfoHandler // /api/cluster (nil if not configured)
	slaveMode          bool                // true when this node is a slave
	masterURL          string              // master URL for slave error messages
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
	// Login, setup and cluster sync are allowed on slaves too
	return path == "/api/login" ||
		path == "/api/logout" ||
		strings.HasPrefix(path, "/api/setup/") ||
		strings.HasPrefix(path, "/api/internal/")
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

func (r *Router) apiHandler(req *http.Request) http.Handler {
	path := req.URL.Path
	switch {
	case path == "/api/zones" || strings.HasPrefix(path, "/api/zones/"):
		if strings.Contains(path, "/records") {
			return r.records
		}
		return r.zones
	case strings.HasPrefix(path, "/api/acme/dns-01"), strings.HasPrefix(path, "/api/acme/httpreq/"):
		return r.acme
	case path == "/api/config":
		return r.config
	case path == "/api/cluster":
		if r.clusterInfoHandler != nil {
			return r.clusterInfoHandler
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "Cluster not configured")
		})
	case strings.HasPrefix(path, "/api/blocklist"):
		if r.blocklist != nil {
			return r.blocklist
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "Blocklist not configured")
		})
	case path == "/api/query-log" || strings.HasPrefix(path, "/api/query-log/"):
		if r.queryLog != nil {
			return r.queryLog
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "Query log not enabled")
		})
	case strings.HasPrefix(path, "/api/ddns/"):
		if r.ddns != nil {
			return r.ddns
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "DDNS not configured")
		})
	case path == "/api/split-horizon":
		if r.splitHorizon != nil {
			return r.splitHorizon
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "Split-Horizon not configured")
		})
	case strings.HasPrefix(path, "/api/dhcp/"):
		if r.dhcpHandler != nil {
			return r.dhcpHandler
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "DHCP-Lease-Sync not configured")
		})
	default:
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "Unknown endpoint")
		})
	}
}
