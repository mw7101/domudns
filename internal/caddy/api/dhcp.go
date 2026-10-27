package api

import (
	"net/http"
	"strings"

	"github.com/mw7101/domudns/internal/dhcp"
)

// DHCPHandler stellt REST-Endpoints fuer DHCP-Lease-Sync bereit.
type DHCPHandler struct {
	syncManager *dhcp.SyncManager
}

// NewDHCPHandler erstellt einen neuen DHCPHandler.
func NewDHCPHandler(sm *dhcp.SyncManager) *DHCPHandler {
	return &DHCPHandler{syncManager: sm}
}

// ServeHTTP routet DHCP-API-Requests.
func (h *DHCPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is supported")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/dhcp/")
	path = strings.TrimSuffix(path, "/")

	switch path {
	case "leases":
		h.getLeases(w)
	case "status":
		h.getStatus(w)
	default:
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Unknown DHCP endpoint")
	}
}

func (h *DHCPHandler) getLeases(w http.ResponseWriter) {
	leases := h.syncManager.GetLeases()
	if leases == nil {
		leases = []dhcp.TrackedLease{}
	}
	writeSuccess(w, leases, http.StatusOK)
}

func (h *DHCPHandler) getStatus(w http.ResponseWriter) {
	status := h.syncManager.GetStatus()
	writeSuccess(w, status, http.StatusOK)
}
