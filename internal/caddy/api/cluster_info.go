package api

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/mw7101/domudns/internal/config"
)

// ClusterInfoHandler serves GET /api/cluster.
// Returns the cluster configuration so the frontend can load nodes dynamically.
type ClusterInfoHandler struct {
	cfg *config.Config
}

// NewClusterInfoHandler creates a new ClusterInfoHandler.
func NewClusterInfoHandler(cfg *config.Config) *ClusterInfoHandler {
	return &ClusterInfoHandler{cfg: cfg}
}

// clusterNodeInfo describes a remote node in the cluster.
type clusterNodeInfo struct {
	Label string `json:"label"`
	URL   string `json:"url"`
	IP    string `json:"ip"`
	Role  string `json:"role"`
}

// clusterInfoResponse is the response for GET /api/cluster.
type clusterInfoResponse struct {
	// Role is the role of this node ("master" or "slave").
	Role string `json:"role"`
	// RemoteNodes are all other known nodes (slaves for master, master for slave).
	RemoteNodes []clusterNodeInfo `json:"remote_nodes"`
}

// ServeHTTP implements http.Handler.
func (h *ClusterInfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	resp := clusterInfoResponse{
		Role:        h.cfg.Cluster.Role,
		RemoteNodes: []clusterNodeInfo{},
	}

	switch h.cfg.Cluster.Role {
	case "master":
		for i, slaveURL := range h.cfg.Cluster.Slaves {
			ip := extractNodeIP(slaveURL)
			resp.RemoteNodes = append(resp.RemoteNodes, clusterNodeInfo{
				Label: fmt.Sprintf("Slave %d", i+1),
				URL:   slaveURL,
				IP:    ip,
				Role:  "slave",
			})
		}
	case "slave":
		if h.cfg.Cluster.MasterURL != "" {
			ip := extractNodeIP(h.cfg.Cluster.MasterURL)
			resp.RemoteNodes = append(resp.RemoteNodes, clusterNodeInfo{
				Label: "Master",
				URL:   h.cfg.Cluster.MasterURL,
				IP:    ip,
				Role:  "master",
			})
		}
	}

	writeSuccess(w, resp, http.StatusOK)
}

// extractNodeIP extracts the hostname/IP from a URL.
// Returns the original URL on error.
func extractNodeIP(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Hostname()
}
