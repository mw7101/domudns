package api

import (
	"context"
	"net"
	"net/http"

	"github.com/mw7101/domudns/internal/dns"
	"github.com/mw7101/domudns/internal/dnsserver"
	"github.com/rs/zerolog/log"
)

// clientGroupStore is the minimal store interface needed by ClientGroupsHandler.
type clientGroupStore interface {
	GetClientGroups(ctx context.Context) ([]*dns.ClientGroup, error)
	SetClientGroups(ctx context.Context, groups []*dns.ClientGroup) error
}

// ClientGroupsHandler handles GET/PUT /api/client-groups.
type ClientGroupsHandler struct {
	store    clientGroupStore
	resolver *dnsserver.ClientGroupResolver
}

// NewClientGroupsHandler creates a new ClientGroupsHandler.
func NewClientGroupsHandler(store clientGroupStore, resolver *dnsserver.ClientGroupResolver) *ClientGroupsHandler {
	return &ClientGroupsHandler{store: store, resolver: resolver}
}

// ServeHTTP routes GET and PUT requests for /api/client-groups.
func (h *ClientGroupsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.get(w, r)
	case http.MethodPut:
		h.put(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Use GET or PUT")
	}
}

func (h *ClientGroupsHandler) get(w http.ResponseWriter, r *http.Request) {
	groups, err := h.store.GetClientGroups(r.Context())
	if err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	if groups == nil {
		groups = []*dns.ClientGroup{}
	}
	writeSuccess(w, groups, http.StatusOK)
}

func (h *ClientGroupsHandler) put(w http.ResponseWriter, r *http.Request) {
	var groups []*dns.ClientGroup
	if err := DecodeJSON(r, &groups, 0); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}
	if groups == nil {
		groups = []*dns.ClientGroup{}
	}

	// Validate: unique names, valid CIDRs, known categories.
	seen := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		if g.Name == "" {
			writeError(w, http.StatusBadRequest, "INVALID_NAME", "Group name must not be empty")
			return
		}
		if _, dup := seen[g.Name]; dup {
			writeError(w, http.StatusBadRequest, "DUPLICATE_NAME", "Duplicate group name: "+g.Name)
			return
		}
		seen[g.Name] = struct{}{}
		for _, cidr := range g.CIDRs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				writeError(w, http.StatusBadRequest, "INVALID_CIDR", "Invalid CIDR in group "+g.Name+": "+cidr)
				return
			}
		}
		for _, cat := range g.Categories {
			if _, ok := dns.ValidCategories[cat]; !ok {
				writeError(w, http.StatusBadRequest, "INVALID_CATEGORY", "Unknown category: "+cat)
				return
			}
		}
	}

	if err := h.store.SetClientGroups(r.Context(), groups); err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}

	// Live-reload the in-memory resolver. CIDRs were already validated above,
	// so this should not fail in practice — log a warning if it does.
	if err := h.resolver.Update(groups); err != nil {
		log.Warn().Err(err).Msg("client-groups: live-reload failed after save")
	}

	log.Info().Int("groups", len(groups)).Msg("client groups updated")
	writeSuccess(w, groups, http.StatusOK)
}
