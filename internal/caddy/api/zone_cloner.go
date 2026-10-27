package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/mw7101/domudns/internal/dns"
	"github.com/mw7101/domudns/internal/store"
)

// ZoneCloneHandler handles POST /api/zones/{domain}/clone.
type ZoneCloneHandler struct {
	store      store.ZoneStore
	zoneReload ZoneReloader
}

// NewZoneCloneHandler creates a new ZoneCloneHandler.
func NewZoneCloneHandler(s store.ZoneStore, zoneReload ZoneReloader) *ZoneCloneHandler {
	return &ZoneCloneHandler{store: s, zoneReload: zoneReload}
}

// ServeHTTP handles clone requests: POST /api/zones/{domain}/clone?view={sourceView}
func (h *ZoneCloneHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
		return
	}

	domain, sourceView, ok := parseCloneSource(w, r)
	if !ok {
		return
	}
	req, ok := parseCloneTarget(w, r, domain, sourceView)
	if !ok {
		return
	}

	ctx := r.Context()
	srcZone, ok := h.loadCloneSourceZone(ctx, w, domain, sourceView)
	if !ok {
		return
	}
	if !h.checkCloneTargetFree(ctx, w, req.NewDomain, req.NewView) {
		return
	}

	newZone := cloneZone(srcZone, req.NewDomain, req.NewView)
	if err := h.store.PutZone(ctx, newZone); err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	if h.zoneReload != nil {
		_ = h.zoneReload()
	}
	writeSuccess(w, newZone, http.StatusCreated)
}

// parseCloneSource extracts and validates the source domain/view from the
// URL: POST /api/zones/{domain}/clone?view={sourceView}. Writes the error
// response itself on failure.
func parseCloneSource(w http.ResponseWriter, r *http.Request) (domain, sourceView string, ok bool) {
	path := strings.TrimPrefix(r.URL.Path, "/api/zones/")
	domain = strings.TrimSuffix(path, "/clone")
	if domain == "" || !dns.IsValidDomain(domain) {
		writeError(w, http.StatusBadRequest, "INVALID_ZONE", "Invalid domain name")
		return "", "", false
	}
	sourceView = r.URL.Query().Get("view")
	if sourceView != "" && !isValidViewName(sourceView) {
		writeError(w, http.StatusBadRequest, "INVALID_VIEW", "Invalid view name")
		return "", "", false
	}
	return domain, sourceView, true
}

// cloneTargetRequest is the decoded POST body for a zone clone request.
type cloneTargetRequest struct {
	NewDomain string `json:"new_domain"`
	NewView   string `json:"new_view"`
}

// parseCloneTarget decodes and validates the request body, and rejects a
// clone onto the same domain+view as the source. Writes the error response
// itself on failure.
func parseCloneTarget(w http.ResponseWriter, r *http.Request, sourceDomain, sourceView string) (cloneTargetRequest, bool) {
	var req cloneTargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid JSON body")
		return cloneTargetRequest{}, false
	}
	req.NewDomain = strings.TrimSpace(req.NewDomain)
	if !dns.IsValidDomain(req.NewDomain) {
		writeError(w, http.StatusBadRequest, "INVALID_ZONE", "Invalid new_domain")
		return cloneTargetRequest{}, false
	}
	if req.NewView != "" && !isValidViewName(req.NewView) {
		writeError(w, http.StatusBadRequest, "INVALID_VIEW", "Invalid new_view")
		return cloneTargetRequest{}, false
	}
	if sourceDomain == req.NewDomain && sourceView == req.NewView {
		writeError(w, http.StatusConflict, "ZONE_EXISTS", "Source and target zone are identical")
		return cloneTargetRequest{}, false
	}
	return req, true
}

// loadCloneSourceZone loads the zone to clone, writing the error response
// itself on failure.
func (h *ZoneCloneHandler) loadCloneSourceZone(ctx context.Context, w http.ResponseWriter, domain, view string) (*dns.Zone, bool) {
	var srcZone *dns.Zone
	var err error
	if view != "" {
		srcZone, err = h.store.GetZoneView(ctx, domain, view)
	} else {
		srcZone, err = h.store.GetZone(ctx, domain)
	}
	if errors.Is(err, dns.ErrZoneNotFound) {
		writeError(w, http.StatusNotFound, "ZONE_NOT_FOUND", "Source zone not found")
		return nil, false
	}
	if err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return nil, false
	}
	return srcZone, true
}

// checkCloneTargetFree reports whether newDomain/newView is free to clone
// into, writing the error response itself when it already exists or the
// check itself fails.
func (h *ZoneCloneHandler) checkCloneTargetFree(ctx context.Context, w http.ResponseWriter, newDomain, newView string) bool {
	var existing *dns.Zone
	var err error
	if newView != "" {
		existing, err = h.store.GetZoneView(ctx, newDomain, newView)
	} else {
		existing, err = h.store.GetZone(ctx, newDomain)
	}
	if err == nil && existing != nil {
		writeError(w, http.StatusConflict, "ZONE_EXISTS", "Target zone already exists")
		return false
	}
	if err != nil && !errors.Is(err, dns.ErrZoneNotFound) {
		writeInternalError(w, "DB_ERROR", err)
		return false
	}
	return true
}

// cloneZone deep-copies src into a new zone with the given domain and view.
// Records receive fresh sequential IDs starting at 1.
// SOA is reset so EnsureSOA generates a fresh one for the target domain.
func cloneZone(src *dns.Zone, newDomain, newView string) *dns.Zone {
	// Copy records with fresh sequential IDs starting at 1.
	records := make([]dns.Record, len(src.Records))
	for i, r := range src.Records {
		records[i] = r
		records[i].ID = i + 1
	}

	// Copy nameservers slice to avoid shared backing array.
	var ns []string
	if len(src.Nameservers) > 0 {
		ns = make([]string, len(src.Nameservers))
		copy(ns, src.Nameservers)
	}

	newZone := &dns.Zone{
		Domain:      newDomain,
		View:        newView,
		TTL:         src.TTL,
		TTLOverride: src.TTLOverride,
		Nameservers: ns,
		Records:     records,
		SOA:         nil, // reset: EnsureSOA will generate a fresh SOA for the target domain
	}
	newZone.EnsureSOA()
	return newZone
}
