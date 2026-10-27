package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/mw7101/domudns/internal/blocklist"
	"github.com/mw7101/domudns/internal/config"
	"github.com/mw7101/domudns/internal/dns"
	"github.com/mw7101/domudns/internal/store"
)

const (
	// Resource limits to prevent abuse and OOM on Raspberry Pi
	maxBlocklistURLs     = 100
	maxManualDomains     = 10000
	maxWhitelistIPs      = 1000
	maxBlocklistPatterns = 1000
)

// CoreDNSReloader is called when the DNS server needs to reload its in-memory blocklist
// after whitelist IP changes via the API.
type CoreDNSReloader func() error

// BlocklistHandler handles blocklist API operations.
type BlocklistHandler struct {
	store         store.BlocklistStore
	cfg           *config.Config
	regenCh       chan struct{}
	corednsReload CoreDNSReloader
}

// NewBlocklistHandler creates a blocklist handler.
// The handler starts a background goroutine for debounced hosts file regeneration.
// corednsReload is optional - if provided, it will be called when whitelist IPs change.
func NewBlocklistHandler(store store.BlocklistStore, cfg *config.Config, corednsReload CoreDNSReloader) *BlocklistHandler {
	h := &BlocklistHandler{
		store:         store,
		cfg:           cfg,
		regenCh:       make(chan struct{}, 1), // Buffered channel to avoid blocking
		corednsReload: corednsReload,
	}
	// Start debouncing goroutine
	go h.regenDebounceLoop()
	return h
}

// blocklistRoute matches a request against one path pattern and, if it
// matches, handles it and reports true. A path match with no matching
// method reports false so ServeHTTP falls through to the next route and,
// eventually, the 404 — routes never overlap since each checks a distinct
// resource name in parts[0].
type blocklistRoute func(h *BlocklistHandler, w http.ResponseWriter, r *http.Request, parts []string) bool

// blocklistRoutes lists the /api/blocklist/* routes in the order they're
// tried. Order only matters in that a more specific pattern (e.g. .../fetch)
// must be checked before a less specific one that could also match its
// length — see the parts-length guard in each route.
var blocklistRoutes = []blocklistRoute{
	routeBlocklistURLsCollection,
	routeBlocklistURLsItem,
	routeBlocklistURLsFetch,
	routeBlocklistDomainsCollection,
	routeBlocklistDomainsItem,
	routeBlocklistAllowedCollection,
	routeBlocklistAllowedItem,
	routeBlocklistPatternsCollection,
	routeBlocklistPatternsItem,
	routeBlocklistWhitelistIPsCollection,
	routeBlocklistWhitelistIPsItem,
}

// ServeHTTP routes blocklist requests.
func (h *BlocklistHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/blocklist")
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")

	if !h.cfg.Blocklist.Enabled {
		writeError(w, http.StatusServiceUnavailable, "BLOCKLIST_DISABLED", "Blocklist is disabled")
		return
	}

	for _, route := range blocklistRoutes {
		if route(h, w, r, parts) {
			return
		}
	}

	writeError(w, http.StatusNotFound, "NOT_FOUND", "Unknown blocklist endpoint")
}

// /api/blocklist/urls
func routeBlocklistURLsCollection(h *BlocklistHandler, w http.ResponseWriter, r *http.Request, parts []string) bool {
	if len(parts) != 1 || parts[0] != "urls" {
		return false
	}
	switch r.Method {
	case http.MethodGet:
		h.listURLs(r.Context(), w)
	case http.MethodPost:
		h.addURL(r.Context(), w, r)
	default:
		return false
	}
	return true
}

// /api/blocklist/urls/{id}
func routeBlocklistURLsItem(h *BlocklistHandler, w http.ResponseWriter, r *http.Request, parts []string) bool {
	if len(parts) != 2 || parts[0] != "urls" {
		return false
	}
	id, err := strconv.Atoi(parts[1])
	if err != nil || id < 1 {
		writeError(w, http.StatusBadRequest, "INVALID_ID", "Invalid URL ID")
		return true
	}
	switch r.Method {
	case http.MethodDelete:
		h.removeURL(r.Context(), w, id)
	case http.MethodPatch:
		h.toggleURLEnabled(r.Context(), w, id, r)
	default:
		return false
	}
	return true
}

// /api/blocklist/urls/{id}/fetch
func routeBlocklistURLsFetch(h *BlocklistHandler, w http.ResponseWriter, r *http.Request, parts []string) bool {
	if len(parts) != 3 || parts[0] != "urls" || parts[2] != "fetch" {
		return false
	}
	id, err := strconv.Atoi(parts[1])
	if err != nil || id < 1 {
		writeError(w, http.StatusBadRequest, "INVALID_ID", "Invalid URL ID")
		return true
	}
	if r.Method != http.MethodPost {
		return false
	}
	h.fetchURL(r.Context(), w, id)
	return true
}

// /api/blocklist/domains
func routeBlocklistDomainsCollection(h *BlocklistHandler, w http.ResponseWriter, r *http.Request, parts []string) bool {
	if len(parts) != 1 || parts[0] != "domains" {
		return false
	}
	switch r.Method {
	case http.MethodGet:
		h.listBlockedDomains(r.Context(), w)
	case http.MethodPost:
		h.addBlockedDomain(r.Context(), w, r)
	default:
		return false
	}
	return true
}

// /api/blocklist/domains/{domain}
func routeBlocklistDomainsItem(h *BlocklistHandler, w http.ResponseWriter, r *http.Request, parts []string) bool {
	if len(parts) != 2 || parts[0] != "domains" || r.Method != http.MethodDelete {
		return false
	}
	h.removeBlockedDomain(r.Context(), w, parts[1])
	return true
}

// /api/blocklist/allowed
func routeBlocklistAllowedCollection(h *BlocklistHandler, w http.ResponseWriter, r *http.Request, parts []string) bool {
	if len(parts) != 1 || parts[0] != "allowed" {
		return false
	}
	switch r.Method {
	case http.MethodGet:
		h.listAllowedDomains(r.Context(), w)
	case http.MethodPost:
		h.addAllowedDomain(r.Context(), w, r)
	default:
		return false
	}
	return true
}

// /api/blocklist/allowed/{domain}
func routeBlocklistAllowedItem(h *BlocklistHandler, w http.ResponseWriter, r *http.Request, parts []string) bool {
	if len(parts) != 2 || parts[0] != "allowed" || r.Method != http.MethodDelete {
		return false
	}
	h.removeAllowedDomain(r.Context(), w, parts[1])
	return true
}

// /api/blocklist/patterns
func routeBlocklistPatternsCollection(h *BlocklistHandler, w http.ResponseWriter, r *http.Request, parts []string) bool {
	if len(parts) != 1 || parts[0] != "patterns" {
		return false
	}
	switch r.Method {
	case http.MethodGet:
		h.listPatterns(r.Context(), w)
	case http.MethodPost:
		h.addPattern(r.Context(), w, r)
	default:
		return false
	}
	return true
}

// /api/blocklist/patterns/{id}
func routeBlocklistPatternsItem(h *BlocklistHandler, w http.ResponseWriter, r *http.Request, parts []string) bool {
	if len(parts) != 2 || parts[0] != "patterns" {
		return false
	}
	id, err := strconv.Atoi(parts[1])
	if err != nil || id < 1 {
		writeError(w, http.StatusBadRequest, "INVALID_ID", "Invalid pattern ID")
		return true
	}
	if r.Method != http.MethodDelete {
		return false
	}
	h.removePattern(r.Context(), w, id)
	return true
}

// /api/blocklist/whitelist-ips
func routeBlocklistWhitelistIPsCollection(h *BlocklistHandler, w http.ResponseWriter, r *http.Request, parts []string) bool {
	if len(parts) != 1 || parts[0] != "whitelist-ips" {
		return false
	}
	switch r.Method {
	case http.MethodGet:
		h.listWhitelistIPs(r.Context(), w)
	case http.MethodPost:
		h.addWhitelistIP(r.Context(), w, r)
	default:
		return false
	}
	return true
}

// /api/blocklist/whitelist-ips/{ip_cidr}
func routeBlocklistWhitelistIPsItem(h *BlocklistHandler, w http.ResponseWriter, r *http.Request, parts []string) bool {
	if len(parts) < 2 || parts[0] != "whitelist-ips" || r.Method != http.MethodDelete {
		return false
	}
	ipCIDR := strings.Join(parts[1:], "/")
	if u, err := url.PathUnescape(ipCIDR); err == nil {
		ipCIDR = u
	}
	h.removeWhitelistIP(r.Context(), w, ipCIDR)
	return true
}

func (h *BlocklistHandler) regenerateHosts(ctx context.Context) {
	// Signal the debounce loop instead of regenerating immediately
	select {
	case h.regenCh <- struct{}{}:
	default:
		// Channel full, regeneration already pending
	}
}

func (h *BlocklistHandler) listURLs(ctx context.Context, w http.ResponseWriter) {
	urls, err := h.store.ListBlocklistURLs(ctx)
	if err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	writeSuccess(w, urls, http.StatusOK)
}

func (h *BlocklistHandler) addURL(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL      string `json:"url"`
		Category string `json:"category"`
		Enabled  *bool  `json:"enabled"`
	}
	if err := DecodeJSON(r, &req, 0); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}
	if !h.checkBlocklistURLLimit(ctx, w) {
		return
	}
	urlStr, ok := validateBlocklistURLValue(w, req.URL)
	if !ok {
		return
	}
	if !validateBlocklistCategory(w, req.Category) {
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	u, err := h.store.AddBlocklistURL(ctx, urlStr, req.Category, enabled)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			writeError(w, http.StatusConflict, "URL_EXISTS", "Blocklist URL already exists")
			return
		}
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	h.regenerateHosts(ctx)
	writeSuccess(w, u, http.StatusCreated)
}

// checkBlocklistURLLimit reports whether another blocklist URL may be
// added. Writes the error response itself and returns false when the limit
// is reached or the current count can't be read.
func (h *BlocklistHandler) checkBlocklistURLLimit(ctx context.Context, w http.ResponseWriter) bool {
	urls, err := h.store.ListBlocklistURLs(ctx)
	if err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return false
	}
	if len(urls) >= maxBlocklistURLs {
		writeError(w, http.StatusBadRequest, "LIMIT_EXCEEDED", fmt.Sprintf("Maximum %d blocklist URLs allowed", maxBlocklistURLs))
		return false
	}
	return true
}

// validateBlocklistURLValue validates and trims a blocklist URL: non-empty,
// well-formed with an http(s) scheme, and not pointing at an internal or
// private host (SSRF prevention). Writes the error response itself on
// failure.
func validateBlocklistURLValue(w http.ResponseWriter, rawURL string) (string, bool) {
	urlStr := strings.TrimSpace(rawURL)
	if urlStr == "" {
		writeError(w, http.StatusBadRequest, "INVALID_URL", "URL is required")
		return "", false
	}
	parsedURL, err := url.Parse(urlStr)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		writeError(w, http.StatusBadRequest, "INVALID_URL", "URL must be valid with scheme and host")
		return "", false
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		writeError(w, http.StatusBadRequest, "INVALID_URL", "URL scheme must be http or https")
		return "", false
	}
	if isInternalBlocklistHost(parsedURL.Host) {
		writeError(w, http.StatusBadRequest, "INVALID_URL", "Cannot fetch from internal or private hosts")
		return "", false
	}
	return urlStr, true
}

// validateBlocklistCategory reports whether category is valid: empty
// (uncategorized) is always valid; otherwise it must be a known category.
// Writes the error response itself on failure.
func validateBlocklistCategory(w http.ResponseWriter, category string) bool {
	if category == "" {
		return true
	}
	if _, ok := dns.ValidCategories[category]; !ok {
		writeError(w, http.StatusBadRequest, "INVALID_CATEGORY", "Unknown category: "+category)
		return false
	}
	return true
}

func (h *BlocklistHandler) removeURL(ctx context.Context, w http.ResponseWriter, id int) {
	if err := h.store.RemoveBlocklistURL(ctx, id); err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	h.regenerateHosts(ctx)
	w.WriteHeader(http.StatusNoContent)
}

func (h *BlocklistHandler) toggleURLEnabled(ctx context.Context, w http.ResponseWriter, id int, r *http.Request) {
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := DecodeJSON(r, &req, 0); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}
	if req.Enabled == nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "enabled is required")
		return
	}
	if err := h.store.SetBlocklistURLEnabled(ctx, id, *req.Enabled); err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	h.regenerateHosts(ctx)
	writeSuccess(w, map[string]bool{"enabled": *req.Enabled}, http.StatusOK)
}

func (h *BlocklistHandler) fetchURL(ctx context.Context, w http.ResponseWriter, id int) {
	urls, err := h.store.ListBlocklistURLs(ctx)
	if err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	var targetURL string
	var targetEnabled bool
	for _, u := range urls {
		if u.ID == id {
			targetURL = u.URL
			targetEnabled = u.Enabled
			break
		}
	}
	if targetURL == "" {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Blocklist URL not found")
		return
	}
	domains, err := blocklist.FetchURL(ctx, targetURL)
	if err != nil {
		errStr := err.Error()
		_ = h.store.UpdateBlocklistURLFetch(ctx, id, &errStr)
		writeError(w, http.StatusBadGateway, "FETCH_FAILED", err.Error())
		return
	}
	if err := h.store.UpdateBlocklistURLFetch(ctx, id, nil); err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	if err := h.store.SetBlocklistURLDomains(ctx, id, domains); err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	if targetEnabled {
		h.regenerateHosts(ctx)
	}
	writeSuccess(w, map[string]int{"domains": len(domains)}, http.StatusOK)
}

// isInternalBlocklistHost returns true for localhost, loopback, and private IP ranges.
// Used for SSRF prevention when adding blocklist URLs.
func isInternalBlocklistHost(host string) bool {
	hostname := host
	// Strip port from hostname
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		hostname = host[:idx]
	}
	// Strip brackets from IPv6
	hostname = strings.TrimPrefix(hostname, "[")
	hostname = strings.TrimSuffix(hostname, "]")

	// Check for localhost string
	if strings.EqualFold(hostname, "localhost") {
		return true
	}

	// Parse as IP and check ranges
	ip := net.ParseIP(hostname)
	if ip == nil {
		// Not an IP, assume external domain (allow)
		return false
	}

	// Block loopback, private, link-local, and unspecified IPs
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return true
	}

	// Block cloud metadata service (AWS, GCP, Azure)
	if ip.String() == "169.254.169.254" {
		return true
	}

	return false
}
