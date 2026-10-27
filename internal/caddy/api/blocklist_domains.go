package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/mw7101/domudns/internal/dns"
	"github.com/rs/zerolog/log"
)

func (h *BlocklistHandler) listBlockedDomains(ctx context.Context, w http.ResponseWriter) {
	domains, err := h.store.ListBlockedDomains(ctx)
	if err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	writeSuccess(w, domains, http.StatusOK)
}

func (h *BlocklistHandler) addBlockedDomain(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := DecodeJSON(r, &req, 0); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}
	// Check resource limit
	domains, err := h.store.ListBlockedDomains(ctx)
	if err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	if len(domains) >= maxManualDomains {
		writeError(w, http.StatusBadRequest, "LIMIT_EXCEEDED", fmt.Sprintf("Maximum %d blocked domains allowed", maxManualDomains))
		return
	}
	// Remove trailing dot (DNS names from query log have FQDN format with dot)
	domain := strings.TrimSuffix(strings.TrimSpace(req.Domain), ".")
	if domain == "" || !dns.IsValidDomain(domain) {
		writeError(w, http.StatusBadRequest, "INVALID_DOMAIN", "Invalid domain name")
		return
	}
	if err := h.store.AddBlockedDomain(ctx, domain); err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	h.regenerateHosts(ctx)
	// Update in-memory blocklist immediately
	if h.corednsReload != nil {
		if err := h.corednsReload(); err != nil {
			log.Warn().Err(err).Msg("failed to reload DNS blocklist after blocked domain add")
		}
	}
	writeSuccess(w, map[string]string{"domain": strings.ToLower(domain)}, http.StatusCreated)
}

func (h *BlocklistHandler) removeBlockedDomain(ctx context.Context, w http.ResponseWriter, domain string) {
	domain, _ = decodePathDomain(domain)
	if err := h.store.RemoveBlockedDomain(ctx, domain); err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	h.regenerateHosts(ctx)
	// Update in-memory blocklist immediately
	if h.corednsReload != nil {
		if err := h.corednsReload(); err != nil {
			log.Warn().Err(err).Msg("failed to reload DNS blocklist after blocked domain remove")
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *BlocklistHandler) listAllowedDomains(ctx context.Context, w http.ResponseWriter) {
	domains, err := h.store.ListAllowedDomains(ctx)
	if err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	writeSuccess(w, domains, http.StatusOK)
}

func (h *BlocklistHandler) addAllowedDomain(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := DecodeJSON(r, &req, 0); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}
	// Check resource limit
	domains, err := h.store.ListAllowedDomains(ctx)
	if err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	if len(domains) >= maxManualDomains {
		writeError(w, http.StatusBadRequest, "LIMIT_EXCEEDED", fmt.Sprintf("Maximum %d allowed domains allowed", maxManualDomains))
		return
	}
	// Remove trailing dot (DNS names from query log have FQDN format with dot)
	domain := strings.TrimSuffix(strings.TrimSpace(req.Domain), ".")
	if domain == "" || !dns.IsValidDomain(domain) {
		writeError(w, http.StatusBadRequest, "INVALID_DOMAIN", "Invalid domain name")
		return
	}
	if err := h.store.AddAllowedDomain(ctx, domain); err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	h.regenerateHosts(ctx)
	// Update in-memory blocklist immediately so the domain is released right away
	if h.corednsReload != nil {
		if err := h.corednsReload(); err != nil {
			log.Warn().Err(err).Msg("failed to reload DNS blocklist after allowed domain add")
		}
	}
	writeSuccess(w, map[string]string{"domain": strings.ToLower(domain)}, http.StatusCreated)
}

func (h *BlocklistHandler) removeAllowedDomain(ctx context.Context, w http.ResponseWriter, domain string) {
	domain, _ = decodePathDomain(domain)
	if err := h.store.RemoveAllowedDomain(ctx, domain); err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	h.regenerateHosts(ctx)
	// Update in-memory blocklist immediately
	if h.corednsReload != nil {
		if err := h.corednsReload(); err != nil {
			log.Warn().Err(err).Msg("failed to reload DNS blocklist after allowed domain remove")
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *BlocklistHandler) listWhitelistIPs(ctx context.Context, w http.ResponseWriter) {
	ips, err := h.store.ListWhitelistIPs(ctx)
	if err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	writeSuccess(w, ips, http.StatusOK)
}

func (h *BlocklistHandler) addWhitelistIP(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req struct {
		IPCIDR string `json:"ip_cidr"`
	}
	if err := DecodeJSON(r, &req, 0); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}
	// Check resource limit
	ips, err := h.store.ListWhitelistIPs(ctx)
	if err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	if len(ips) >= maxWhitelistIPs {
		writeError(w, http.StatusBadRequest, "LIMIT_EXCEEDED", fmt.Sprintf("Maximum %d whitelist IPs allowed", maxWhitelistIPs))
		return
	}
	input := strings.TrimSpace(req.IPCIDR)
	if strings.EqualFold(input, "localhost") {
		for _, ip := range []string{"127.0.0.1", "::1"} {
			if err := h.store.AddWhitelistIP(ctx, ip); err != nil {
				writeError(w, http.StatusBadRequest, "INVALID_IP", err.Error())
				return
			}
		}
		writeSuccess(w, map[string][]string{"ip_cidr": {"127.0.0.1", "::1"}}, http.StatusCreated)
		return
	}
	if err := h.store.AddWhitelistIP(ctx, input); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_IP", err.Error())
		return
	}
	// Reload blocklist in DNS server immediately so the whitelist change takes effect
	if h.corednsReload != nil {
		if err := h.corednsReload(); err != nil {
			log.Warn().Err(err).Msg("failed to reload DNS blocklist after whitelist IP add")
		}
	}
	writeSuccess(w, map[string]string{"ip_cidr": input}, http.StatusCreated)
}

func (h *BlocklistHandler) removeWhitelistIP(ctx context.Context, w http.ResponseWriter, ipCIDR string) {
	if err := h.store.RemoveWhitelistIP(ctx, ipCIDR); err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	// Reload blocklist in DNS server immediately so the whitelist change takes effect
	if h.corednsReload != nil {
		if err := h.corednsReload(); err != nil {
			log.Warn().Err(err).Msg("failed to reload DNS blocklist after whitelist IP remove")
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodePathDomain(s string) (string, error) {
	d, err := url.PathUnescape(s)
	if err != nil {
		return s, nil
	}
	return strings.TrimSpace(strings.ToLower(d)), nil
}
