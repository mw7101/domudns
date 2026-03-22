package api

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/mw7101/domudns/internal/dns"
	"github.com/rs/zerolog/log"
)

func (h *BlocklistHandler) listPatterns(ctx context.Context, w http.ResponseWriter) {
	patterns, err := h.store.ListBlocklistPatterns(ctx)
	if err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	writeSuccess(w, patterns, http.StatusOK)
}

func (h *BlocklistHandler) addPattern(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pattern string `json:"pattern"`
		Type    string `json:"type"`
	}
	if err := DecodeJSON(r, &req, 0); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}
	// Check resource limit
	patterns, err := h.store.ListBlocklistPatterns(ctx)
	if err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	if len(patterns) >= maxBlocklistPatterns {
		writeError(w, http.StatusBadRequest, "LIMIT_EXCEEDED", fmt.Sprintf("Maximum %d patterns allowed", maxBlocklistPatterns))
		return
	}
	req.Pattern = strings.TrimSpace(req.Pattern)
	req.Type = strings.TrimSpace(req.Type)
	if err := validateBlocklistPattern(req.Pattern, req.Type); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_PATTERN", err.Error())
		return
	}
	p, err := h.store.AddBlocklistPattern(ctx, req.Pattern, req.Type)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			writeError(w, http.StatusConflict, "PATTERN_EXISTS", "Pattern already exists")
			return
		}
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	// Reload blocklist immediately so the pattern takes effect
	if h.corednsReload != nil {
		if err := h.corednsReload(); err != nil {
			log.Warn().Err(err).Msg("failed to reload DNS blocklist after pattern add")
		}
	}
	writeSuccess(w, p, http.StatusCreated)
}

func (h *BlocklistHandler) removePattern(ctx context.Context, w http.ResponseWriter, id int) {
	if err := h.store.RemoveBlocklistPattern(ctx, id); err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	if h.corednsReload != nil {
		if err := h.corednsReload(); err != nil {
			log.Warn().Err(err).Msg("failed to reload DNS blocklist after pattern remove")
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// validateBlocklistPattern checks whether pattern and type are valid.
// Wildcard: must start with "*.", followed by a valid domain.
// Regex: must be a valid Go regex (optionally with /.../ delimiter).
func validateBlocklistPattern(pattern, patternType string) error {
	if pattern == "" {
		return fmt.Errorf("pattern is required")
	}
	switch patternType {
	case "wildcard":
		if !strings.HasPrefix(pattern, "*.") {
			return fmt.Errorf("wildcard pattern must start with '*.'")
		}
		domain := pattern[2:]
		if !dns.IsValidDomain(domain) {
			return fmt.Errorf("invalid domain in wildcard pattern: %q", domain)
		}
	case "regex":
		raw := pattern
		if strings.HasPrefix(raw, "/") && strings.HasSuffix(raw, "/") && len(raw) > 2 {
			raw = raw[1 : len(raw)-1]
		}
		if _, err := regexp.Compile(raw); err != nil {
			return fmt.Errorf("invalid regex: %w", err)
		}
	default:
		return fmt.Errorf("type must be 'wildcard' or 'regex'")
	}
	return nil
}
