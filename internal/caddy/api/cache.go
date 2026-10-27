package api

import (
	"net/http"
	"strings"

	"github.com/mw7101/domudns/internal/dnsserver"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

const cacheEntryLimit = 500

// CacheAccessor is implemented by *dnsserver.CacheManager.
type CacheAccessor interface {
	Stats() (entries, hits, misses int, hitRate float64)
	Entries(limit int) []dnsserver.CacheEntryInfo
	Flush()
	Delete(qname string, qtype uint16) bool
}

// CacheStatsResponse is the response body for GET /api/cache.
type CacheStatsResponse struct {
	Entries   int                        `json:"entries"`
	Hits      int                        `json:"hits"`
	Misses    int                        `json:"misses"`
	HitRate   float64                    `json:"hit_rate"`
	EntryList []dnsserver.CacheEntryInfo `json:"entry_list"`
}

// CacheHandler handles /api/cache endpoints.
type CacheHandler struct {
	cache CacheAccessor
}

// NewCacheHandler creates a CacheHandler.
// cache may be nil (cache disabled) — all requests return 503.
func NewCacheHandler(cache CacheAccessor) *CacheHandler {
	return &CacheHandler{cache: cache}
}

// ServeHTTP routes /api/cache requests.
//
//	GET    /api/cache              → stats + entry list
//	DELETE /api/cache              → flush all entries
//	DELETE /api/cache/{name}/{type} → delete specific entry
func (h *CacheHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.cache == nil {
		writeError(w, http.StatusServiceUnavailable, "CACHE_DISABLED", "Cache is disabled")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/cache")
	path = strings.Trim(path, "/")

	if path == "" {
		switch r.Method {
		case http.MethodGet:
			h.statsAndEntries(w)
		case http.MethodDelete:
			h.flush(w)
		default:
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Use GET or DELETE")
		}
		return
	}

	// DELETE /api/cache/{name}/{type}
	// The last path segment is the record type; everything before it is the qname.
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Use DELETE")
		return
	}
	lastSlash := strings.LastIndex(path, "/")
	if lastSlash < 0 {
		writeError(w, http.StatusBadRequest, "INVALID_PATH", "Expected /api/cache/{name}/{type}")
		return
	}
	qname := path[:lastSlash]
	qtypeStr := strings.ToUpper(path[lastSlash+1:])
	h.deleteEntry(w, qname, qtypeStr)
}

func (h *CacheHandler) statsAndEntries(w http.ResponseWriter) {
	entries, hits, misses, hitRate := h.cache.Stats()
	entryList := h.cache.Entries(cacheEntryLimit)
	if entryList == nil {
		entryList = []dnsserver.CacheEntryInfo{}
	}
	writeSuccess(w, CacheStatsResponse{
		Entries:   entries,
		Hits:      hits,
		Misses:    misses,
		HitRate:   hitRate,
		EntryList: entryList,
	}, http.StatusOK)
}

func (h *CacheHandler) flush(w http.ResponseWriter) {
	h.cache.Flush()
	log.Info().Msg("cache flushed via API")
	writeSuccess(w, map[string]string{"status": "flushed"}, http.StatusOK)
}

func (h *CacheHandler) deleteEntry(w http.ResponseWriter, qname, qtypeStr string) {
	// Normalize: ensure qname has a trailing dot (FQDN)
	if !strings.HasSuffix(qname, ".") {
		qname = qname + "."
	}
	qtype, ok := dns.StringToType[qtypeStr]
	if !ok {
		writeError(w, http.StatusBadRequest, "INVALID_TYPE", "Unknown DNS record type: "+qtypeStr)
		return
	}
	if !h.cache.Delete(qname, qtype) {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Entry not in cache")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
