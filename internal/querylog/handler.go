package querylog

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

// Handler implements the HTTP API for the query log.
// GET /api/query-log       — filtered, paginated entries
// GET /api/query-log/stats — aggregated statistics
type Handler struct {
	logger *QueryLogger
}

// NewHandler creates a new API handler.
// logger may be nil — in that case empty responses are returned.
func NewHandler(logger *QueryLogger) *Handler {
	return &Handler{logger: logger}
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "only GET allowed")
		return
	}

	switch r.URL.Path {
	case "/api/query-log/stats":
		h.handleStats(w, r)
	default:
		h.handleList(w, r)
	}
}

// handleList serves GET /api/query-log with optional filter parameters.
func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	f, err := parseFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_PARAM", err.Error())
		return
	}

	page := h.logger.Query(f)
	writeSuccess(w, page)
}

// handleStats serves GET /api/query-log/stats.
func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := h.logger.Stats()
	writeSuccess(w, stats)
}

// parseFilter reads query parameters and returns a QueryLogFilter.
func parseFilter(r *http.Request) (QueryLogFilter, error) {
	q := r.URL.Query()
	f := QueryLogFilter{
		Client: q.Get("client"),
		Domain: q.Get("domain"),
		Result: q.Get("result"),
		QType:  q.Get("qtype"),
		Node:   q.Get("node"),
	}

	if s := q.Get("since"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return f, fmt.Errorf("invalid 'since': %w", err)
		}
		f.Since = t
	}

	if s := q.Get("until"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return f, fmt.Errorf("invalid 'until': %w", err)
		}
		f.Until = t
	}

	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return f, fmt.Errorf("invalid 'limit': must be a non-negative integer")
		}
		f.Limit = n
	}

	if s := q.Get("offset"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return f, fmt.Errorf("invalid 'offset': must be a non-negative integer")
		}
		f.Offset = n
	}

	// Validate result values
	if f.Result != "" {
		switch f.Result {
		case ResultBlocked, ResultCached, ResultAuthoritative, ResultForwarded, ResultError:
		default:
			return f, fmt.Errorf("invalid 'result': must be one of blocked, cached, authoritative, forwarded, error")
		}
	}

	return f, nil
}

// writeSuccess writes a successful JSON response.
func writeSuccess(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := jsonEncode(w, map[string]interface{}{
		"success": true,
		"data":    data,
	}); err != nil {
		log.Error().Err(err).Msg("query-log: failed to encode response")
	}
}

// writeError writes an error JSON response.
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = jsonEncode(w, map[string]interface{}{
		"success": false,
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

// jsonEncode writes v as JSON to w.
func jsonEncode(w io.Writer, v interface{}) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}
