package api

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog/log"
)

// Response is the standard API response wrapper.
type Response struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *ErrorBody  `json:"error,omitempty"`
	Meta    *Meta       `json:"meta,omitempty"`
}

// ErrorBody holds error details.
type ErrorBody struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
}

// Meta holds response metadata.
type Meta struct {
	Timestamp string `json:"timestamp"`
	RequestID string `json:"request_id,omitempty"`
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// writeSuccess writes a success response.
func writeSuccess(w http.ResponseWriter, data interface{}, status int) {
	writeJSON(w, status, Response{
		Success: true,
		Data:    data,
	})
}

// writeError writes an error response.
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, Response{
		Success: false,
		Error: &ErrorBody{
			Code:    code,
			Message: message,
		},
	})
}

// writeInternalError logs err and returns a generic message to the client.
// Prevents leaking internal details (paths, connection strings) via err.Error().
func writeInternalError(w http.ResponseWriter, code string, err error) {
	log.Error().Err(err).Str("api_error_code", code).Msg("internal API error")
	writeError(w, http.StatusInternalServerError, code, "internal error")
}
