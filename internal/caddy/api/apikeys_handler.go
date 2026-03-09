package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/mw7101/domudns/internal/store"
)

// APIKeysHandler handles CRUD for named API keys at /api/auth/api-keys.
type APIKeysHandler struct {
	store NamedAPIKeyStore
}

// NewAPIKeysHandler creates a new named API key handler.
func NewAPIKeysHandler(s NamedAPIKeyStore) *APIKeysHandler {
	return &APIKeysHandler{store: s}
}

// ServeHTTP routes /api/auth/api-keys and /api/auth/api-keys/{id}.
func (h *APIKeysHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// /api/auth/api-keys/{id}
	if strings.HasPrefix(path, "/api/auth/api-keys/") {
		id := strings.TrimPrefix(path, "/api/auth/api-keys/")
		id = strings.Trim(id, "/")
		if r.Method == http.MethodDelete {
			h.handleDelete(w, r, id)
			return
		}
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "DELETE required")
		return
	}

	// /api/auth/api-keys
	switch r.Method {
	case http.MethodGet:
		h.handleList(w, r)
	case http.MethodPost:
		h.handleCreate(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET or POST required")
	}
}

func (h *APIKeysHandler) handleList(w http.ResponseWriter, r *http.Request) {
	keys, err := h.store.ListNamedAPIKeys(r.Context())
	if err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	if keys == nil {
		keys = []store.NamedAPIKey{}
	}
	writeSuccess(w, keys, http.StatusOK)
}

func (h *APIKeysHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := DecodeJSON(r, &req, 0); err != nil {
		if errors.Is(err, ErrJSONDepthExceeded) {
			writeError(w, http.StatusBadRequest, "INVALID_JSON", "JSON nesting depth exceeded")
			return
		}
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "name required")
		return
	}
	if len(req.Name) > 100 {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "name too long (max 100 characters)")
		return
	}
	if len(req.Description) > 500 {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "description too long (max 500 characters)")
		return
	}

	key, err := h.store.CreateNamedAPIKey(r.Context(), req.Name, req.Description)
	if err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	writeSuccess(w, key, http.StatusCreated)
}

func (h *APIKeysHandler) handleDelete(w http.ResponseWriter, r *http.Request, id string) {
	if id == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "id required")
		return
	}
	if err := h.store.DeleteNamedAPIKey(r.Context(), id); err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
