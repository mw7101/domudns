package api

import (
	"encoding/json"
	"net/http"
)

// AuthHandler manages password changes and API key regeneration.
type AuthHandler struct {
	auth *AuthManager
}

// NewAuthHandler creates a new auth handler.
func NewAuthHandler(auth *AuthManager) *AuthHandler {
	return &AuthHandler{auth: auth}
}

// ServeHTTP routes /api/auth/* requests (auth required).
func (h *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case path == "/api/auth/change-password" && r.Method == http.MethodPost:
		h.handleChangePassword(w, r)
	case path == "/api/auth/regenerate-api-key" && r.Method == http.MethodPost:
		h.handleRegenerateAPIKey(w, r)
	default:
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Unknown auth endpoint")
	}
}

// handleChangePassword processes password changes (POST /api/auth/change-password).
func (h *AuthHandler) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Ungültige JSON-Anfrage")
		return
	}

	// Check current password
	if !h.auth.ValidatePassword(h.auth.getCurrentUsername(), req.CurrentPassword) {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Aktuelles Passwort ist falsch")
		return
	}

	if len(req.NewPassword) < 8 {
		writeError(w, http.StatusBadRequest, "PASSWORD_TOO_SHORT", "Passwort muss mindestens 8 Zeichen lang sein")
		return
	}

	if err := h.auth.UpdatePassword(r.Context(), h.auth.getCurrentUsername(), req.NewPassword); err != nil {
		writeError(w, http.StatusInternalServerError, "UPDATE_FAILED", "Passwort konnte nicht geändert werden")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Passwort erfolgreich geändert"})
}

// handleRegenerateAPIKey generates a new API key (POST /api/auth/regenerate-api-key).
func (h *AuthHandler) handleRegenerateAPIKey(w http.ResponseWriter, r *http.Request) {
	key, err := h.auth.RegenerateAPIKey(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "KEYGEN_FAILED", "API-Key konnte nicht generiert werden")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"api_key": key,
		"message": "Neuer API-Key generiert – nur einmalig angezeigt",
	})
}
