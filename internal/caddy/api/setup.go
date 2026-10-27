package api

import (
	"encoding/json"
	"html/template"
	"net/http"
	"strings"
)

var setupTmpl = template.Must(template.New("setup").Parse(`<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DNS Stack – Ersteinrichtung</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 16px;
    }
    .card {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 16px;
      padding: 48px 40px;
      width: 100%;
      max-width: 420px;
      box-shadow: 0 32px 64px rgba(0, 0, 0, 0.4);
    }
    .header { text-align: center; margin-bottom: 32px; }
    .icon {
      width: 56px; height: 56px;
      background: linear-gradient(135deg, #0ea5e9, #6366f1);
      border-radius: 14px;
      display: inline-flex; align-items: center; justify-content: center;
      font-size: 26px; margin-bottom: 16px;
    }
    h1 { font-size: 22px; font-weight: 700; color: #f1f5f9; margin-bottom: 4px; }
    .subtitle { font-size: 13px; color: #64748b; }
    .step-info {
      background: rgba(14, 165, 233, 0.1);
      border: 1px solid rgba(14, 165, 233, 0.3);
      color: #7dd3fc;
      padding: 11px 14px;
      border-radius: 10px;
      font-size: 13px;
      margin-bottom: 24px;
    }
    .field { margin-bottom: 20px; }
    label { display: block; font-size: 13px; font-weight: 500; color: #94a3b8; margin-bottom: 8px; }
    input[type="text"], input[type="password"] {
      width: 100%;
      padding: 11px 14px;
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 10px;
      color: #f1f5f9;
      font-size: 15px;
      outline: none;
      transition: border-color 0.15s, box-shadow 0.15s;
    }
    input[type="text"]:focus, input[type="password"]:focus {
      border-color: #0ea5e9;
      box-shadow: 0 0 0 3px rgba(14, 165, 233, 0.15);
    }
    .checkbox-row {
      display: flex; align-items: center; gap: 10px;
      font-size: 13px; color: #94a3b8; margin-bottom: 20px;
    }
    .checkbox-row input { width: auto; }
    button[type="submit"] {
      width: 100%;
      padding: 12px;
      background: linear-gradient(135deg, #0ea5e9, #6366f1);
      color: #fff;
      border: none;
      border-radius: 10px;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: opacity 0.15s, transform 0.1s;
      margin-top: 8px;
    }
    button[type="submit"]:hover { opacity: 0.9; }
    button[type="submit"]:active { transform: scale(0.98); }
    .error {
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid rgba(239, 68, 68, 0.3);
      color: #fca5a5;
      padding: 11px 14px;
      border-radius: 10px;
      font-size: 13px;
      margin-bottom: 20px;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <div class="icon">⬡</div>
      <h1>DNS Stack Setup</h1>
      <p class="subtitle">Ersteinrichtung des Admin-Accounts</p>
    </div>
    <div class="step-info">
      Willkommen! Bitte legen Sie jetzt Ihren Admin-Account und API-Key fest.
      Der API-Key wird nur einmalig angezeigt.
    </div>
    {{if .Error}}
    <div class="error">⚠ {{.Error}}</div>
    {{end}}
    <form method="POST" action="/api/setup/complete">
      <div class="field">
        <label for="username">Benutzername</label>
        <input type="text" id="username" name="username"
               value="admin" placeholder="Benutzername" required>
      </div>
      <div class="field">
        <label for="password">Neues Passwort</label>
        <input type="password" id="password" name="password"
               placeholder="Mindestens 8 Zeichen" autofocus required>
      </div>
      <div class="field">
        <label for="password2">Passwort bestätigen</label>
        <input type="password" id="password2" name="password2"
               placeholder="Passwort wiederholen" required>
      </div>
      <div class="checkbox-row">
        <input type="checkbox" id="generate_api_key" name="generate_api_key" value="1" checked>
        <label for="generate_api_key">API-Key generieren (für curl/Scripts)</label>
      </div>
      <button type="submit">Setup abschließen →</button>
    </form>
  </div>
</body>
</html>
`))

type setupPageData struct {
	Error string
}

// SetupHandler verwaltet die Setup-Wizard-Endpoints.
type SetupHandler struct {
	auth *AuthManager
}

// NewSetupHandler erstellt einen neuen Setup-Handler.
func NewSetupHandler(auth *AuthManager) *SetupHandler {
	return &SetupHandler{auth: auth}
}

// SetupPageHandler rendert die Setup-Seite (GET /setup).
func (h *SetupHandler) SetupPageHandler(w http.ResponseWriter, r *http.Request) {
	// Nach abgeschlossenem Setup → weiterleiten
	if h.auth.IsSetupCompleted() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = setupTmpl.Execute(w, setupPageData{})
}

// ServeHTTP verteilt /api/setup/* Anfragen.
func (h *SetupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case path == "/api/setup/status" && r.Method == http.MethodGet:
		h.handleStatus(w, r)
	case path == "/api/setup/complete":
		h.handleComplete(w, r)
	default:
		writeError(w, http.StatusNotFound, "NOT_FOUND", "Unknown setup endpoint")
	}
}

// handleStatus gibt den Setup-Status zurück (GET /api/setup/status).
func (h *SetupHandler) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"setup_completed": h.auth.IsSetupCompleted(),
	})
}

// handleComplete verarbeitet den Setup-Abschluss (POST /api/setup/complete).
// Akzeptiert sowohl JSON als auch HTML-Formular.
func (h *SetupHandler) handleComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only POST allowed")
		return
	}

	// Setup darf nur einmal abgeschlossen werden
	if h.auth.IsSetupCompleted() {
		if isJSONRequest(r) {
			writeError(w, http.StatusConflict, "ALREADY_SETUP", "Setup bereits abgeschlossen")
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	var username, password, password2 string
	var generateAPIKey bool

	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		var req struct {
			Username       string `json:"username"`
			Password       string `json:"password"`
			GenerateAPIKey bool   `json:"generate_api_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_JSON", "Ungültige JSON-Anfrage")
			return
		}
		username = req.Username
		password = req.Password
		generateAPIKey = req.GenerateAPIKey
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Ungültige Anfrage", http.StatusBadRequest)
			return
		}
		username = r.FormValue("username")
		password = r.FormValue("password")
		password2 = r.FormValue("password2")
		generateAPIKey = r.FormValue("generate_api_key") == "1"
	}

	// Validierung
	if username == "" {
		username = "admin"
	}
	if len(password) < 8 {
		if isJSONRequest(r) {
			writeError(w, http.StatusBadRequest, "PASSWORD_TOO_SHORT", "Passwort muss mindestens 8 Zeichen lang sein")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = setupTmpl.Execute(w, setupPageData{Error: "Passwort muss mindestens 8 Zeichen lang sein."})
		return
	}
	if password2 != "" && password != password2 {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = setupTmpl.Execute(w, setupPageData{Error: "Passwörter stimmen nicht überein."})
		return
	}

	// Passwort setzen
	if err := h.auth.UpdatePassword(r.Context(), username, password); err != nil {
		if isJSONRequest(r) {
			writeError(w, http.StatusInternalServerError, "UPDATE_FAILED", "Passwort konnte nicht gesetzt werden")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = setupTmpl.Execute(w, setupPageData{Error: "Fehler beim Setzen des Passworts."})
		return
	}

	// API-Key generieren (optional)
	var newAPIKey string
	if generateAPIKey {
		key, err := h.auth.RegenerateAPIKey(r.Context())
		if err == nil {
			newAPIKey = key
		}
	}

	// Setup abschließen
	if err := h.auth.MarkSetupCompleted(r.Context()); err != nil {
		if isJSONRequest(r) {
			writeError(w, http.StatusInternalServerError, "SETUP_FAILED", "Setup konnte nicht abgeschlossen werden")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = setupTmpl.Execute(w, setupPageData{Error: "Fehler beim Abschließen des Setups."})
		return
	}

	if isJSONRequest(r) {
		resp := map[string]interface{}{
			"message": "Setup abgeschlossen",
		}
		if newAPIKey != "" {
			resp["api_key"] = newAPIKey
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// HTML-Formular: Bei API-Key → kleine Erfolgsseite, sonst direkt zur Login-Seite
	if newAPIKey != "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		apiKeySuccessTmpl.Execute(w, map[string]string{"APIKey": newAPIKey})
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

var apiKeySuccessTmpl = template.Must(template.New("apikey").Parse(`<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <title>DNS Stack – Setup abgeschlossen</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0f172a; color: #e2e8f0;
      min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 16px;
    }
    .card {
      background: #1e293b; border: 1px solid #334155; border-radius: 16px;
      padding: 48px 40px; width: 100%; max-width: 520px;
      box-shadow: 0 32px 64px rgba(0,0,0,0.4);
    }
    h1 { font-size: 22px; font-weight: 700; color: #4ade80; margin-bottom: 12px; }
    p { font-size: 14px; color: #94a3b8; margin-bottom: 16px; }
    .key-box {
      background: #0f172a; border: 1px solid #334155; border-radius: 10px;
      padding: 14px; font-family: monospace; font-size: 13px; color: #7dd3fc;
      word-break: break-all; margin-bottom: 24px;
    }
    .warning {
      background: rgba(234, 179, 8, 0.1); border: 1px solid rgba(234, 179, 8, 0.3);
      color: #fde047; padding: 11px 14px; border-radius: 10px; font-size: 13px; margin-bottom: 24px;
    }
    a {
      display: block; text-align: center; padding: 12px;
      background: linear-gradient(135deg, #0ea5e9, #6366f1);
      color: #fff; border-radius: 10px; text-decoration: none; font-weight: 600;
    }
  </style>
</head>
<body>
  <div class="card">
    <h1>✓ Setup abgeschlossen</h1>
    <p>Ihr API-Key wurde generiert. Er wird nur jetzt einmalig angezeigt – bitte sichern Sie ihn!</p>
    <div class="key-box">{{.APIKey}}</div>
    <div class="warning">⚠ Dieser Key wird nicht erneut angezeigt. Jetzt kopieren!</div>
    <a href="/login">Zum Login →</a>
  </div>
</body>
</html>
`))

// isJSONRequest gibt true zurück wenn die Anfrage JSON erwartet oder sendet.
func isJSONRequest(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	ct := r.Header.Get("Content-Type")
	return strings.Contains(accept, "application/json") || strings.Contains(ct, "application/json")
}
