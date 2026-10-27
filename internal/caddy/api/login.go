package api

import (
	"encoding/json"
	"html/template"
	"net/http"
	"strings"
)

var loginTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DNS Stack – Anmeldung</title>
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
      max-width: 380px;
      box-shadow: 0 32px 64px rgba(0, 0, 0, 0.4);
    }
    .header {
      text-align: center;
      margin-bottom: 40px;
    }
    .icon {
      width: 56px;
      height: 56px;
      background: linear-gradient(135deg, #0ea5e9, #6366f1);
      border-radius: 14px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-size: 26px;
      margin-bottom: 16px;
    }
    h1 {
      font-size: 22px;
      font-weight: 700;
      color: #f1f5f9;
      margin-bottom: 4px;
    }
    .subtitle {
      font-size: 13px;
      color: #64748b;
    }
    .field {
      margin-bottom: 20px;
    }
    label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: #94a3b8;
      margin-bottom: 8px;
    }
    input[type="text"],
    input[type="password"] {
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
    input[type="text"]:focus,
    input[type="password"]:focus {
      border-color: #0ea5e9;
      box-shadow: 0 0 0 3px rgba(14, 165, 233, 0.15);
    }
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
      display: flex;
      align-items: center;
      gap: 8px;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <div class="icon">⬡</div>
      <h1>DNS Stack</h1>
      <p class="subtitle">Lightweight DNS Management</p>
    </div>
    {{if .Error}}
    <div class="error">
      <span>⚠</span> {{.Error}}
    </div>
    {{end}}
    <form method="POST" action="/api/login">
      <input type="hidden" name="redirect" value="{{.Redirect}}">
      <div class="field">
        <label for="username">Benutzername</label>
        <input type="text" id="username" name="username"
               placeholder="Benutzername" autofocus required>
      </div>
      <div class="field">
        <label for="password">Passwort</label>
        <input type="password" id="password" name="password"
               placeholder="Passwort eingeben" required>
      </div>
      <button type="submit">Anmelden →</button>
    </form>
  </div>
</body>
</html>
`))

type loginPageData struct {
	Error    string
	Redirect string
}

// LoginPageHandler renders the login page (GET /login).
func LoginPageHandler(w http.ResponseWriter, r *http.Request) {
	redirect := r.URL.Query().Get("redirect")
	if !isSafeRedirect(redirect) {
		redirect = "/"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginTmpl.Execute(w, loginPageData{Redirect: redirect})
}

// LoginHandler processes the login request (POST /api/login).
// Checks username and password via AuthManager (bcrypt).
// Supports both JSON (Next.js Dashboard) and HTML form.
func LoginHandler(auth *AuthManager, sessions *SessionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var username, password, redirect string

		if isJSONRequest(r) {
			// JSON request (Next.js Dashboard)
			var req struct {
				Username string `json:"username"`
				Password string `json:"password"`
				Redirect string `json:"redirect"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeError(w, http.StatusBadRequest, "INVALID_JSON", "Ungültige JSON-Anfrage")
				return
			}
			username = req.Username
			password = req.Password
			redirect = req.Redirect
		} else {
			// HTML form (fallback)
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Ungültige Anfrage", http.StatusBadRequest)
				return
			}
			username = r.FormValue("username")
			password = r.FormValue("password")
			redirect = r.FormValue("redirect")
		}

		if !isSafeRedirect(redirect) {
			redirect = "/"
		}

		if !auth.ValidatePassword(username, password) {
			if isJSONRequest(r) {
				writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Ungültige Anmeldedaten.")
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_ = loginTmpl.Execute(w, loginPageData{
				Error:    "Ungültige Anmeldedaten.",
				Redirect: redirect,
			})
			return
		}

		token, err := sessions.Create()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "SESSION_ERROR", "Interner Fehler")
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     SessionCookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(sessionTTL.Seconds()),
		})

		// Setup not yet completed
		setupCompleted := auth.IsSetupCompleted()
		if isJSONRequest(r) {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"message":         "Angemeldet",
				"setup_completed": setupCompleted,
			})
			return
		}

		if !setupCompleted {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, redirect, http.StatusSeeOther)
	}
}

// LogoutHandler deletes the session and redirects to the login page (POST /api/logout).
func LogoutHandler(sessions *SessionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie(SessionCookieName); err == nil {
			sessions.Delete(cookie.Value)
		}
		http.SetCookie(w, &http.Cookie{
			Name:     SessionCookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			MaxAge:   -1,
		})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

// isSafeRedirect prevents open redirect attacks.
// Only relative paths starting with "/" (but not "//") are allowed.
func isSafeRedirect(redirect string) bool {
	if redirect == "" {
		return false
	}
	return strings.HasPrefix(redirect, "/") && !strings.HasPrefix(redirect, "//")
}
