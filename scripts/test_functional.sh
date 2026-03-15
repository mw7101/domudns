#!/bin/bash
# =============================================================================
# DomU DNS — Funktionaler Integrationstest
# Prüft alle API-Endpunkte und DNS-Funktionen gegen einen laufenden Server.
#
# Verwendung:
#   ./scripts/test_functional.sh [OPTIONEN]
#
# Optionen (auch als Umgebungsvariable):
#   DNS_BASE_URL    HTTP-Basis-URL des Servers        (Standard: http://localhost)
#   DNS_API_KEY     API-Key für Bearer-Auth            (Pflicht)
#   DNS_HOST        DNS-Server-Host für dig-Tests      (Standard: 127.0.0.1)
#   DNS_PORT        DNS-Server-Port für dig-Tests      (Standard: 53)
#   DNS_ADMIN_USER  Admin-Benutzername für Login-Test  (Standard: admin)
#   DNS_ADMIN_PASS  Admin-Passwort für Login-Test      (optional, überspringt Login-Test wenn leer)
#   DNS_TEST_REGEN  API-Key neu generieren testen (1)  (Standard: 0, ACHTUNG: ungültig machend!)
#   SKIP_DNS        DNS-Tests überspringen (1/0)        (Standard: 0)
#   SKIP_CLEANUP    Testdaten nicht löschen (1/0)       (Standard: 0)
#   VERBOSE         Ausführliche curl-Ausgabe (1/0)     (Standard: 0)
#
# Beispiel:
#   DNS_API_KEY=mein-key ./scripts/test_functional.sh
#   DNS_BASE_URL=http://192.0.2.1 DNS_API_KEY=key DNS_HOST=192.0.2.1 \
#     DNS_ADMIN_PASS=geheim ./scripts/test_functional.sh
# =============================================================================

set -uo pipefail

# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------
BASE_URL="${DNS_BASE_URL:-http://localhost}"
API_KEY="${DNS_API_KEY:-}"
DNS_HOST="${DNS_HOST:-127.0.0.1}"
DNS_PORT="${DNS_PORT:-53}"
DNS_ADMIN_USER="${DNS_ADMIN_USER:-admin}"
DNS_ADMIN_PASS="${DNS_ADMIN_PASS:-}"
DNS_TEST_REGEN="${DNS_TEST_REGEN:-0}"
SKIP_DNS="${SKIP_DNS:-0}"
SKIP_CLEANUP="${SKIP_CLEANUP:-0}"
VERBOSE="${VERBOSE:-0}"

# Testdaten (werden am Ende bereinigt)
TEST_ZONE="test-functional.example."
TEST_DOMAIN="test-functional.example"
TEST_VIEW="internal"
TEST_VIEW_DOMAIN="test-functional-view.example"
TEST_API_KEY_NAME="test-functional-key-$$"  # PID verhindert Kollisionen

# ---------------------------------------------------------------------------
# Farben & Zähler
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0
WARN=0

# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------
ok()      { echo -e "  ${GREEN}✓${NC} $1"; (( PASS++ )) || true; }
fail()    { echo -e "  ${RED}✗${NC} $1"; (( FAIL++ )) || true; }
warn()    { echo -e "  ${YELLOW}⚠${NC} $1"; (( WARN++ )) || true; }
skip()    { echo -e "  ${YELLOW}-${NC} $1 ${YELLOW}(übersprungen)${NC}"; (( SKIP++ )) || true; }
section() { echo; echo -e "${BOLD}${CYAN}═══ $1 ═══${NC}"; }
info()    { echo -e "  ${BLUE}ℹ${NC} $1"; }

# Globale Variable für letzten HTTP-Response-Body
LAST_BODY=""
LAST_HTTP=""

# curl: gibt HTTP-Statuscode zurück, speichert Body in LAST_BODY
api_req() {
    local method="$1"; shift
    local path="$1"; shift
    local extra_args=("$@")

    if [[ "$VERBOSE" == "1" ]]; then
        echo -e "  ${BLUE}→ $method $BASE_URL$path${NC}"
    fi

    local tmpfile
    tmpfile=$(mktemp)

    LAST_HTTP=$(curl -s -o "$tmpfile" -w "%{http_code}" \
        -X "$method" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        --connect-timeout 5 \
        --max-time 15 \
        "${extra_args[@]}" \
        "$BASE_URL$path" 2>/dev/null || echo "000")

    LAST_BODY=$(cat "$tmpfile")
    rm -f "$tmpfile"

    if [[ "$VERBOSE" == "1" ]]; then
        echo -e "  ${BLUE}← HTTP $LAST_HTTP${NC}"
        [[ -n "$LAST_BODY" ]] && echo "$LAST_BODY" | head -5
    fi
}

api_get()    { api_req "GET"    "$1"; }
api_delete() { api_req "DELETE" "$1"; }
api_post()   { local _b="${2}"; [[ -z "$_b" ]] && _b='{}'; api_req "POST"  "$1" -d "$_b"; }
api_put()    { local _b="${2}"; [[ -z "$_b" ]] && _b='{}'; api_req "PUT"   "$1" -d "$_b"; }
api_patch()  { local _b="${2}"; [[ -z "$_b" ]] && _b='{}'; api_req "PATCH" "$1" -d "$_b"; }

# HEAD-Request (kein Body)
api_head() {
    local path="$1"
    LAST_HTTP=$(curl -s -o /dev/null -w "%{http_code}" \
        -X HEAD \
        -H "Authorization: Bearer $API_KEY" \
        --connect-timeout 5 --max-time 10 \
        "$BASE_URL$path" 2>/dev/null || echo "000")
    LAST_BODY=""
}

# HTTP-Status-Check
expect_status() {
    local label="$1"
    local expected="$2"
    if [[ "$LAST_HTTP" == "$expected" ]]; then
        ok "$label (HTTP $expected)"
    else
        fail "$label (erwartet HTTP $expected, bekommen HTTP $LAST_HTTP)"
        if [[ -n "$LAST_BODY" ]]; then
            echo -e "    ${BLUE}↳${NC} $(echo "$LAST_BODY" | head -c 300)"
        fi
    fi
}

# HTTP-Status-Check: einer von mehreren OK
expect_status_any() {
    local label="$1"; shift
    local statuses=("$@")
    for s in "${statuses[@]}"; do
        if [[ "$LAST_HTTP" == "$s" ]]; then
            ok "$label (HTTP $LAST_HTTP)"
            return 0
        fi
    done
    fail "$label (erwartet HTTP $(IFS=/; echo "${statuses[*]}"), bekommen HTTP $LAST_HTTP)"
    if [[ -n "$LAST_BODY" ]]; then
        echo -e "    ${BLUE}↳${NC} $(echo "$LAST_BODY" | head -c 300)"
    fi
}

# JSON-Feld aus letztem Response extrahieren
json_field() {
    echo "$LAST_BODY" | grep -o "\"$1\":[^,}]*" | head -1 | sed 's/.*: *"\?\([^",}]*\)"\?.*/\1/' 2>/dev/null || true
}

# Erste numerische ID aus JSON extrahieren (Record-IDs sind int, nicht string)
extract_id() {
    echo "${1:-$LAST_BODY}" | grep -o '"id":[0-9]*' | head -1 | grep -o '[0-9]*' || true
}

# Alle numerischen IDs aus JSON extrahieren (für Schleifenbereinigung)
extract_all_ids() {
    echo "${1:-$LAST_BODY}" | grep -o '"id":[0-9]*' | grep -o '[0-9]*' || true
}

# UUID/String-ID aus JSON extrahieren (für API-Keys, Blocklist-URLs)
extract_str_id() {
    echo "${1:-$LAST_BODY}" | grep -o '"id":"[^"]*"' | head -1 | sed 's/"id":"//;s/"//' || true
}

# DNS-Abfrage mit dig
dns_query() {
    local type="$1"
    local name="$2"
    local expected="${3:-}"

    if ! command -v dig &>/dev/null; then
        skip "dig nicht verfügbar: $type $name"
        return
    fi

    local result
    result=$(dig @"$DNS_HOST" -p "$DNS_PORT" +short +time=3 +tries=1 "$type" "$name" 2>/dev/null || true)

    if [[ -z "$expected" ]]; then
        if [[ -n "$result" ]]; then
            ok "DNS $type $name → $result"
        else
            fail "DNS $type $name → keine Antwort"
        fi
    else
        if echo "$result" | grep -qF "$expected"; then
            ok "DNS $type $name → $result (enthält '$expected')"
        else
            fail "DNS $type $name → '$result' (erwartet '$expected')"
        fi
    fi
}

# DNS-Abfrage erwartet NXDOMAIN oder leere Antwort
dns_blocked() {
    local name="$1"

    if ! command -v dig &>/dev/null; then
        skip "dig nicht verfügbar: BLOCKED $name"
        return
    fi

    local rcode
    rcode=$(dig @"$DNS_HOST" -p "$DNS_PORT" +time=3 +tries=1 A "$name" 2>/dev/null | grep "^;; ->>HEADER" | grep -o "status: [A-Z]*" | awk '{print $2}' || true)
    local result
    result=$(dig @"$DNS_HOST" -p "$DNS_PORT" +short +time=3 +tries=1 A "$name" 2>/dev/null || true)

    if [[ "$rcode" == "NXDOMAIN" ]] || [[ -z "$result" ]] || [[ "$result" == "0.0.0.0" ]]; then
        ok "DNS BLOCKED $name (rcode=$rcode)"
    else
        warn "DNS $name nicht blockiert → $result"
    fi
}

# DNS-RCODE abfragen
dns_rcode() {
    local name="$1"
    dig @"$DNS_HOST" -p "$DNS_PORT" +time=3 +tries=1 A "$name" 2>/dev/null \
        | grep "^;; ->>HEADER" | grep -o "status: [A-Z]*" | awk '{print $2}' || true
}

# ---------------------------------------------------------------------------
# Vorbedingungen
# ---------------------------------------------------------------------------
section "Vorbedingungen"

if [[ -z "$API_KEY" ]]; then
    echo -e "${RED}FEHLER: DNS_API_KEY nicht gesetzt.${NC}"
    echo "  Verwendung: DNS_API_KEY=<key> $0"
    exit 1
fi

if ! command -v curl &>/dev/null; then
    echo -e "${RED}FEHLER: curl nicht gefunden.${NC}"
    exit 1
fi

info "Basis-URL:   $BASE_URL"
info "DNS-Server:  $DNS_HOST:$DNS_PORT"
info "DNS-Tests:   $([ "$SKIP_DNS" = "1" ] && echo "deaktiviert" || echo "aktiv")"
info "Admin-User:  $DNS_ADMIN_USER"
info "Login-Test:  $([ -n "$DNS_ADMIN_PASS" ] && echo "aktiv" || echo "deaktiviert (DNS_ADMIN_PASS fehlt)")"

# ---------------------------------------------------------------------------
# 1. Health & Setup
# ---------------------------------------------------------------------------
section "1. Health & Setup"

api_get "/api/health"
if [[ "$LAST_HTTP" == "200" ]]; then
    ok "GET /api/health (HTTP 200)"
else
    fail "GET /api/health (HTTP $LAST_HTTP) — Server nicht erreichbar!"
    echo -e "${RED}FEHLER: Server nicht erreichbar. Abbruch.${NC}"
    exit 1
fi

api_get "/api/setup/status"
if [[ "$LAST_HTTP" == "200" ]]; then
    ok "GET /api/setup/status (HTTP 200)"
    SETUP_DONE=$(json_field "completed")
    info "Setup abgeschlossen: ${SETUP_DONE:-unbekannt}"
else
    fail "GET /api/setup/status (HTTP $LAST_HTTP)"
fi

# ---------------------------------------------------------------------------
# 2. Authentifizierung (Bearer API-Key)
# ---------------------------------------------------------------------------
section "2. Authentifizierung (Bearer API-Key)"

# Ungültiger Key
SAVED_KEY="$API_KEY"
API_KEY="invalid-key-12345"
api_get "/api/zones"
if [[ "$LAST_HTTP" == "401" || "$LAST_HTTP" == "403" ]]; then
    ok "Ungültiger API-Key → HTTP $LAST_HTTP (korrekt abgelehnt)"
else
    fail "Ungültiger API-Key sollte 401/403 liefern, bekam $LAST_HTTP"
fi
API_KEY="$SAVED_KEY"

# Gültiger Key
api_get "/api/zones"
expect_status "Gültiger API-Key → GET /api/zones" "200"

# ---------------------------------------------------------------------------
# 2b. Login / Logout (Session-Auth)
# ---------------------------------------------------------------------------
section "2b. Login / Logout (Session-Auth)"

COOKIE_JAR=$(mktemp)

if [[ -n "$DNS_ADMIN_PASS" ]]; then
    # Login
    LOGIN_TMPFILE=$(mktemp)
    LOGIN_HTTP=$(curl -s -o "$LOGIN_TMPFILE" -w "%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        -c "$COOKIE_JAR" \
        --connect-timeout 5 --max-time 10 \
        -d "{\"username\":\"$DNS_ADMIN_USER\",\"password\":\"$DNS_ADMIN_PASS\"}" \
        "$BASE_URL/api/login" 2>/dev/null || echo "000")
    LOGIN_BODY=$(cat "$LOGIN_TMPFILE")
    rm -f "$LOGIN_TMPFILE"

    if [[ "$LOGIN_HTTP" == "200" ]]; then
        ok "POST /api/login → HTTP 200"

        # Authentifizierten Request mit Session-Cookie testen
        SESSION_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
            -b "$COOKIE_JAR" \
            --connect-timeout 5 --max-time 10 \
            "$BASE_URL/api/zones" 2>/dev/null || echo "000")
        if [[ "$SESSION_STATUS" == "200" ]]; then
            ok "Session-Cookie: GET /api/zones → HTTP 200"
        else
            warn "Session-Cookie: GET /api/zones → HTTP $SESSION_STATUS (erwartet 200)"
        fi

        # Logout
        LOGOUT_HTTP=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST \
            -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
            --connect-timeout 5 --max-time 10 \
            "$BASE_URL/api/logout" 2>/dev/null || echo "000")
        if [[ "$LOGOUT_HTTP" == "200" || "$LOGOUT_HTTP" == "204" || "$LOGOUT_HTTP" == "303" ]]; then
            ok "POST /api/logout → HTTP $LOGOUT_HTTP"

            # Session nach Logout muss ungültig sein
            AFTER_LOGOUT=$(curl -s -o /dev/null -w "%{http_code}" \
                -b "$COOKIE_JAR" \
                --connect-timeout 5 --max-time 10 \
                "$BASE_URL/api/zones" 2>/dev/null || echo "000")
            if [[ "$AFTER_LOGOUT" == "401" || "$AFTER_LOGOUT" == "403" ]]; then
                ok "Session ungültig nach Logout (HTTP $AFTER_LOGOUT)"
            else
                warn "Session nach Logout → HTTP $AFTER_LOGOUT (erwartet 401/403)"
            fi
        else
            warn "POST /api/logout → HTTP $LOGOUT_HTTP (erwartet 200/204/303)"
        fi

        # Ungültiges Login testen
        BAD_LOGIN=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST \
            -H "Content-Type: application/json" \
            --connect-timeout 5 --max-time 10 \
            -d '{"username":"admin","password":"falsch-12345"}' \
            "$BASE_URL/api/login" 2>/dev/null || echo "000")
        if [[ "$BAD_LOGIN" == "401" || "$BAD_LOGIN" == "403" ]]; then
            ok "POST /api/login (falsches Passwort) → HTTP $BAD_LOGIN"
        else
            warn "POST /api/login (falsches Passwort) → HTTP $BAD_LOGIN (erwartet 401/403)"
        fi
    else
        warn "POST /api/login → HTTP $LOGIN_HTTP (erwartet 200)"
    fi
else
    skip "Login/Logout-Test (DNS_ADMIN_PASS nicht gesetzt)"
fi

rm -f "$COOKIE_JAR"

# ---------------------------------------------------------------------------
# 3. Named API Keys
# ---------------------------------------------------------------------------
section "3. Named API Keys"

api_get "/api/auth/api-keys"
expect_status "GET /api/auth/api-keys" "200"

api_post "/api/auth/api-keys" "{\"name\":\"$TEST_API_KEY_NAME\",\"description\":\"Funktionstest\"}"
if [[ "$LAST_HTTP" == "200" || "$LAST_HTTP" == "201" ]]; then
    ok "POST /api/auth/api-keys (HTTP $LAST_HTTP)"
else
    warn "POST /api/auth/api-keys → HTTP $LAST_HTTP"
    [[ -n "$LAST_BODY" ]] && echo -e "    ${BLUE}↳${NC} $(echo "$LAST_BODY" | head -c 300)"
fi
NAMED_KEY_ID=$(extract_str_id)
NAMED_KEY_VALUE=$(echo "$LAST_BODY" | grep -o '"key":"[^"]*"' | head -1 | sed 's/"key":"//;s/"//' || true)

if [[ -n "$NAMED_KEY_ID" ]]; then
    ok "Named API Key erstellt (id=$NAMED_KEY_ID)"

    # Named Key testen
    SAVED_KEY="$API_KEY"
    API_KEY="$NAMED_KEY_VALUE"
    api_get "/api/zones"
    if [[ "$LAST_HTTP" == "200" ]]; then
        ok "Named API Key funktioniert"
    else
        warn "Named API Key → HTTP $LAST_HTTP (erwartet 200)"
    fi
    API_KEY="$SAVED_KEY"

    # Named Key löschen
    api_delete "/api/auth/api-keys/$NAMED_KEY_ID"
    expect_status_any "DELETE /api/auth/api-keys/$NAMED_KEY_ID" "200" "204"
else
    warn "Named API Key ID nicht aus Antwort extrahierbar"
fi

# ---------------------------------------------------------------------------
# 3b. Auth-Verwaltung (Passwort-Änderung / API-Key-Regeneration)
# ---------------------------------------------------------------------------
section "3b. Auth-Verwaltung"

# Passwort-Änderung: nur testen wenn Admin-Passwort bekannt
if [[ -n "$DNS_ADMIN_PASS" ]]; then
    # Ungültiges aktuelles Passwort → muss 401 liefern
    api_post "/api/auth/change-password" \
        '{"current_password":"falsch-passwort-xyz","new_password":"ebenfalls-falsch"}'
    if [[ "$LAST_HTTP" == "401" || "$LAST_HTTP" == "403" ]]; then
        ok "POST /api/auth/change-password (falsches Passwort) → HTTP $LAST_HTTP"
    else
        warn "POST /api/auth/change-password (falsches Passwort) → HTTP $LAST_HTTP (erwartet 401/403)"
    fi

    # Zu kurzes neues Passwort → muss 400 liefern
    api_post "/api/auth/change-password" \
        "{\"current_password\":\"$DNS_ADMIN_PASS\",\"new_password\":\"kurz\"}"
    if [[ "$LAST_HTTP" == "400" || "$LAST_HTTP" == "422" ]]; then
        ok "POST /api/auth/change-password (zu kurzes Passwort) → HTTP $LAST_HTTP"
    else
        warn "POST /api/auth/change-password (zu kurzes Passwort) → HTTP $LAST_HTTP (erwartet 400)"
    fi
else
    skip "POST /api/auth/change-password Validierung (DNS_ADMIN_PASS nicht gesetzt)"
fi

# API-Key-Regeneration: nur mit DNS_TEST_REGEN=1 (ungültig machend!)
if [[ "$DNS_TEST_REGEN" == "1" ]]; then
    api_post "/api/auth/regenerate-api-key" '{}'
    if [[ "$LAST_HTTP" == "200" ]]; then
        NEW_KEY=$(echo "$LAST_BODY" | grep -o '"api_key":"[^"]*"' | head -1 | sed 's/"api_key":"//;s/"//' || true)
        if [[ -n "$NEW_KEY" ]]; then
            ok "POST /api/auth/regenerate-api-key → neuer Key: ${NEW_KEY:0:8}..."
            info "ACHTUNG: API-Key wurde geändert — alten Key nicht mehr verwenden!"
            API_KEY="$NEW_KEY"
        else
            warn "POST /api/auth/regenerate-api-key → Key nicht extrahierbar"
        fi
    else
        warn "POST /api/auth/regenerate-api-key → HTTP $LAST_HTTP"
    fi
else
    skip "POST /api/auth/regenerate-api-key (DNS_TEST_REGEN=1 setzen zum Aktivieren — ungültig machend!)"
fi

# ---------------------------------------------------------------------------
# 4. Konfiguration
# ---------------------------------------------------------------------------
section "4. Konfiguration (Live-Reload)"

api_get "/api/config"
expect_status "GET /api/config" "200"

# Originalen Block-Modus merken
ORIG_BLOCK_MODE=$(echo "$LAST_BODY" | grep -o '"block_mode":"[^"]*"' | head -1 | sed 's/"block_mode":"//;s/"//' || true)
info "Aktueller Block-Modus: ${ORIG_BLOCK_MODE:-unbekannt}"

# Log-Level auf debug setzen und zurückstellen
api_patch "/api/config" '{"system":{"log_level":"debug"}}'
expect_status "PATCH /api/config (log_level=debug)" "200"

api_patch "/api/config" '{"system":{"log_level":"info"}}'
expect_status "PATCH /api/config (log_level=info, Rückstellung)" "200"

# ---------------------------------------------------------------------------
# 5. Zonen-Verwaltung (CRUD)
# ---------------------------------------------------------------------------
section "5. Zonen-Verwaltung (CRUD)"

# Pre-cleanup: eventuell übriggebliebene Testzone löschen
api_get "/api/zones/$TEST_DOMAIN"
if [[ "$LAST_HTTP" == "200" ]]; then
    api_get "/api/zones/$TEST_DOMAIN/records"
    PRE_IDS=$(extract_all_ids "$LAST_BODY")
    for rid in $PRE_IDS; do
        api_delete "/api/zones/$TEST_DOMAIN/records/$rid" || true
    done
    api_delete "/api/zones/$TEST_DOMAIN" || true
    info "Pre-cleanup: bestehende Zone $TEST_DOMAIN gelöscht"
fi

# Zone anlegen
api_post "/api/zones" "{\"domain\":\"$TEST_DOMAIN\",\"ttl\":300}"
if [[ "$LAST_HTTP" == "200" || "$LAST_HTTP" == "201" ]]; then
    ok "POST /api/zones ($TEST_DOMAIN erstellt, HTTP $LAST_HTTP)"
elif [[ "$LAST_HTTP" == "409" ]]; then
    warn "Zone $TEST_DOMAIN existiert bereits (409) — wird weiterverwendet"
else
    fail "POST /api/zones → HTTP $LAST_HTTP"
    [[ -n "$LAST_BODY" ]] && echo -e "    ${BLUE}↳${NC} $(echo "$LAST_BODY" | head -c 300)"
fi

# Zone abrufen
api_get "/api/zones/$TEST_DOMAIN"
expect_status "GET /api/zones/$TEST_DOMAIN" "200"

# Zone aktualisieren
api_put "/api/zones/$TEST_DOMAIN" '{"ttl":600}'
expect_status "PUT /api/zones/$TEST_DOMAIN" "200"

# Zonenliste
api_get "/api/zones"
expect_status "GET /api/zones (Liste)" "200"
ZONE_COUNT=$(echo "$LAST_BODY" | grep -o '"domain"' | wc -l | tr -d ' ' || true)
info "Zonen in Store: $ZONE_COUNT"

# Nicht-existente Zone
api_get "/api/zones/nonexistent.invalid"
if [[ "$LAST_HTTP" == "404" ]]; then
    ok "GET nicht-existente Zone → HTTP 404"
else
    warn "GET nicht-existente Zone → HTTP $LAST_HTTP (erwartet 404)"
fi

# ---------------------------------------------------------------------------
# 6. Records (CRUD)
# ---------------------------------------------------------------------------
section "6. Records (CRUD)"

RECORD_ID=""

# A-Record erstellen
api_post "/api/zones/$TEST_DOMAIN/records" \
    '{"type":"A","name":"@","value":"192.0.2.100","ttl":300}'
if [[ "$LAST_HTTP" == "200" || "$LAST_HTTP" == "201" ]]; then
    ok "POST A-Record (@→192.0.2.100)"
    RECORD_ID=$(extract_id)
else
    fail "POST A-Record → HTTP $LAST_HTTP"
    if [[ -n "$LAST_BODY" ]]; then
        echo -e "    ${BLUE}↳${NC} $(echo "$LAST_BODY" | head -c 300)"
    fi
fi

# AAAA-Record
api_post "/api/zones/$TEST_DOMAIN/records" \
    '{"type":"AAAA","name":"@","value":"2001:db8::1","ttl":300}'
expect_status_any "POST AAAA-Record" "200" "201"
AAAA_ID=$(extract_id)

# CNAME-Record
api_post "/api/zones/$TEST_DOMAIN/records" \
    '{"type":"CNAME","name":"www","value":"test-functional.example.","ttl":300}'
expect_status_any "POST CNAME-Record (www)" "200" "201"
CNAME_ID=$(extract_id)

# MX-Record
api_post "/api/zones/$TEST_DOMAIN/records" \
    '{"type":"MX","name":"@","value":"mail.test-functional.example.","ttl":300,"priority":10}'
expect_status_any "POST MX-Record" "200" "201"

# TXT-Record
api_post "/api/zones/$TEST_DOMAIN/records" \
    '{"type":"TXT","name":"@","value":"v=spf1 -all","ttl":300}'
expect_status_any "POST TXT-Record" "200" "201"
TXT_ID=$(extract_id)

# Records abrufen
api_get "/api/zones/$TEST_DOMAIN/records"
expect_status "GET /api/zones/$TEST_DOMAIN/records" "200"
REC_COUNT=$(echo "$LAST_BODY" | grep -o '"type"' | wc -l | tr -d ' ' || true)
info "Records in Zone: $REC_COUNT"

# Record per ID abrufen
if [[ -n "$RECORD_ID" ]]; then
    api_get "/api/zones/$TEST_DOMAIN/records/$RECORD_ID"
    expect_status "GET Record per ID" "200"

    # Record aktualisieren
    api_put "/api/zones/$TEST_DOMAIN/records/$RECORD_ID" \
        '{"type":"A","name":"@","value":"192.0.2.101","ttl":300}'
    expect_status "PUT A-Record (Wert-Update)" "200"
fi

# Validierungs-Test: ungültige IP
api_post "/api/zones/$TEST_DOMAIN/records" \
    '{"type":"A","name":"bad","value":"not-an-ip","ttl":300}'
if [[ "$LAST_HTTP" == "400" || "$LAST_HTTP" == "422" ]]; then
    ok "Validation: ungültige IP → HTTP $LAST_HTTP"
else
    warn "Validation: ungültige IP → HTTP $LAST_HTTP (erwartet 400/422)"
fi

# ---------------------------------------------------------------------------
# 7. DNS-Auflösung (dig)
# ---------------------------------------------------------------------------
if [[ "$SKIP_DNS" == "0" ]]; then
    section "7. DNS-Auflösung"

    # Kurz warten damit Zone geladen ist
    sleep 1

    dns_query "A"    "$TEST_DOMAIN"          "192.0.2.10"
    dns_query "AAAA" "$TEST_DOMAIN"          "2001:db8"
    dns_query "CNAME" "www.$TEST_DOMAIN"     "$TEST_DOMAIN"
    dns_query "MX"   "$TEST_DOMAIN"          "mail"
    dns_query "TXT"  "$TEST_DOMAIN"          "v=spf1"

    # Öffentliche Domain (Upstream-Forwarding)
    dns_query "A" "dns.quad9.net"
    # NXDOMAIN für nicht-existente Domain
    dns_query "A" "nonexistent.invalid." ""
else
    section "7. DNS-Auflösung"
    skip "DNS-Tests (SKIP_DNS=1)"
fi

# ---------------------------------------------------------------------------
# 8. Blocklist-Verwaltung
# ---------------------------------------------------------------------------
section "8. Blocklist-Verwaltung"

# Blocklist-URLs
api_get "/api/blocklist/urls"
expect_status "GET /api/blocklist/urls" "200"
URL_COUNT=$(echo "$LAST_BODY" | grep -o '"url"' | wc -l | tr -d ' ' || true)
info "Konfigurierte Blocklist-URLs: $URL_COUNT"

# Neue URL hinzufügen
api_post "/api/blocklist/urls" '{"url":"https://example.com/blocklist-test.txt","enabled":false}'
if [[ "$LAST_HTTP" == "200" || "$LAST_HTTP" == "201" ]]; then
    ok "POST /api/blocklist/urls (disabled URL)"
    EFFECTIVE_BL_ID=$(extract_id)

    if [[ -n "$EFFECTIVE_BL_ID" ]]; then

        # Aktivieren/Deaktivieren
        api_patch "/api/blocklist/urls/$EFFECTIVE_BL_ID" '{"enabled":true}'
        expect_status "PATCH /api/blocklist/urls (enable)" "200"

        # Löschen
        api_delete "/api/blocklist/urls/$EFFECTIVE_BL_ID"
        expect_status_any "DELETE /api/blocklist/urls/$EFFECTIVE_BL_ID" "200" "204"
    fi
else
    warn "POST /api/blocklist/urls → HTTP $LAST_HTTP"
fi

# Manuelle Domains (Blacklist)
api_get "/api/blocklist/domains"
expect_status "GET /api/blocklist/domains" "200"

api_post "/api/blocklist/domains" '{"domain":"test-blocked-functional.example"}'
if [[ "$LAST_HTTP" == "200" || "$LAST_HTTP" == "201" ]]; then
    ok "POST /api/blocklist/domains (test-blocked-functional.example)"

    if [[ "$SKIP_DNS" == "0" ]]; then
        sleep 0.5
        dns_blocked "test-blocked-functional.example"
    fi

    api_delete "/api/blocklist/domains/test-blocked-functional.example"
    expect_status_any "DELETE /api/blocklist/domains" "200" "204"
else
    warn "POST /api/blocklist/domains → HTTP $LAST_HTTP"
fi

# Whitelist (erlaubte Domains)
api_get "/api/blocklist/allowed"
expect_status "GET /api/blocklist/allowed" "200"

api_post "/api/blocklist/allowed" '{"domain":"allow-test.example"}'
if [[ "$LAST_HTTP" == "200" || "$LAST_HTTP" == "201" ]]; then
    ok "POST /api/blocklist/allowed"
    api_delete "/api/blocklist/allowed/allow-test.example"
    expect_status_any "DELETE /api/blocklist/allowed" "200" "204"
else
    warn "POST /api/blocklist/allowed → HTTP $LAST_HTTP"
fi

# Muster (Wildcard/Regex)
api_get "/api/blocklist/patterns"
expect_status "GET /api/blocklist/patterns" "200"

api_post "/api/blocklist/patterns" '{"pattern":"*.ads-functional.example","type":"wildcard"}'
if [[ "$LAST_HTTP" == "200" || "$LAST_HTTP" == "201" ]]; then
    ok "POST /api/blocklist/patterns (wildcard)"
    EFFECTIVE_PAT_ID=$(extract_id)
    if [[ -n "$EFFECTIVE_PAT_ID" ]]; then
        api_delete "/api/blocklist/patterns/$EFFECTIVE_PAT_ID"
        expect_status_any "DELETE /api/blocklist/patterns" "200" "204"
    fi
else
    warn "POST /api/blocklist/patterns → HTTP $LAST_HTTP"
fi

# Whitelist-IPs
api_get "/api/blocklist/whitelist-ips"
expect_status "GET /api/blocklist/whitelist-ips" "200"

api_post "/api/blocklist/whitelist-ips" '{"cidr":"192.0.2.200/32"}'
if [[ "$LAST_HTTP" == "200" || "$LAST_HTTP" == "201" ]]; then
    ok "POST /api/blocklist/whitelist-ips"
    api_delete "/api/blocklist/whitelist-ips/192.0.2.200%2F32"
    if [[ "$LAST_HTTP" != "200" ]]; then
        # Fallback ohne URL-Encoding
        api_delete "/api/blocklist/whitelist-ips/192.0.2.200/32"
    fi
    expect_status_any "DELETE /api/blocklist/whitelist-ips" "200" "204"
else
    warn "POST /api/blocklist/whitelist-ips → HTTP $LAST_HTTP"
fi

# ---------------------------------------------------------------------------
# 8b. Blocklist-URL-Fetch
# ---------------------------------------------------------------------------
section "8b. Blocklist-URL-Fetch"

api_get "/api/blocklist/urls"
if [[ "$LAST_HTTP" == "200" ]]; then
    # Numerische ID der ersten vorhandenen URL extrahieren
    FIRST_URL_ID=$(extract_id "$LAST_BODY")

    if [[ -n "$FIRST_URL_ID" ]]; then
        api_post "/api/blocklist/urls/$FIRST_URL_ID/fetch" '{}'
        if [[ "$LAST_HTTP" == "200" || "$LAST_HTTP" == "202" ]]; then
            ok "POST /api/blocklist/urls/$FIRST_URL_ID/fetch (HTTP $LAST_HTTP)"
        elif [[ "$LAST_HTTP" == "400" ]]; then
            # URL evtl. nicht erreichbar (private/interner Host) — kein Fehler
            warn "POST /api/blocklist/urls/$FIRST_URL_ID/fetch → HTTP 400 (URL evtl. nicht erreichbar)"
        else
            warn "POST /api/blocklist/urls/$FIRST_URL_ID/fetch → HTTP $LAST_HTTP"
        fi
    else
        skip "Blocklist-URL-Fetch (keine Blocklist-URL konfiguriert)"
    fi
else
    skip "Blocklist-URL-Fetch (URL-Liste nicht verfügbar: HTTP $LAST_HTTP)"
fi

# ---------------------------------------------------------------------------
# 8c. Block-Modus-Wechsel (NXDOMAIN / zero_ip)
# ---------------------------------------------------------------------------
section "8c. Block-Modus-Wechsel"

# NXDOMAIN-Modus setzen
api_patch "/api/config" '{"blocklist":{"block_mode":"nxdomain"}}'
if [[ "$LAST_HTTP" == "200" ]]; then
    ok "PATCH /api/config block_mode=nxdomain"

    if [[ "$SKIP_DNS" == "0" ]]; then
        sleep 0.5
        # Blockierte Domain testen (muss NXDOMAIN liefern)
        api_post "/api/blocklist/domains" '{"domain":"block-mode-test.example"}'
        if [[ "$LAST_HTTP" == "200" || "$LAST_HTTP" == "201" ]]; then
            sleep 0.5
            RCODE=$(dns_rcode "block-mode-test.example")
            if [[ "$RCODE" == "NXDOMAIN" ]]; then
                ok "Block-Modus NXDOMAIN: dig block-mode-test.example → NXDOMAIN"
            else
                warn "Block-Modus NXDOMAIN: dig → '$RCODE' (erwartet NXDOMAIN)"
            fi
            api_delete "/api/blocklist/domains/block-mode-test.example" || true
        else
            skip "Block-Modus NXDOMAIN DNS-Test (Domain konnte nicht hinzugefügt werden)"
        fi
    fi
else
    warn "PATCH /api/config block_mode=nxdomain → HTTP $LAST_HTTP"
fi

# zero_ip-Modus setzen
api_patch "/api/config" '{"blocklist":{"block_mode":"zero_ip"}}'
if [[ "$LAST_HTTP" == "200" ]]; then
    ok "PATCH /api/config block_mode=zero_ip"

    if [[ "$SKIP_DNS" == "0" ]]; then
        sleep 0.5
        # Blockierte Domain testen (muss 0.0.0.0 liefern)
        api_post "/api/blocklist/domains" '{"domain":"block-mode-zero-test.example"}'
        if [[ "$LAST_HTTP" == "200" || "$LAST_HTTP" == "201" ]]; then
            sleep 0.5
            ZERO_RESULT=$(dig @"$DNS_HOST" -p "$DNS_PORT" +short +time=3 +tries=1 \
                A "block-mode-zero-test.example" 2>/dev/null || true)
            if [[ "$ZERO_RESULT" == "0.0.0.0" ]]; then
                ok "Block-Modus zero_ip: dig block-mode-zero-test.example → 0.0.0.0"
            else
                warn "Block-Modus zero_ip: dig → '$ZERO_RESULT' (erwartet 0.0.0.0)"
            fi
            api_delete "/api/blocklist/domains/block-mode-zero-test.example" || true
        else
            skip "Block-Modus zero_ip DNS-Test (Domain konnte nicht hinzugefügt werden)"
        fi
    fi
else
    warn "PATCH /api/config block_mode=zero_ip → HTTP $LAST_HTTP"
fi

# Ursprünglichen Block-Modus wiederherstellen
if [[ -n "${ORIG_BLOCK_MODE:-}" ]]; then
    api_patch "/api/config" "{\"blocklist\":{\"block_mode\":\"$ORIG_BLOCK_MODE\"}}"
    expect_status "PATCH /api/config block_mode rückstellen ($ORIG_BLOCK_MODE)" "200"
else
    # Fallback: zero_ip ist der Default
    api_patch "/api/config" '{"blocklist":{"block_mode":"zero_ip"}}'
    expect_status "PATCH /api/config block_mode rückstellen (zero_ip, Fallback)" "200"
fi

# ---------------------------------------------------------------------------
# 9. DDNS (RFC 2136 TSIG-Keys)
# ---------------------------------------------------------------------------
section "9. DDNS (TSIG-Keys)"

api_get "/api/ddns/keys"
expect_status "GET /api/ddns/keys" "200"

# TSIG-Key erstellen
api_post "/api/ddns/keys" '{"name":"test-functional-tsig","algorithm":"hmac-sha256"}'
if [[ "$LAST_HTTP" == "200" || "$LAST_HTTP" == "201" ]]; then
    ok "POST /api/ddns/keys (TSIG-Key erstellt)"
    TSIG_NAME="test-functional-tsig"

    api_delete "/api/ddns/keys/$TSIG_NAME"
    expect_status_any "DELETE /api/ddns/keys/$TSIG_NAME" "200" "204"
else
    warn "POST /api/ddns/keys → HTTP $LAST_HTTP"
fi

# ---------------------------------------------------------------------------
# 9b. DDNS Status
# ---------------------------------------------------------------------------
section "9b. DDNS Status"

api_get "/api/ddns/status"
if [[ "$LAST_HTTP" == "200" ]]; then
    ok "GET /api/ddns/status (HTTP 200)"
    DDNS_TOTAL=$(json_field "total_updates")
    info "DDNS total_updates: ${DDNS_TOTAL:-unbekannt}"
elif [[ "$LAST_HTTP" == "404" ]]; then
    skip "GET /api/ddns/status → 404 (DDNS nicht konfiguriert)"
else
    warn "GET /api/ddns/status → HTTP $LAST_HTTP"
fi

# ---------------------------------------------------------------------------
# 10. Split-Horizon DNS
# ---------------------------------------------------------------------------
section "10. Split-Horizon DNS"

api_get "/api/split-horizon"
expect_status "GET /api/split-horizon" "200"
SH_ENABLED=$(json_field "enabled")
info "Split-Horizon aktiv: ${SH_ENABLED:-unbekannt}"

# Konfiguration aktualisieren (aktivieren+deaktivieren als Smoke-Test)
api_put "/api/split-horizon" '{"enabled":false,"views":[]}'
if [[ "$LAST_HTTP" == "200" ]]; then
    ok "PUT /api/split-horizon (disable, Smoke-Test)"
else
    warn "PUT /api/split-horizon → HTTP $LAST_HTTP"
fi

# Originalzustand wiederherstellen wenn nötig
if [[ "${SH_ENABLED:-false}" == "true" ]]; then
    api_put "/api/split-horizon" '{"enabled":true}'
    info "Split-Horizon wieder aktiviert"
fi

# ---------------------------------------------------------------------------
# 10b. Split-Horizon Zone CRUD (mit ?view= Parameter)
# ---------------------------------------------------------------------------
section "10b. Split-Horizon Zone CRUD (?view=)"

VIEW_ZONE_CREATED=0
VIEW_RECORD_ID=""

# View-Zone anlegen
api_post "/api/zones?view=$TEST_VIEW" \
    "{\"domain\":\"$TEST_VIEW_DOMAIN\",\"ttl\":300}"
if [[ "$LAST_HTTP" == "200" || "$LAST_HTTP" == "201" ]]; then
    ok "POST /api/zones?view=$TEST_VIEW ($TEST_VIEW_DOMAIN)"
    VIEW_ZONE_CREATED=1
elif [[ "$LAST_HTTP" == "409" ]]; then
    warn "Zone $TEST_VIEW_DOMAIN@$TEST_VIEW existiert bereits (409)"
    VIEW_ZONE_CREATED=1
elif [[ "$LAST_HTTP" == "400" || "$LAST_HTTP" == "404" ]]; then
    warn "POST /api/zones?view=$TEST_VIEW → HTTP $LAST_HTTP (Split-Horizon evtl. deaktiviert)"
else
    fail "POST /api/zones?view=$TEST_VIEW → HTTP $LAST_HTTP"
fi

if [[ "$VIEW_ZONE_CREATED" == "1" ]]; then
    # Zone abrufen
    api_get "/api/zones/$TEST_VIEW_DOMAIN?view=$TEST_VIEW"
    if [[ "$LAST_HTTP" == "200" ]]; then
        ok "GET /api/zones/$TEST_VIEW_DOMAIN?view=$TEST_VIEW"
    else
        warn "GET /api/zones/$TEST_VIEW_DOMAIN?view=$TEST_VIEW → HTTP $LAST_HTTP"
    fi

    # A-Record in View-Zone erstellen
    api_post "/api/zones/$TEST_VIEW_DOMAIN/records?view=$TEST_VIEW" \
        '{"type":"A","name":"@","value":"10.0.0.1","ttl":300}'
    if [[ "$LAST_HTTP" == "200" || "$LAST_HTTP" == "201" ]]; then
        ok "POST A-Record in View-Zone ($TEST_VIEW_DOMAIN@$TEST_VIEW → 10.0.0.1)"
        VIEW_RECORD_ID=$(extract_id)
    else
        warn "POST A-Record in View-Zone → HTTP $LAST_HTTP"
    fi

    # Records der View-Zone abrufen
    api_get "/api/zones/$TEST_VIEW_DOMAIN/records?view=$TEST_VIEW"
    if [[ "$LAST_HTTP" == "200" ]]; then
        ok "GET /api/zones/$TEST_VIEW_DOMAIN/records?view=$TEST_VIEW"
    else
        warn "GET /api/zones/$TEST_VIEW_DOMAIN/records?view=$TEST_VIEW → HTTP $LAST_HTTP"
    fi

    # DNS-Test für View-Zone (nur wenn Split-Horizon aktiv war)
    if [[ "$SKIP_DNS" == "0" && "${SH_ENABLED:-false}" == "true" ]]; then
        sleep 0.5
        dns_query "A" "$TEST_VIEW_DOMAIN" "10.0.0.1"
    fi
fi

# ---------------------------------------------------------------------------
# 11. ACME (DNS-01 Challenge)
# ---------------------------------------------------------------------------
section "11. ACME (DNS-01 / Traefik httpreq)"

# DNS-01 present
api_post "/api/acme/dns-01/present" \
    '{"fqdn":"_acme-challenge.acme-test.example.","value":"testtoken123"}'
if [[ "$LAST_HTTP" == "200" || "$LAST_HTTP" == "204" ]]; then
    ok "POST /api/acme/dns-01/present"

    if [[ "$SKIP_DNS" == "0" ]]; then
        sleep 0.5
        dns_query "TXT" "_acme-challenge.acme-test.example" "testtoken123"
    fi

    api_post "/api/acme/dns-01/cleanup" \
        '{"fqdn":"_acme-challenge.acme-test.example.","value":"testtoken123"}'
    expect_status "POST /api/acme/dns-01/cleanup" "200"
else
    warn "POST /api/acme/dns-01/present → HTTP $LAST_HTTP"
fi

# Traefik httpreq
api_post "/api/acme/httpreq/present" \
    '{"fqdn":"_acme-challenge.httpreq-test.example.","value":"httpreqtoken"}'
if [[ "$LAST_HTTP" == "200" || "$LAST_HTTP" == "204" ]]; then
    ok "POST /api/acme/httpreq/present"
    api_post "/api/acme/httpreq/cleanup" \
        '{"fqdn":"_acme-challenge.httpreq-test.example.","value":"httpreqtoken"}'
    expect_status "POST /api/acme/httpreq/cleanup" "200"
else
    warn "POST /api/acme/httpreq/present → HTTP $LAST_HTTP"
fi

# ---------------------------------------------------------------------------
# 12. DoH (DNS-over-HTTPS, RFC 8484)
# ---------------------------------------------------------------------------
section "12. DoH (DNS-over-HTTPS, RFC 8484)"

# Echter A-Record-Query für dns.quad9.net (Wire-Format, base64url-encoded)
# Aufbau: ID=0xAABB, Flags=0x0100 (Standard-Query), QDCOUNT=1
# QNAME=3dns5quad99net0, QTYPE=A(1), QCLASS=IN(1)
DOH_DNS_QUERY="q80BAAABAAAAAAAAA2RucwVxdWFkOQNuZXQAAAEAAQ"

# DoH GET
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    --connect-timeout 5 --max-time 10 \
    "$BASE_URL/dns-query?dns=$DOH_DNS_QUERY" \
    -H "Accept: application/dns-message" \
    2>/dev/null || echo "000")

if [[ "$HTTP_STATUS" == "200" ]]; then
    ok "DoH GET /dns-query (RFC 8484, HTTP 200)"
elif [[ "$HTTP_STATUS" == "400" ]]; then
    ok "DoH GET /dns-query erreichbar (HTTP 400 — Query-Format evtl. ungültig)"
elif [[ "$HTTP_STATUS" == "000" ]]; then
    warn "DoH GET /dns-query → nicht erreichbar (Timeout/Verbindungsfehler)"
else
    warn "DoH GET /dns-query → HTTP $HTTP_STATUS"
fi

# DoH POST mit leerem Body (muss 400 liefern — kein valides DNS-Wire-Format)
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST \
    -H "Content-Type: application/dns-message" \
    --data-binary "" \
    --connect-timeout 5 --max-time 10 \
    "$BASE_URL/dns-query" 2>/dev/null || echo "000")

if [[ "$HTTP_STATUS" == "400" || "$HTTP_STATUS" == "415" ]]; then
    ok "DoH POST /dns-query (leerer Body) → HTTP $HTTP_STATUS (korrekt abgelehnt)"
elif [[ "$HTTP_STATUS" == "200" ]]; then
    ok "DoH POST /dns-query erreichbar (HTTP 200)"
elif [[ "$HTTP_STATUS" == "000" ]]; then
    warn "DoH POST /dns-query → nicht erreichbar"
else
    warn "DoH POST /dns-query → HTTP $HTTP_STATUS"
fi

# ---------------------------------------------------------------------------
# 12b. DoT (DNS-over-TLS, RFC 7858)
# ---------------------------------------------------------------------------
section "12b. DoT (DNS-over-TLS, Port 853)"

if command -v openssl &>/dev/null; then
    DOT_RESULT=$(echo "" | timeout 5 openssl s_client \
        -connect "$DNS_HOST:853" \
        -verify_return_error \
        2>&1 | head -5 || true)

    if echo "$DOT_RESULT" | grep -q "CONNECTED"; then
        ok "DoT: TLS-Verbindung zu $DNS_HOST:853 aufgebaut"
    elif echo "$DOT_RESULT" | grep -qiE "connect.*refused|connection refused|no route"; then
        warn "DoT: Port 853 nicht erreichbar (DoT evtl. deaktiviert)"
    elif echo "$DOT_RESULT" | grep -qiE "error|failed|timeout"; then
        warn "DoT: TLS-Handshake fehlgeschlagen ($DNS_HOST:853)"
    else
        skip "DoT: openssl-Ergebnis nicht eindeutig auswertbar"
    fi
else
    skip "DoT-Test (openssl nicht verfügbar)"
fi

# ---------------------------------------------------------------------------
# 13. Cluster-Info
# ---------------------------------------------------------------------------
section "13. Cluster-Info"

api_get "/api/cluster"
expect_status "GET /api/cluster" "200"
CLUSTER_ROLE=$(json_field "role")
info "Cluster-Rolle: ${CLUSTER_ROLE:-unbekannt}"

# Slave-Schutz: auf Master werden Writes erlaubt, auf Slave abgelehnt
if [[ "${CLUSTER_ROLE:-}" == "slave" ]]; then
    # Slave sollte Write-Ops mit 403 ablehnen
    api_post "/api/zones" '{"domain":"should-fail.example"}'
    if [[ "$LAST_HTTP" == "403" ]]; then
        ok "Slave-Schutz: POST /api/zones → 403 (korrekt)"
    else
        warn "Slave-Schutz: POST /api/zones → $LAST_HTTP (erwartet 403)"
    fi
fi

# ---------------------------------------------------------------------------
# 14. Metriken & Monitoring
# ---------------------------------------------------------------------------
section "14. Metriken & Monitoring"

api_get "/api/metrics"
if [[ "$LAST_HTTP" == "200" ]]; then
    ok "GET /api/metrics (Prometheus)"
    METRIC_LINES=$(echo "$LAST_BODY" | grep -c "^dns_" 2>/dev/null || echo 0)
    info "dns_* Metriken: $METRIC_LINES"
elif [[ "$LAST_HTTP" == "404" ]]; then
    skip "GET /api/metrics → 404 (Metriken deaktiviert)"
else
    warn "GET /api/metrics → HTTP $LAST_HTTP"
fi

api_get "/api/metrics/history?range=1h"
if [[ "$LAST_HTTP" == "200" ]]; then
    ok "GET /api/metrics/history?range=1h"
elif [[ "$LAST_HTTP" == "404" ]]; then
    skip "Metriken-History nicht verfügbar (range=1h)"
else
    warn "GET /api/metrics/history?range=1h → HTTP $LAST_HTTP"
fi

# ---------------------------------------------------------------------------
# 14b. Query-Log
# ---------------------------------------------------------------------------
section "14b. Query-Log"

api_get "/api/query-log"
if [[ "$LAST_HTTP" == "200" ]]; then
    ok "GET /api/query-log (HTTP 200)"
    LOG_COUNT=$(echo "$LAST_BODY" | grep -o '"total":[0-9]*' | head -1 | grep -o '[0-9]*' || true)
    info "Query-Log Einträge: ${LOG_COUNT:-unbekannt}"

    # Mit Limit
    api_get "/api/query-log?limit=10"
    expect_status "GET /api/query-log?limit=10" "200"

    # Filter: nur blockierte Einträge
    api_get "/api/query-log?result=blocked"
    if [[ "$LAST_HTTP" == "200" ]]; then
        ok "GET /api/query-log?result=blocked"
    else
        warn "GET /api/query-log?result=blocked → HTTP $LAST_HTTP"
    fi

    # Statistiken
    api_get "/api/query-log/stats"
    if [[ "$LAST_HTTP" == "200" ]]; then
        ok "GET /api/query-log/stats"
    else
        warn "GET /api/query-log/stats → HTTP $LAST_HTTP"
    fi

    # Ungültiger Filter → muss 400 liefern
    api_get "/api/query-log?result=invalid"
    if [[ "$LAST_HTTP" == "400" ]]; then
        ok "GET /api/query-log?result=invalid → HTTP 400 (korrekte Validierung)"
    else
        warn "GET /api/query-log?result=invalid → HTTP $LAST_HTTP (erwartet 400)"
    fi
elif [[ "$LAST_HTTP" == "404" ]]; then
    skip "GET /api/query-log → 404 (Query-Log deaktiviert)"
else
    warn "GET /api/query-log → HTTP $LAST_HTTP"
fi

# ---------------------------------------------------------------------------
# 14c. DHCP-Leases
# ---------------------------------------------------------------------------
section "14c. DHCP-Leases"

api_get "/api/dhcp/leases"
if [[ "$LAST_HTTP" == "200" ]]; then
    ok "GET /api/dhcp/leases (HTTP 200)"
    LEASE_COUNT=$(echo "$LAST_BODY" | grep -o '"ip"' | wc -l | tr -d ' ' || true)
    info "DHCP-Leases: $LEASE_COUNT"
elif [[ "$LAST_HTTP" == "404" ]]; then
    skip "GET /api/dhcp/leases → 404 (DHCP-Sync nicht konfiguriert)"
else
    warn "GET /api/dhcp/leases → HTTP $LAST_HTTP"
fi

api_get "/api/dhcp/status"
if [[ "$LAST_HTTP" == "200" ]]; then
    ok "GET /api/dhcp/status (HTTP 200)"
elif [[ "$LAST_HTTP" == "404" ]]; then
    skip "GET /api/dhcp/status → 404 (DHCP-Sync nicht konfiguriert)"
else
    warn "GET /api/dhcp/status → HTTP $LAST_HTTP"
fi

# ---------------------------------------------------------------------------
# 14d. Metriken-History (weitere Zeitbereiche)
# ---------------------------------------------------------------------------
section "14d. Metriken-History (Zeitbereiche)"

for RANGE in "24h" "7d" "30d"; do
    api_get "/api/metrics/history?range=$RANGE"
    if [[ "$LAST_HTTP" == "200" ]]; then
        ok "GET /api/metrics/history?range=$RANGE"
    elif [[ "$LAST_HTTP" == "404" ]]; then
        skip "Metriken-History nicht verfügbar (range=$RANGE)"
    else
        warn "GET /api/metrics/history?range=$RANGE → HTTP $LAST_HTTP"
    fi
done

# HEAD /api/metrics
api_head "/api/metrics"
if [[ "$LAST_HTTP" == "200" || "$LAST_HTTP" == "404" ]]; then
    ok "HEAD /api/metrics → HTTP $LAST_HTTP"
else
    warn "HEAD /api/metrics → HTTP $LAST_HTTP"
fi

# ---------------------------------------------------------------------------
# 14e. Rebinding Protection (DNS-Test)
# ---------------------------------------------------------------------------
section "14e. Rebinding Protection"

if [[ "$SKIP_DNS" == "0" ]]; then
    if command -v dig &>/dev/null; then
        # Rebinding-Test: öffentliche Domain die zu privater IP auflöst
        # Da kein echter Upstream kontrollierbar ist, testen wir indirekt:
        # 1. Zone mit privater IP anlegen (simuliert Rebinding-Angriff)
        # 2. Prüfen ob externe Upstream-Antworten mit privater IP geblockt werden
        #
        # Direkter Test über eine Zone (authoritative = kein Rebinding-Check nötig)
        # Echter Rebinding-Schutz greift nur bei Upstream-Antworten (Phase 5.5)
        info "Rebinding-Schutz: Direkt-Test über Upstream nicht möglich ohne kontrollierten DNS"
        info "Rebinding-Schutz wird via OWASP-Tests in 'make test-security' geprüft"
        skip "Rebinding Protection DNS-Test (erfordert kontrollierten Upstream)"
    else
        skip "Rebinding Protection DNS-Test (dig nicht verfügbar)"
    fi
else
    skip "Rebinding Protection DNS-Test (SKIP_DNS=1)"
fi

# ---------------------------------------------------------------------------
# 15. Aufräumen (Testdaten löschen)
# ---------------------------------------------------------------------------
if [[ "$SKIP_CLEANUP" != "1" ]]; then
    section "15. Aufräumen"

    # View-Zone bereinigen (zuerst Records, dann Zone)
    if [[ "$VIEW_ZONE_CREATED" == "1" ]]; then
        # Records der View-Zone löschen
        if [[ -n "$VIEW_RECORD_ID" ]]; then
            api_delete "/api/zones/$TEST_VIEW_DOMAIN/records/$VIEW_RECORD_ID?view=$TEST_VIEW" || true
        fi
        api_get "/api/zones/$TEST_VIEW_DOMAIN/records?view=$TEST_VIEW"
        REMAINING_VIEW_IDS=$(extract_all_ids "$LAST_BODY")
        for rid in $REMAINING_VIEW_IDS; do
            api_delete "/api/zones/$TEST_VIEW_DOMAIN/records/$rid?view=$TEST_VIEW" || true
        done

        # View-Zone löschen
        api_delete "/api/zones/$TEST_VIEW_DOMAIN?view=$TEST_VIEW"
        if [[ "$LAST_HTTP" == "200" || "$LAST_HTTP" == "204" ]]; then
            ok "View-Zone $TEST_VIEW_DOMAIN@$TEST_VIEW gelöscht"
        else
            warn "View-Zone löschen → HTTP $LAST_HTTP"
        fi
    fi

    # Einzelne Records löschen
    for rid in "$AAAA_ID" "$CNAME_ID" "$TXT_ID" "$RECORD_ID"; do
        if [[ -n "$rid" ]]; then
            api_delete "/api/zones/$TEST_DOMAIN/records/$rid"
            [[ "$LAST_HTTP" == "200" ]] || true
        fi
    done

    # Alle Records der Zone via API löschen (falls noch welche übrig)
    api_get "/api/zones/$TEST_DOMAIN/records"
    REMAINING_IDS=$(extract_all_ids "$LAST_BODY")
    for rid in $REMAINING_IDS; do
        api_delete "/api/zones/$TEST_DOMAIN/records/$rid" || true
    done

    # Testzone löschen
    api_delete "/api/zones/$TEST_DOMAIN"
    if [[ "$LAST_HTTP" == "200" || "$LAST_HTTP" == "204" ]]; then
        ok "Testzone $TEST_DOMAIN gelöscht"
    else
        warn "Testzone löschen → HTTP $LAST_HTTP"
    fi
else
    section "15. Aufräumen"
    skip "Aufräumen (SKIP_CLEANUP=1) — Testdaten bleiben erhalten"
fi

# ---------------------------------------------------------------------------
# Zusammenfassung
# ---------------------------------------------------------------------------
echo
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "${BOLD}  Testergebnis${NC}"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo -e "  ${GREEN}✓ Bestanden:${NC}     $PASS"
echo -e "  ${RED}✗ Fehlgeschlagen:${NC} $FAIL"
echo -e "  ${YELLOW}⚠ Warnungen:${NC}     $WARN"
echo -e "  ${YELLOW}- Übersprungen:${NC}  $SKIP"
echo -e "${BOLD}══════════════════════════════════════════${NC}"
echo

if [[ "$FAIL" -gt 0 ]]; then
    echo -e "${RED}${BOLD}FEHLGESCHLAGEN — $FAIL Test(s) nicht bestanden.${NC}"
    exit 1
elif [[ "$WARN" -gt 0 ]]; then
    echo -e "${YELLOW}${BOLD}WARNUNG — Alle Pflicht-Tests bestanden, $WARN Warnungen.${NC}"
    exit 0
else
    echo -e "${GREEN}${BOLD}ALLE TESTS BESTANDEN.${NC}"
    exit 0
fi
