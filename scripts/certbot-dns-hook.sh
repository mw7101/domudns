#!/bin/bash
# Certbot DNS-01 hook für dns-stack
# Verwendung: certbot certonly --manual --preferred-challenges dns \
#   --manual-auth-hook ./scripts/certbot-dns-hook.sh \
#   --manual-cleanup-hook ./scripts/certbot-dns-hook-cleanup.sh \
#   -d deine.domain.de

# Konfiguration
API_URL="${DNS_STACK_API_URL:-http://127.0.0.1:8081}"
API_KEY="${DNS_STACK_API_KEY:-}"
DOMAIN="${CERTBOT_DOMAIN}"
VALIDATION="${CERTBOT_VALIDATION}"

if [ -z "$DOMAIN" ] || [ -z "$VALIDATION" ]; then
  echo "CERTBOT_DOMAIN und CERTBOT_VALIDATION müssen gesetzt sein."
  exit 1
fi

# TXT-Wert für DNS-01: base64url(sha256(key_authorization))
# Certbot liefert VALIDATION bereits als den korrekten Wert
curl -s -X POST "$API_URL/api/acme/dns-01/present" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"domain\": \"$DOMAIN\", \"txt_value\": \"$VALIDATION\"}"
