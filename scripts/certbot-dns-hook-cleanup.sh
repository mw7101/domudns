#!/bin/bash
# Certbot DNS-01 Cleanup-Hook
API_URL="${DNS_STACK_API_URL:-http://127.0.0.1:8081}"
API_KEY="${DNS_STACK_API_KEY:-}"
DOMAIN="${CERTBOT_DOMAIN}"

if [ -z "$DOMAIN" ]; then
  exit 0
fi

curl -s -X POST "$API_URL/api/acme/dns-01/cleanup" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"domain\": \"$DOMAIN\"}"
