#!/usr/bin/env bash
# DomU DNS acme.sh/Proxmox DNS hook
#
# Usage with acme.sh:
#   export DOMUDNS_URL=http://192.168.100.x
#   export DOMUDNS_API_KEY=<named api key from DomU DNS dashboard>
#   acme.sh --issue --dns dns_domudns -d example.com
#
# Usage with Proxmox ACME (Datacenter → ACME → DNS Plugin):
#   Plugin ID: domudns
#   DOMUDNS_URL=http://192.168.100.x
#   DOMUDNS_API_KEY=<named api key from DomU DNS dashboard>
#
# Required env vars:
#   DOMUDNS_URL      - Base URL of the DomU DNS instance (no trailing slash)
#   DOMUDNS_API_KEY  - Named API key created in the DomU DNS dashboard
#
# API endpoints used:
#   POST /api/acme/dns-01/present  { "domain": "...", "txt_value": "..." }
#   POST /api/acme/dns-01/cleanup  { "domain": "..." }

dns_domudns_add() {
  local fulldomain="$1"
  local txtvalue="$2"

  DOMUDNS_URL="${DOMUDNS_URL:-}"
  DOMUDNS_API_KEY="${DOMUDNS_API_KEY:-}"

  if [ -z "$DOMUDNS_URL" ]; then
    _err "DOMUDNS_URL is not set"
    return 1
  fi
  if [ -z "$DOMUDNS_API_KEY" ]; then
    _err "DOMUDNS_API_KEY is not set"
    return 1
  fi

  # Strip leading _acme-challenge. prefix to get the domain
  local domain="${fulldomain#_acme-challenge.}"
  # Remove trailing dot if present
  domain="${domain%.}"

  _info "Adding TXT record for ${fulldomain}"

  local response
  response=$(curl -sf \
    -X POST \
    -H "Authorization: Bearer ${DOMUDNS_API_KEY}" \
    -H "Content-Type: application/json" \
    -d "{\"domain\":\"${domain}\",\"txt_value\":\"${txtvalue}\"}" \
    "${DOMUDNS_URL}/api/acme/dns-01/present")

  if [ $? -ne 0 ]; then
    _err "Failed to add TXT record for ${domain}"
    return 1
  fi

  _info "TXT record added: ${fulldomain}"
  return 0
}

dns_domudns_rm() {
  local fulldomain="$1"

  DOMUDNS_URL="${DOMUDNS_URL:-}"
  DOMUDNS_API_KEY="${DOMUDNS_API_KEY:-}"

  if [ -z "$DOMUDNS_URL" ]; then
    _err "DOMUDNS_URL is not set"
    return 1
  fi
  if [ -z "$DOMUDNS_API_KEY" ]; then
    _err "DOMUDNS_API_KEY is not set"
    return 1
  fi

  # Strip leading _acme-challenge. prefix to get the domain
  local domain="${fulldomain#_acme-challenge.}"
  domain="${domain%.}"

  _info "Removing TXT record for ${fulldomain}"

  curl -sf \
    -X POST \
    -H "Authorization: Bearer ${DOMUDNS_API_KEY}" \
    -H "Content-Type: application/json" \
    -d "{\"domain\":\"${domain}\"}" \
    "${DOMUDNS_URL}/api/acme/dns-01/cleanup" >/dev/null

  if [ $? -ne 0 ]; then
    _err "Failed to remove TXT record for ${domain}"
    return 1
  fi

  _info "TXT record removed: ${fulldomain}"
  return 0
}
