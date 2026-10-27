# Changelog

All notable changes to DomU DNS will be documented in this file.

## [v0.1.3]

### 2026-03-14

#### Fixed
- **Functional test script** (`scripts/test_functional.sh`): Fixed multiple correctness bugs found during live testing:
  - Record TTL validation: changed all record TTLs from 60 to 300 (server rejects TTL < 300)
  - HTTP status codes: all DELETE endpoints return 204 (not 200) — fixed `expect_status` calls to `expect_status_any "200" "204"`
  - HTTP status codes: record/zone POST returns 201 (Created) — fixed to accept `"200" "201"`
  - Record ID type: record IDs are `int` not string — replaced `grep '"id":"..."'` with `grep '"id":[0-9]*'` via new `extract_id()` / `extract_all_ids()` helpers
  - `expect_status` / `expect_status_any` no longer `return 1` (avoided spurious failures in shell scripts without `set -e`)
  - Health check added explicit `exit 1` guard when server is unreachable

#### Changed
- **Functional test script** (`scripts/test_functional.sh`): Extended with comprehensive coverage of all API endpoints. New sections: Session-Auth login/logout (2b), auth management with password-change validation (3b), blocklist URL fetch trigger (8b), block-mode switching NXDOMAIN/zero_ip with DNS verification (8c), DDNS status endpoint (9b), Split-Horizon zone CRUD with `?view=` parameter (10b), DoH path corrected to `/dns-query` with valid wire-format query, DoT connectivity smoke-test via openssl (12b), query-log with filters and stats (14b), DHCP leases and status (14c), metrics history for 24h/7d/30d ranges and HEAD request (14d), rebinding protection documentation (14e). New env vars: `DNS_ADMIN_USER`, `DNS_ADMIN_PASS`, `DNS_TEST_REGEN`. New helpers: `api_head()`, `expect_status_any()`, `dns_rcode()`, `extract_id()`, `extract_all_ids()`, `extract_str_id()`.

## [v0.1.2]

### 2026-03-08

#### Added
- **Named API Keys** (`internal/store/apikeys.go`, `internal/filestore/apikeys.go`, `internal/caddy/api/apikeys_handler.go`): Dedicated API keys per external tool (Traefik, Certbot, acme.sh, Proxmox). Keys are created/deleted via `GET/POST/DELETE /api/auth/api-keys`. Each key is shown only once on creation. Root key and named keys are interchangeable for Bearer and Basic Auth.
- **Basic Auth support** (`internal/caddy/api/middleware.go`): `AuthMiddleware` now accepts `Authorization: Basic` with the named API key as password — required for Traefik's `httpreq` DNS provider.
- **Named API Key cluster sync** (`internal/cluster/`): Master propagates key list (including raw key values) to slaves via `EventAPIKeys`. Slaves can validate named keys locally without round-trip to master.
- **ACME DNS-01 TXT serving** (`internal/dnsserver/acme.go`, `internal/dnsserver/handler.go` Phase 2.9, `internal/filestore/acme.go`): `_acme-challenge.*` TXT queries are now answered directly from `acme_challenges.json`. Previously NXDOMAIN was returned even when a challenge was stored.
- **Traefik httpreq endpoints** (`internal/caddy/api/acme.go`): `POST /api/acme/httpreq/present` and `POST /api/acme/httpreq/cleanup` speak the Traefik `httpreq` DNS provider protocol (FQDN with trailing dot, `value` field).
- **acme.sh / Proxmox script** (`scripts/dns_domudns.sh`): Drop-in DNS hook for acme.sh and Proxmox ACME datacenter plugin. Uses `DOMUDNS_URL` + `DOMUDNS_API_KEY` env vars.
- **Certbot DNS plugin** (`certbot-dns-domudns/`): Standalone Python certbot plugin (`certbot-dns-domudns`) with entry point `dns-domudns`. Uses INI credentials file (`dns_domudns_url`, `dns_domudns_api_key`).

#### Tests
- `TestACMEChallengeHandlerHit`: TXT query for stored, non-expired challenge → RcodeSuccess + TXT answer.
- `TestACMEChallengeHandlerMiss`: TXT query for unknown challenge → ACME phase skipped, pipeline continues.
- `TestACMEChallengeHandlerWrongQtype`: A query on `_acme-challenge.*` → phase 2.9 not triggered.

## [v0.1.1]

### 2026-03-07

#### Added
- **RFC 2136 DDNS fully operational** — ISC dhcpd integration end-to-end working. DNS records are created/updated automatically from DHCP leases via TSIG-authenticated RFC 2136 UPDATE messages.
- **DDNS runtime statistics + dashboard** (`internal/dnsserver/update.go`, `internal/caddy/api/ddns.go`, `dashboard/`): `DDNSStats` struct tracks total updates, failures, last error and rejection reason. `GET /api/ddns/status` exposes these stats. Dashboard shows a 4-card stats grid with contextual diagnosis banners (NOTZONE, NOTAUTH) and a dhcpd config guide (pre-filled `dhcpd.conf` snippet with key name and algorithm).

#### Fixed
- **DDNS UPDATE packets rejected with NOTIMP** (`internal/dnsserver/server.go`): miekg/dns `DefaultMsgAcceptFunc` rejects `OpcodeUpdate` (5) before the handler is called. Fixed by setting a custom `ddnsMsgAcceptFunc` on all server instances (UDP, TCP, DoT).
- **TSIG key lookup failing silently** (`internal/dnsserver/update.go`): `UpdateKeys()` and `GetSecrets()` now add trailing dots to key names in `TsigSecret`. miekg looks up keys as FQDNs — without the trailing dot the lookup silently failed, causing every UPDATE to be rejected with NOTAUTH.
- **TSIG signature missing from responses** (`internal/dnsserver/update.go`): `respond()` now calls `resp.SetTsig()` before `WriteMsg()`. miekg only signs responses when the response message already contains a TSIG RR — without this, dhcpd reported `expected a TSIG or SIG(0)` and treated successful updates as failures.
- **Duplicate records on dhcpd retries** (`internal/dnsserver/update.go`): `applyUpdate` for ClassINET now uses upsert semantics — existing records with the same name+type are deleted before inserting the new one. Previously, dhcpd retries created duplicate A/TXT records.

#### Tests
- `TestDDNS_TsigSecret_TrailingDot`: trailing-dot regression test for `UpdateKeys()` / `GetSecrets()`.
- `TestDDNS_Stats_SuccessfulUpdate`, `TestDDNS_Stats_NotZoneRejection`, `TestDDNS_Stats_NotAuthRejection`, `TestDDNS_Stats_AccumulatesAcrossMultipleCalls`: DDNS stats unit tests.
