# Changelog

All notable changes to DomU DNS will be documented in this file.

## [v0.2.0]

### Added

- **Cache TTL decrement**: DNS responses served from cache now have their TTL values decremented by the elapsed time since caching, in compliance with RFC 1035. Previously, cached responses always returned the original TTL regardless of how long the entry had been cached.
- **Cache management API**: New endpoints to inspect and control the DNS cache:
  - `GET /api/cache` — returns cache statistics (entries, hits, misses, hit rate) and a list of up to 500 entries sorted by remaining TTL
  - `DELETE /api/cache` — flushes all cache entries (local only; allowed on slave nodes)
  - `DELETE /api/cache/{name}/{type}` — removes a specific cache entry by FQDN and record type
- **Cache management dashboard**: New page at `/dashboard/cache/` showing live cache statistics (KPI cards for entries, hit rate, hits, misses) and a sortable entry list with per-entry delete and a global flush button.

- **SOA editor in dashboard**: SOA records are now editable in the zone detail view — displayed as a pinned first row in the record table with an amber SOA badge. A dedicated edit modal provides fields for MName, RName, Refresh, Retry, Expire, and Minimum TTL; the serial is auto-incremented (YYYYMMDDnn) and shown read-only as a preview.

### Fixed

- **Underscores in DNS labels**: DHCP hostnames and DNS labels now allow underscore characters, in compliance with real-world DNS usage (e.g. `_dmarc`, SRV service labels).
- **Underscores in FQDN record targets**: PTR, MX, NS, and SRV record targets now accept underscores in their FQDN values (e.g. `_sip._tcp.example.com`).
- **Cache KpiCard label prop**: Replaced deprecated `title` prop with `label` in the cache dashboard KPI cards.

## [v0.1.5]

#### Fixed

- **CNAME chasing for A queries** (`internal/dnsserver/zones.go`): Authoritative zones now return the CNAME record (plus the target's A record if it is in the same zone) when a client queries for type A on a name that only has a CNAME — previously the server returned an empty answer, causing `ping` and stub resolvers to fail even though `dig … in CNAME` succeeded (RFC 1034 §4.3.2).

## [v0.1.4]

#### Added

- **RFC 1035 zone file import** (`POST /api/zones/import`): Multipart file upload of BIND-format zone files. Supports automatic domain detection from SOA record and optional `view` parameter for split-horizon zones.
- **AXFR live transfer import** (`POST /api/zones/import/axfr`): Imports a zone directly from a running DNS server via AXFR (RFC 5936). Accepts `{"server": "1.2.3.4:53", "domain": "example.com", "view": ""}`.
- **Zone file export** (`GET /api/zones/{domain}/export`): Downloads a zone as an RFC 1035 zone file (`Content-Disposition: attachment`). Supports `?view=` for split-horizon zones.
- **Merge semantics**: When importing into an existing zone, records are merged — all existing records sharing the same (Name, Type) combination as an imported record are replaced; unaffected records remain unchanged.
- **Dashboard import modal**: New "Importieren" button in the zone list opens a modal with two tabs — "Zone File" (file upload) and "AXFR Transfer" (server + domain form).
- **Dashboard export button**: "↓ Export .zone" button in the zone detail view downloads the zone file directly to the browser.

#### Security

- **Cluster replay protection** (`internal/cluster/`): `SyncRequest` now carries a Unix-nanosecond timestamp and a 16-byte random nonce. Both fields are bound into the HMAC. The receiver rejects events outside a 5-minute window and deduplicates nonces for 10 minutes, making replayed cluster events impossible.
- **Cluster HMAC now mandatory** (`internal/cluster/receiver.go`): Sync requests are always rejected when no HMAC secret is configured — previously, an empty secret allowed unauthenticated cluster sync.
- **Cluster payload limits** (`internal/cluster/receiver.go`): Reduced HTTP body limit from 64 MB to 16 MB and gzip decompression limit from 256 MB to 16 MB to mitigate ZIP-bomb / DoS attacks.
- **Zone validation after cluster deserialization** (`internal/cluster/receiver.go`): `applyZoneUpdated` now calls `dns.ValidateZone` before writing the zone to disk, preventing a compromised master from pushing malformed zones to slaves.
- **Blocklist SSRF protection** (`internal/blocklist/fetcher.go`): `FetchURL` uses a custom `DialContext` that resolves hostnames and rejects private/loopback IPs. A `CheckRedirect` hook blocks redirects to internal addresses, preventing server-side request forgery via admin-configured blocklist URLs.
- **DoH rate limiting** (`internal/caddy/server.go`): DNS-over-HTTPS endpoint is now covered by the same rate limiter as the API (3× the API limit) to prevent amplification and DoS attacks.
- **Named API key timing attack** (`internal/filestore/apikeys.go`): `ValidateNamedAPIKey` now uses a constant-time loop without early exit, preventing timing side-channels that could reveal key position.
- **ACME FQDN case normalization** (`internal/filestore/acme.go`): `PutACMEChallenge` now normalises the FQDN to lowercase on write, matching the case-insensitive lookup in `GetACMEChallenge` and eliminating duplicate entries for the same domain.
- **ACME TXT value limit reduced to 255 bytes** (`internal/caddy/api/acme.go`): Aligns with RFC 1035 §3.3 (single TXT string limit). ACME challenge values are 43 bytes, making the previous 512-byte limit excessively permissive.
- **Request context propagated to key store** (`internal/caddy/api/auth_manager.go`, `middleware.go`): `ValidateAnyKey` now accepts a `context.Context` and forwards it to the named-key store, replacing the previous `context.Background()` call.
- **File permissions** (`internal/filestore/atomic.go`): Data directories are now created with mode `0700` instead of `0755` to prevent world-readable access to zone and config files.
- **Default credentials not logged** (`cmd/domudns/main.go`): Removed `admin/admin` from the setup-wizard log message.

#### Performance

- **Singleflight for upstream cache-miss** (`internal/dnsserver/handler.go`): Concurrent cache-miss requests for the same domain+type now share a single upstream round-trip instead of N parallel ones (thundering-herd protection). Each caller receives an independent copy of the response via `resp.Copy()`.
- **Cache warmup concurrency reduced** (`internal/dnsserver/warmup.go`): Goroutine count reduced from 10 to 6 to better match the RPi 3B's 4 cores without starving the DNS and HTTP servers during startup.
- **API request timeout** (`dashboard/lib/api.ts`): All `fetch` calls now have a 30-second timeout via `AbortController` to prevent indefinitely hanging requests.
- **Prometheus regex** (`dashboard/lib/utils.ts`): Regex in `parsePrometheus` is now compiled once as a module constant instead of per loop iteration.

#### Fixed

- **Silent JSON read errors in filestore** (`internal/filestore/apikeys.go`, `acme.go`): Corrupted JSON files now return an error instead of silently resetting state and overwriting data.
- **`os.Rename` error not wrapped** (`internal/filestore/atomic.go`): `writeGzipDomains` now wraps the rename error with `fmt.Errorf` for consistent error context, matching `atomicWriteJSON`.
- **WarmCache panic recovery** (`cmd/domudns/main.go`): The warmup goroutine now has a `defer recover()` so a panic during cache warmup does not crash the server.
- **splitHorizonResolver race condition** (`cmd/domudns/main.go`): Concurrent access from `splitHorizonUpdater` and `configReloader` is now guarded by `sync.Mutex`.
- **WarmupEnabled override bug** (`internal/config/config.go`): Removed the default that forced `WarmupEnabled=true` when cache was enabled, which prevented explicit opt-out. A new `warmup_disabled: true` config field allows clean opt-out.
- **Blocklist domain file removal error ignored** (`internal/filestore/blocklist.go`): Failure to delete the domain file on URL removal is now logged as a warning instead of being silently swallowed.
- **RateLimitMiddleware goroutine** (`internal/caddy/api/middleware.go`, `internal/caddy/server.go`): Cleanup goroutine now accepts a `context.Context` and stops on server shutdown — previously leaked indefinitely.
- **Dashboard error feedback** (`dashboard/app/dashboard/query-log/page.tsx`): Whitelist errors are now shown as a red toast to the user instead of being silently swallowed in `console.error`.
- **acme.sh/Proxmox DNS plugin** (`scripts/dns_domudns.sh`): Renamed info variable from `dns_hetzner_info` to `dns_domudns_info` so Proxmox ACME UI correctly detects and lists the plugin in the DNS API dropdown.

#### Changed

- **Let's Encrypt docs** (`website/docs/letsencrypt.html`): Expanded Proxmox section into a full "Option D: Proxmox Cluster" guide with all 4 manual installation steps — plugin file distribution to all nodes, schema registration in `dns-challenge-schema.json`, service restart, UI plugin configuration, and per-node certificate setup. Added two Proxmox-specific troubleshooting entries.

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
