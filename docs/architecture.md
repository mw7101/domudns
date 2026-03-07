# Architecture

## Overview

DomU DNS consists of the following main components:

- **Custom DNS Server** (Port 53): High-performance DNS server with blocklist, authoritative zones, FWD records, and cache
- **HTTP Server** (Port 80/443): Next.js dashboard + REST API + DoH endpoint (RFC 8484)
- **DoT Listener** (Port 853): DNS over TLS (RFC 7858), integrated directly into the DNS server core
- **Prometheus Metrics** (Port 9090): Separate metrics endpoint without authentication
- **File Backend** (`internal/filestore/`): Local JSON files as persistent storage — no external DB required
- **Cluster** (`internal/cluster/`): Master/slave synchronization via HTTP push + polling
- **Blocklist Manager**: Periodic fetch of blocklist URLs, in-memory management

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Clients                             │
├──────────────┬──────────────┬──────────────┬────────────────┤
│ DNS Clients  │ Web Browser  │ API Clients  │ Prometheus     │
└──────┬───────┴──────┬───────┴──────┬───────┴────────┬───────┘
       │              │              │                │
       │ DNS Query    │ HTTP/HTTPS   │ REST API       │ Scrape
       │ (Port 53)    │ (Port 80/443)│                │ (Port 9090)
       ↓              ↓              ↓                ↓
┌──────────────────────────────────────────────────────────────┐
│                      domudns Binary                        │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │        DNS Server (Port 53 + opt. Port 853)            │ │
│  ├────────────────────────────────────────────────────────┤ │
│  │  • BlocklistManager (In-Memory, O(1) Lookup)          │ │
│  │  • ZoneManager (Authoritative Zones, 0ms)             │ │
│  │  • CacheManager (LRU Cache, TTL Expiration, Warming)  │ │
│  │  • Forwarder (Round-Robin Upstream, UDP/TCP)          │ │
│  │  • DoT-Listener (tcp-tls, Port 853, RFC 7858)        │ │
│  └────────────────────────────────────────────────────────┘ │
│                            ↕                                 │
│  ┌────────────────────────────────────────────────────────┐ │
│  │         HTTP Server (Port 80/443)                     │ │
│  ├────────────────────────────────────────────────────────┤ │
│  │  • Next.js Web UI (embedded as Go embed.FS)           │ │
│  │  • REST API (/api/*)                                  │ │
│  │  • DoH endpoint (/dns-query, RFC 8484, no auth)      │ │
│  │  • Authentication (Session + Bearer Token)            │ │
│  │  • Rate Limiting                                      │ │
│  └────────────────────────────────────────────────────────┘ │
│                            ↕                                 │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              Store Interface (api.Store)               │ │
│  │  FileStore or PropagatingStore (Master)                │ │
│  └────────────────────────────────────────────────────────┘ │
│                            ↕                                 │
│  ┌────────────────────────────────────────────────────────┐ │
│  │         File Backend (/var/lib/domudns/data/)       │ │
│  ├────────────────────────────────────────────────────────┤ │
│  │  zones/               → JSON files per zone           │ │
│  │  blocklist/           → URLs, domains, whitelist      │ │
│  │  auth.json            → password hash, API key        │ │
│  │  config_overrides.json→ web UI configuration          │ │
│  └────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

## File Backend

### Filesystem Layout

```
/var/lib/domudns/data/
  zones/
    example.com.json              # dns.Zone struct + records as JSON
    100.168.192.in-addr.arpa.json # Reverse zone for PTR records
  blocklist/
    urls.json                     # []store.BlocklistURL
    domains_manual.json           # Manually blocked domains
    allowed_domains.json          # Manually allowed domains (whitelist)
    whitelist_ips.json            # Client IP CIDRs (bypass blocklist)
    url_domains/
      1.domains.gz                # Domains per URL ID (gzip plain-text)
      2.domains.gz
  auth.json                       # username, password_hash, api_key, setup_completed
  config_overrides.json           # Web UI config overrides (upstream, log_level, etc.)
  acme_challenges.json            # ACME TXT records (temporary, Let's Encrypt)
  tsig_keys.json                  # TSIG keys for RFC 2136 DDNS (secrets in plaintext!)
```

### Atomic Writes

All write operations use `temp-file + os.Rename()` (guaranteed atomic on Linux):

```
1. Write data to /tmp/domudns-*.tmp
2. os.Rename(tmp, targetfile) — atomic, no partial state
```

### Packages

| Package | Contents |
|---------|----------|
| `internal/filestore/store.go` | `FileStore` struct, `NewFileStore()`, `HealthCheck()` |
| `internal/filestore/zones.go` | `GetZone`, `ListZones`, `PutZone`, `DeleteZone`, `GetRecords` |
| `internal/filestore/blocklist.go` | BlocklistURL CRUD, domain lists, whitelist IPs |
| `internal/filestore/auth.go` | `GetAuthConfig`, `UpdateAuthConfig`, `MarkSetupCompleted` |
| `internal/filestore/config.go` | `GetConfigOverrides`, `UpdateConfigOverrides` |
| `internal/filestore/atomic.go` | `atomicWriteJSON()`, `writeGzipDomains()`, `readGzipDomains()` |

## Master/Slave Cluster

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  3-Node Raspberry Pi Cluster                 │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │   Pi 1 (Master) — 192.0.2.1                   │    │
│  │   • Accepts all API changes                          │    │
│  │   • Writes locally (FileStore)                       │    │
│  │   • PropagatingStore: push to all slaves             │    │
│  │   • Fetches external blocklists (every 24h)          │    │
│  └────────────────┬────────────────┬────────────────────┘    │
│                   │                │                          │
│      HTTP Push    │                │    HTTP Push             │
│      (HMAC-SHA256)│                │    (HMAC-SHA256)         │
│                   ↓                ↓                          │
│  ┌─────────────────────────────────────────────────────┐     │
│  │ dns2 (Slave, 192.0.2.2)               │             │
│  │ • DNS operation only                        │             │
│  │ • Read-only API                             │             │
│  │ • Polls master every 30s                    │             │
│  └─────────────────────────────────────────────┘             │
└─────────────────────────────────────────────────────────────┘
             │                       │
             └───────────────────────┘
                    DNS Load Balancer (Round-Robin)
```

### Sync Protocol

**Push Events** (Master → Slave):

| Event | Description |
|-------|-------------|
| `zone_updated` | Zone + all records (full state) |
| `zone_deleted` | Zone domain (slave deletes file) |
| `blocklist_urls` | All blocklist URLs with metadata |
| `url_domains` | Domains for a URL (gzip-base64) |
| `manual_domains` | Manually blocked domains |
| `allowed_domains` | Manually allowed domains |
| `whitelist_ips` | Client IP whitelist |
| `auth_config` | Auth configuration (password hash, API key) |
| `config_overrides` | Web UI configuration |
| `tsig_keys` | TSIG keys for RFC 2136 DDNS |

All events are **full state** (no delta) → idempotent, no ordering issues.

**Fallback Polling:** Slaves poll the master every 30s as a backup (in case a push event is lost).

### Security

- **HMAC-SHA256** over the serialized SyncPayload
- **Constant-time compare** (`hmac.Equal`)
- **Sync secret**: 64 hex characters, must be identical on all nodes in `/etc/domudns/env`:
  ```
  DOMUDNS_SYNC_SECRET=<64-hex-characters>
  ```

### Packages

| Package | Contents |
|---------|----------|
| `internal/cluster/types.go` | `SyncEventType`, `SyncPayload`, constants |
| `internal/cluster/auth.go` | `computeHMAC()`, `validateHMAC()` |
| `internal/cluster/propagator.go` | Push to slaves + async retry queue |
| `internal/cluster/receiver.go` | `ReceiverHandler`: HMAC validation + file update |
| `internal/cluster/poll.go` | `RunPollLoop()`: slave fallback polling |
| `internal/cluster/store_wrapper.go` | `PropagatingStore`: decorator over FileStore |
| `internal/cluster/handler.go` | HTTP handler for `/api/internal/sync` |

## DNS Query Pipeline

```
Incoming DNS request (Port 53)
    ↓
Phase 1: Extract client IP
    ↓
Phase 2: Blocklist check
    ├─ Client IP in whitelist? → Skip blocklist (trusted)
    ├─ Domain blocked? → block_mode: 0.0.0.0/:: (zero_ip) or NXDOMAIN (nxdomain)
    └─ Not blocked →
        ↓
Phase 3: Authoritative zone check (ZoneManager, in-memory)
    ├─ Zone + record present? → Authoritative response (aa=true, 0ms)
    │       → TTL override (if zone.TTLOverride > 0): all response TTLs normalized (except SOA)
    ├─ Zone present + NXDOMAIN →
    │       ↓
    │  Phase 3.5: FWD fallback
    │       ├─ FWD record at zone apex? → ForwardToServers() → cache
    │       └─ No FWD → return NXDOMAIN
    └─ No zone →
        ↓
Phase 4: Cache check (LRU + TTL)
    ├─ Cache hit? → cached response (0ms)
    └─ Cache miss →
        ↓
Phase 4.5: Conditional forwarding (ConditionalForwarder)
    ├─ Domain matches rule (longest suffix match)?
    │       → DNSSEC: PrepareRequest (set DO bit)
    │       → ForwardToServers() → cache → ProcessResponse (AD bit, RR filter)
    └─ No rule →
        ↓
Phase 5: DNSSEC preparation + default upstream forwarding (Forwarder)
    ├─ DNSSEC enabled? → PrepareRequest: set DO bit in upstream request
    ├─ Round-robin over upstream[] (1.1.1.1, 8.8.8.8 — both DNSSEC-validating)
    ├─ UDP first, TCP on truncation
    ├─ Cache response (positive + negative, with DNSSEC RRs)
    └─ DNSSEC ProcessResponse: propagate AD bit, filter DNSSEC RRs (if client has no DO)
        ↓
Phase 5.5: DNS Rebinding Protection (RebindingProtector, if enabled)
    ├─ Domain on whitelist? → Allow through
    ├─ Response contains A/AAAA with private IP (RFC1918/Loopback/Link-Local/CGN)?
    │       → NXDOMAIN (attack blocked, logged as "blocked" in query log)
    └─ No attack →
        ↓
Response to client
```

**Invariants:**
- Rebinding check always AFTER upstream (Phase 5.5 > Phase 5)
- Rebinding NOT for authoritative responses or cache hits — upstream responses only
- Rebinding NOT for DDNS UPDATEs (separate handler path, Opcode=5)

### RFC 2136 DDNS

DNS UPDATE messages (Opcode 5, RFC 2136) are handled separately from the normal query path:

```
DNS UPDATE (Opcode=5, Port 53)
    ↓
ddnsMsgAcceptFunc (MsgAcceptFunc on all dns.Server instances)
    └─ OpcodeUpdate=5 → MsgAccept (bypasses miekg DefaultMsgAcceptFunc which rejects Opcode=5)
    ↓
DDNSHandler.Handle()
    ├─ No TSIG keys configured? → REFUSED
    ├─ TSIG verification failed (w.TsigStatus() ≠ nil)? → NOTAUTH (TSIG-signed response)
    ├─ No TSIG in message? → NOTAUTH
    └─ TSIG OK →
        ↓
    Check zone existence (Question section = zone name)
    ├─ Zone not found? → NOTZONE (TSIG-signed response)
    └─ Zone found →
        ↓
    Process update section (for each RR in Ns section):
        ├─ ClassINET: Upsert — delete existing records with same name+type, insert new one
        ├─ ClassNONE: Delete specific record (name + type + value)
        └─ ClassANY:  Delete all records of this name (optionally filtered by type)
        ↓
    ZoneReloader() → DNS server immediately reloads zone
    ↓
    NOERROR (TSIG-signed response)
```

**TSIG key names:** miekg/dns looks up key names as FQDNs with trailing dot. `UpdateKeys()` and `GetSecrets()` add trailing dots automatically before populating `TsigSecret`.

**TSIG response signing:** `respond()` calls `resp.SetTsig()` before `w.WriteMsg()`. miekg only computes the response MAC when the response message already contains a TSIG RR.

**TSIG key live reload:** `DDNSHandler.UpdateKeys()` swaps keys atomically without restart. Called automatically after API changes.

**Runtime statistics:** `DDNSStats` struct tracks `TotalUpdates`, `TotalFailed`, `LastRejectedReason`, `LastRejectedAt`, `LastUpdateAt`. Exposed via `GET /api/ddns/status`.

### Conditional Forwarding

Configuration-based forwarding rules (no zone entry required):

- **Configuration:** `dnsserver.conditional_forwards` in `config.yaml` or via `PATCH /api/config`
- **Matching:** Longest suffix match, case-insensitive — `fritz.box` matches `mydevice.fritz.box` and `fritz.box`
- **Live reload:** `ConditionalForwarder.UpdateRules()` (RWMutex-protected), no restart
- **Pipeline:** Phase 4.5 — after cache miss, before default upstream
- **Example:**
  ```yaml
  dnsserver:
    conditional_forwards:
      - domain: "fritz.box"
        servers: ["192.168.178.1"]
  ```

### FWD Record

Internal record type (not an official DNS RR):

- **Purpose:** NXDOMAIN fallback for subdomains within an authoritative zone
- **Configuration:** Name must be `@` (zone apex), value: comma-separated DNS servers
- **Example:** `@ FWD 3600 helium.ns.hetzner.de,1.1.1.1:53`
- **Pipeline:** Phase 3.5 — after `GenerateResponse()` NXDOMAIN, before response to client

### PTR Records (Reverse DNS)

Validation of PTR records:

- **in-addr.arpa zones:** Name must be `@` or a number 0-255 (last IP octet)
- **ip6.arpa zones:** Name must be `@` or a hex nibble (0-9, a-f)
- **Value:** Must be a hostname (FQDN) — not an IP address!
- **Example:**

```
Zone: 100.168.192.in-addr.arpa
Record: name="1", type=PTR, value="router.int.example.com"
→ dig -x 192.0.2.1 @<pi-ip>  ← PTR query (not: dig 192.0.2.1)
```

## Authentication & Setup

### Flow (Initial Installation)

```
1. Start → auth.json not present / setup_completed=false
2. All requests → redirect to /setup
3. Setup wizard: set password + API key → setup_completed=true
4. Afterwards: /login with username + password → session cookie
         or: Authorization: Bearer <API-Key>
```

### AuthManager

- **Password:** bcrypt (cost 12), stored in `auth.json`
- **API key:** 64 hex characters, randomly generated
- **Sessions:** In-memory, 24h TTL
- **Cluster sync:** Auth changes are propagated to slaves via `auth_config` event

### Password Reset

```bash
# Reset auth.json
echo '{}' > /var/lib/domudns/data/auth.json
sudo systemctl restart domudns
# Now again admin/admin → setup wizard
```

## Config Live Reload

Certain settings can be changed without a service restart:

| Setting | Live Reload | Restart Required |
|---------|-------------|-----------------|
| `dnsserver.upstream` | ✅ Immediately | — |
| `dnsserver.conditional_forwards` | ✅ Immediately | — |
| `blocklist.block_mode` | ✅ Immediately | — |
| `system.log_level` | ✅ Immediately | — |
| `dnsserver.cache.*` | — | ✅ |
| `dnsserver.listen` | — | ✅ |
| `dnsserver.doh.*` | — | ✅ |
| `blocklist.fetch_interval` | — | ✅ |
| `caddy.tls.*` | — | ✅ |

**Implementation:** `ConfigReloader` callback in `ConfigHandler` → `Forwarder.UpdateUpstream()` + `ConditionalForwarder.UpdateRules()` + `Handler.UpdateBlockMode()` (each atomic/RWMutex) + `logger.SetLevel()`.

## DNS over HTTPS (DoH, RFC 8484)

### Architecture

The DoH handler is integrated into the HTTP server and internally uses the same DNS query pipeline:

```
Browser / Client
    ↓ HTTPS GET /dns-query?dns=<base64url>
    ↓ HTTPS POST /dns-query (Content-Type: application/dns-message)
    ↓
DoHHandler (internal/caddy/api/doh.go)
    ├─ Decodes DNS message (GET: base64url, POST: raw bytes)
    ├─ Creates httpDNSWriter (implements dns.ResponseWriter)
    ├─ Calls handler.ServeDNS() → full DNS query pipeline
    ├─ Sets Cache-Control: max-age=<minTTL> (RFC 8484 §5.1)
    └─ Returns application/dns-message
```

### Configuration

```yaml
dnsserver:
  doh:
    enabled: false    # Default: disabled
    path: "/dns-query" # HTTP path (RFC 8484 standard)
```

Activation via `PATCH /api/config` writes to `config_overrides.json`, but **restart required** (HTTP listener must be reconfigured).

### Security

- **No auth**: DoH is intentionally public (RFC 8484 does not expect a Bearer token)
- **Client IP**: From `X-Real-IP` → `X-Forwarded-For` → `RemoteAddr` (proxy support)
- **Block mode**: Also applies to DoH — blocked domains return the `block_mode` response
- **Body limit**: Max 64 KB per POST (protection against excessively large requests)

### Packages

| Package | Contents |
|---------|----------|
| `internal/caddy/api/doh.go` | `DoHHandler`, `httpDNSWriter` (RFC 8484 GET + POST) |
| `internal/caddy/api/doh_test.go` | 13 unit tests (GET, POST, client IP, Cache-Control) |
| `internal/caddy/server.go` | DoH endpoint registration in HTTP mux |

## DNS over TLS (DoT, RFC 7858)

### Architecture

DoT runs directly in the DNS server core (not in the HTTP server) and uses the same handler:

```
DNS client (Android, iOS, systemd-resolved, Stubby)
    ↓ TCP-TLS connection on port 853
    ↓ DNS wire format over encrypted connection
    ↓
dotServer (miekg/dns, Net: "tcp-tls")
    ├─ TLS handshake (TLS 1.2+, certificate from cert_file/key_file)
    ├─ Reads DNS message in wire format
    ├─ Calls handler.ServeDNS() → full DNS query pipeline
    └─ Returns DNS response in wire format
```

Same `*Handler` as UDP (port 53), TCP (port 53), and DoH — blocklist, zones, cache, and forwarding apply to all protocols.

### Configuration

```yaml
dnsserver:
  dot:
    enabled: false          # Default: disabled
    listen: "[::]:853"      # IPv4+IPv6 dual-stack on port 853
    cert_file: ""           # empty = use caddy.tls.cert_file
    key_file: ""            # empty = use caddy.tls.key_file
```

**Restart required** — DoT listener cannot be enabled/disabled without a restart.

### Security

- **TLS certificate required**: Without a valid cert, DoT stays disabled (warning in log)
- **TLS 1.2+**: Minimum version is TLS 1.2 (`tls.VersionTLS12`)
- **Client IP**: Directly from TCP connection (`RemoteAddr`) — no header parsing needed
- **Block mode**: Also applies to DoT — blocked domains return the `block_mode` response
- **No auth**: DoT is intentionally public (encryption ≠ authentication)

### Packages

| Package | Contents |
|---------|----------|
| `internal/dnsserver/server.go` | `dotServer *dns.Server`, start + shutdown in `Start()` |
| `internal/dnsserver/server_test.go` | Unit tests + end-to-end test with self-signed cert |
| `internal/config/config.go` | `DoTConfig` struct + default `[::]:853` |

## Blocklist System

### Pipeline

```
Master (every 24h):
  1. FetchURL(url) → domains []string
  2. PropagatingStore.SetURLDomains(id, domains)
       → writes url_domains/<id>.domains.gz (locally)
       → pushes EventURLDomains to all slaves
  3. Slave: ReceiverHandler → writes url_domains/<id>.domains.gz
       → dnsServer.LoadBlocklist() (in-memory reload)
  4. Master: dnsServer.LoadBlocklist() (in-memory reload)
```

### Default URLs

On first installation (empty store), `blocklist.default_urls` from `config.yaml` are automatically registered:

```yaml
blocklist:
  default_urls:
    - "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
```

Slaves do **not** fetch external URLs — only the master does.

### Block Response Mode

Blocked domains can be answered in different ways (live reload via `PATCH /api/config`):

| Mode | Response | Behavior |
|------|----------|----------|
| `zero_ip` (default) | 0.0.0.0 (A) / :: (AAAA) | Browser attempts connection → immediate rejection |
| `nxdomain` | NXDOMAIN (RcodeNameError) | Browser aborts immediately, no TLS timeout |

**Configuration:**
```yaml
blocklist:
  block_mode: "zero_ip"  # "zero_ip" | "nxdomain"
```

**Implementation:** `Handler.blockMode` as `atomic.Value` — lock-free access in the DNS hot path. `UpdateBlockMode()` writes atomically, all goroutines read without mutex overhead.

## Query Log

### Architecture

```
DNS request completed
    ↓
QueryLogger.LogQuery() — non-blocking channel (backpressure protection)
    ↓
Ring buffer (in-memory, configurable size, default: 5,000 entries)
    ├─ Read API: GET /api/query-log (filter: client, domain, result, qtype, node, ...)
    └─ Slave push: Drain(since) → HMAC-signed batch to master (every 30s)

Optional: SQLite persistence (WAL mode, batch commits, automatic retention)
    → query.log.db in data directory
```

### Pipeline (Slave → Master)

```
Slave ring buffer
    ↓
QueryLogger.Drain(since lastPushTime, max 500)  ← new entries only
    ↓
HMAC-signed HTTP POST to master /api/internal/query-log-sync
    ├─ Success → update lastPushTime
    └─ Error → lastPushTime unchanged → retry on next tick
```

### Configuration

```yaml
system:
  query_log:
    enabled: true
    memory_entries: 5000        # In-memory ring buffer size
    persist: false              # SQLite persistence
    persist_path: ""            # Default: <data_dir>/query.log.db
    persist_days: 7             # Retention in days
    push_interval: "30s"        # Slave→Master push interval
```

### Packages

| Package | Contents |
|---------|----------|
| `internal/querylog/types.go` | `QueryEntry`, `ResultType` constants |
| `internal/querylog/ringbuffer.go` | In-memory ring buffer, `Drain(since, max)` |
| `internal/querylog/logger.go` | `QueryLogger`, non-blocking `LogQuery()`, `Run()` |
| `internal/querylog/handler.go` | HTTP handler `GET /api/query-log`, `GET /api/query-log/stats` |
| `internal/querylog/push.go` | `PushFunc`, HMAC-signed slave push |
| `internal/querylog/sqlite.go` | SQLite backend (modernc.org/sqlite, WAL, batch commits) |

## Cache Warming

On startup, the DNS server asynchronously pre-loads popular domains into the LRU cache. Clients therefore receive cache-hit responses (0 ms) from the start instead of waiting for upstream forwarding.

### Data Sources (Priority)

1. **Query log top domains** (priority 1): Domains this node resolves most frequently — own traffic takes precedence.
2. **Fallback list** (~250 entries, priority 2): Embedded list of popular domains (Google, Microsoft, Apple, CDNs, GitHub, etc.) — used on first installation when the query log is still empty.

### Flow

```
Server.Start() completed
    ↓
go dnsServer.WarmCache(ctx, qLogger, warmupCount)  ← non-blocking
    │
    ├─ collectDomains(): Query log top domains + fallback up to warmupCount
    │
    └─ 10 parallel goroutines (semaphore)
         ├─ Already cached? → skip
         ├─ dns.Client.Exchange(upstream, A query)  → cache.Set()
         └─ dns.Client.Exchange(upstream, AAAA query) → cache.Set()
         │
         ↓
    log.Info "cache warmup completed" warmed=X domains=Y
```

**Timeout:** 60 seconds total, 2 seconds per upstream request.
**Parallelism:** Max 10 concurrent goroutines.

### Configuration

```yaml
dnsserver:
  cache:
    enabled: true
    warmup_count: 200    # Number of domains (default: 200, 0 = disabled)
```

### Packages

| Package | Contents |
|---------|----------|
| `internal/dnsserver/warmup.go` | `WarmCache()`, `collectDomains()`, `warmAndStore()`, `QueryLogReader` interface |
| `internal/dnsserver/warmup_domains.go` | `defaultWarmupDomains` (~250 popular fallback domains) |
| `internal/dnsserver/warmup_test.go` | 10 unit tests (collectDomains + WarmCache incl. fake DNS server) |

---

## DNS Rebinding Protection

### Protection Against DNS Rebinding Attacks

A DNS rebinding attack causes an external domain (e.g. `evil.com`) to resolve to a private IP (e.g. `192.168.1.1`). The browser then believes it is communicating with a local device and bypasses same-origin protection.

**Blocked IP ranges:**

| Range | CIDR | RFC |
|-------|------|-----|
| RFC1918 Class A | `10.0.0.0/8` | RFC 1918 |
| RFC1918 Class B | `172.16.0.0/12` | RFC 1918 |
| RFC1918 Class C | `192.168.0.0/16` | RFC 1918 |
| IPv4 Loopback | `127.0.0.0/8` | — |
| IPv4 Link-Local | `169.254.0.0/16` | APIPA |
| Carrier-Grade NAT | `100.64.0.0/10` | RFC 6598 |
| IPv6 Loopback | `::1/128` | — |
| IPv6 ULA | `fc00::/7` | RFC 4193 |
| IPv6 Link-Local | `fe80::/10` | — |

### Configuration

```yaml
dnsserver:
  rebinding_protection: false          # opt-in (default: disabled)
  rebinding_protection_whitelist:      # domains allowed to return private IPs
    - "fritz.box"                      # FritzBox router
    - "corp.internal"                  # internal network
```

**Live reload:** `Handler.UpdateRebindingProtection()` via `PATCH /api/config`, no restart needed.

### Packages

| Package | Contents |
|---------|----------|
| `internal/dnsserver/rebinding.go` | `RebindingProtector`, `IsRebindingAttack()`, private IP check |
| `internal/dnsserver/rebinding_test.go` | Unit tests (RFC1918, link-local, CGN, whitelist, IPv6) |

## DDNS (RFC 2136) — Architecture

### Packages

| Package | Contents |
|---------|----------|
| `internal/dnsserver/update.go` | `DDNSHandler`, `Handle()`, `applyUpdate()`, `DDNSStats`, TSIG live reload |
| `internal/dnsserver/server.go` | `ddnsMsgAcceptFunc` — accepts OpcodeUpdate, bypasses miekg default rejection |
| `internal/filestore/tsig.go` | `GetTSIGKeys`, `PutTSIGKey`, `DeleteTSIGKey`, `SetTSIGKeys` |
| `internal/caddy/api/ddns.go` | `DDNSAPIHandler`: REST API GET/POST/DELETE `/api/ddns/keys` + `GET /api/ddns/status` |
| `internal/store/types.go` | `TSIGKey` struct (Name, Algorithm, Secret, CreatedAt) |

### Data Storage

TSIG keys are stored in `tsig_keys.json` in the data directory:

```
/var/lib/domudns/data/
  tsig_keys.json   # []store.TSIGKey (secrets in plaintext, local only!)
```

**Cluster sync:** TSIG keys are propagated to all slaves as an `EventTSIGKeys` push event (keys are mirrored on slaves, as clients may also send UPDATEs directly to slaves).

## Prometheus Metrics

- **Endpoint:** `http://<pi>:9090/metrics` (no auth)
- **Metrics:**

```
dns_queries_total{qtype="A", result="forwarded"}
dns_queries_total{qtype="A", result="blocked"}
dns_queries_total{qtype="A", result="cached"}
dns_queries_total{qtype="A", result="authoritative"}
dns_query_duration_seconds{result="forwarded"} (histogram)
api_requests_total{method="GET", path="/api/zones", status="200"}
```

---

