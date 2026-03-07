# DomU DNS

A resource-efficient, full-featured DNS server stack in Go for Raspberry Pi 3B (1 GB RAM).

## Features

- ✅ **Custom DNS Server:** High-performance DNS server using `github.com/miekg/dns`
- ✅ **Blocklist with Whitelist:** 220k+ blocked domains, client-IP-based whitelist
- ✅ **Wildcard & Regex Blocking:** Pattern-based blocking (`*.ads.com`, `/^tracker[0-9]+/`)
- ✅ **Block Response Mode:** `zero_ip` (0.0.0.0) or `nxdomain` — switchable live
- ✅ **Default Blocklist URLs:** Automatically pre-populated on first installation (StevenBlack Hosts)
- ✅ **Authoritative Zones:** DNS zones from local file backend with 0ms response time
- ✅ **FWD Record:** Internal record type for zone-internal fallback forwarding (NXDOMAIN → external DNS)
- ✅ **Conditional Forwarding:** Domain-specific forwarding rules (e.g. `fritz.box` → FritzBox)
- ✅ **Zone Auto-Reload:** Zones are immediately updated in the DNS server after API changes
- ✅ **Config Live-Reload:** Change upstream DNS, conditional forwards, block mode and log level without service restart
- ✅ **PTR Records:** Full validation for reverse DNS (in-addr.arpa, ip6.arpa)
- ✅ **Response Cache:** In-memory LRU cache with TTL expiration and **Cache Warming** (preloads popular domains at startup)
- ✅ **Query Log:** Searchable log of all DNS queries (in-memory + SQLite, slave push)
- ✅ **DNS over HTTPS (DoH):** RFC 8484 compliant DoH endpoint (GET + POST, no auth)
- ✅ **DNS over TLS (DoT):** RFC 7858 compliant DoT listener (TCP port 853, TLS certificate required)
- ✅ **DNSSEC Support:** AD-flag delegation (stub resolver mode, RFC 4035) — set DO bit, propagate AD bit, filter DNSSEC RRs
- ✅ **RFC 2136 DDNS:** DNS UPDATE via TSIG authentication — ISC dhcpd sends lease updates directly as DNS UPDATE (no external script)
- ✅ **DHCP Lease Sync:** Automatic A/PTR records from DHCP leases (dnsmasq/FritzBox), dashboard at `/api/dhcp/leases`
- ✅ **TTL Override per Zone:** Normalizes all DNS response TTLs of a zone to a configured value (except SOA) — ideal for Windows clients
- ✅ **DNS Rebinding Protection:** Blocks upstream responses that resolve public domains to private IPs (RFC1918/loopback)
- ✅ **Prometheus Metrics:** Queries, latency, cache rate on port 9090
- ✅ **Let's Encrypt:** Automatic TLS certificates via DNS-01 challenge
- ✅ **Next.js Dashboard:** Modern management interface (TypeScript, Tailwind, Recharts)
- ✅ **DB Auth:** User authentication (bcrypt, sessions, API key) in local file backend
- ✅ **Setup Wizard:** Guided initial setup on first login
- ✅ **REST API:** Full API for all DNS operations
- ✅ **Master/Slave Cluster:** File-based clustering with HTTP push/pull — no external backend required
- ✅ **Ultra Low RAM:** ~25 MB for DNS server + blocklist + cache

## Performance

| Metric | Value |
|--------|-------|
| **RAM Usage** | ~25 MB (DNS server + blocklist + cache) |
| **Response Time (Cache)** | 0 ms |
| **Response Time (Authoritative)** | 0 ms |
| **Response Time (Upstream)** | 1-8 ms |
| **Blocklist Size** | 220,000+ domains |
| **Blocklist Lookup** | O(1) - hash map |
| **Cache Size** | 10,000 entries (~5 MB) |

**Target Platform:** Raspberry Pi 3B (ARMv7, 1GB RAM)

## Components

| Component | Function | Port |
|-----------|----------|------|
| **DNS Server** | Custom Go DNS server (UDP/TCP) | 53 |
| **HTTP Server** | Web UI + REST API | 80 / 443 |
| **Metrics Server** | Prometheus metrics (no auth) | 9090 |
| **File Backend** | Local JSON files, no external DB required | — |

## Operating Modes

| Mode | Description | Configuration |
|------|-------------|---------------|
| **Standalone** | A single Pi, no cluster | `cluster.role: "master"`, no `slaves:` |
| **Master** | Leading node, propagates to slaves | `cluster.role: "master"` + `slaves: [...]` |
| **Slave** | Receives data from master, read-only API | `cluster.role: "slave"` + `master_url: ...` |

**Standalone is the default** — no `DOMUDNS_SYNC_SECRET`, no cluster overhead, full functionality on a single Pi.

## Quick Start

### Prerequisites

- Go 1.24+
- Raspberry Pi 3B with Debian/Raspbian (or compatible)
- Root access for port 53

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/mw7101/domudns.git
cd domudns

# 2. Build binary for Raspberry Pi
make build-arm

# 3. Test locally (requires sudo for port 53)
sudo ./build/domudns -config configs/config.yaml
```

### Deployment to Raspberry Pi

```bash
# 1. Copy binary
scp build/domudns-arm pi@dns-node-1:/tmp/

# 2. Install on the Raspberry Pi
ssh pi@dns-node-1
sudo systemctl stop domudns
sudo cp /tmp/domudns-arm /usr/local/bin/domudns
sudo chmod +x /usr/local/bin/domudns

# 3. Copy configuration
sudo mkdir -p /etc/domudns /var/lib/domudns/data
sudo cp configs/config.yaml /etc/domudns/

# 4. Install systemd service
sudo cp scripts/domudns.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable domudns
sudo systemctl start domudns

# 5. Check status
sudo systemctl status domudns
```

## Configuration

Edit `/etc/domudns/config.yaml`:

```yaml
# Cluster configuration
cluster:
  role: "master"              # "master" | "slave"
  data_dir: "/var/lib/domudns/data"
  # Slaves (master only):
  # slaves:
  #   - "http://192.0.2.2:80"
  # Master URL (slave only):
  # master_url: "http://192.0.2.1:80"
  push_timeout: "5s"
  poll_interval: "30s"

# DNS server configuration
dnsserver:
  listen: "[::]:53"              # IPv4+IPv6 dual-stack
  upstream:
    - "1.1.1.1"                  # Cloudflare
    - "8.8.8.8"                  # Google DNS
  cache:
    enabled: true
    max_entries: 10000           # ~5MB RAM
    default_ttl: 3600            # 1 hour
    negative_ttl: 300            # 5 minutes for NXDOMAIN
    warmup_count: 200            # Domains to preload at startup (0 = disabled)
  udp_size: 4096
  tcp_timeout: 5s
  # Conditional forwarding: route specific domains to specific DNS servers
  # conditional_forwards:
  #   - domain: "fritz.box"
  #     servers: ["192.168.178.1"]
  #   - domain: "corp.internal"
  #     servers: ["10.0.0.1", "10.0.0.2"]
  # DNS over HTTPS (RFC 8484) — browser compatibility
  doh:
    enabled: false               # true to enable
    path: "/dns-query"           # RFC 8484 standard path
  # DNS over TLS (RFC 7858) — Android 9+, iOS 14+, systemd-resolved
  dot:
    enabled: false               # true to enable (restart required)
    listen: "[::]:853"           # IPv4+IPv6 dual-stack on port 853
    # cert_file: ""              # empty = use caddy.tls.cert_file
    # key_file: ""               # empty = use caddy.tls.key_file

# Blocklist configuration
blocklist:
  enabled: true
  file_path: "/var/lib/domudns/blocklist.hosts"
  fetch_interval: 24h            # Update daily
  block_ip4: "0.0.0.0"           # IPv4 block response (zero_ip mode)
  block_ip6: "::"                # IPv6 block response (zero_ip mode)
  block_mode: "zero_ip"          # "zero_ip" (default) | "nxdomain" (faster for browsers)
  default_urls:                  # Automatically populated on first installation
    - "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

# HTTP server
caddy:
  listen: "0.0.0.0:80"          # TLS: "0.0.0.0:443"

# System
system:
  log_level: info                # debug, info, warn, error
  metrics:
    enabled: true
    listen: "0.0.0.0:9090"
```

### Environment Variables

```bash
# Sync secret for cluster communication (HMAC-SHA256, same on all nodes)
export DOMUDNS_SYNC_SECRET="<64-hex-characters>"

# Log level (optional, overrides config.yaml)
export LOG_LEVEL="debug"
```

**Note:** API key and password are set via the setup wizard — no environment variable required.

## Web UI

After startup the web UI is available at:

- **Production:** http://192.0.2.1 (or your configured IP)
- **Development:** http://localhost:80

**First login:** `admin` / `admin` → redirected to setup wizard → set password and API key.

**API access:** `Authorization: Bearer <API-Key>` (visible in the web UI after the setup wizard).

### Dashboard Features (Next.js)

- ✅ Create and manage DNS zones
- ✅ Add/edit/delete DNS records (A, AAAA, CNAME, MX, TXT, NS, SRV, PTR, CAA, **FWD**)
- ✅ FWD record: name automatically `@`, comma-separated DNS servers
- ✅ PTR records: full validation (reverse DNS for in-addr.arpa and ip6.arpa)
- ✅ Manage blocklist URLs (including default URLs)
- ✅ Wildcard/regex patterns for blocklist (e.g. `*.ads.com`, `/^tracker[0-9]+/`)
- ✅ Block response mode: `zero_ip` or `nxdomain` — switchable live
- ✅ Client IP whitelist for admins
- ✅ DoH status and DoT status on overview page + configuration in settings
- ✅ Adjust configuration via UI — **live reload** for upstream DNS, block mode and log level
- ✅ Change password and API key via UI (Settings → Security)
- ✅ Prometheus monitoring page with live metrics (query rate, latency, cache rate), time range **1h/24h/7d/30d** (default: 1h)
- ✅ **Overview statistics:** Top clients, top domains, top blocks, QPS time series (Recharts)
- ✅ **Query Log:** Searchable table of all DNS queries (live refresh 5s, filter by client/domain/result)
- ✅ **Query Log action menu:** Add a blocked domain to the whitelist with one click
- ✅ **DDNS page:** Create/delete TSIG keys, runtime stats (total updates, failures, last rejection), contextual diagnosis banners (NOTZONE, NOTAUTH), pre-filled ISC dhcpd config guide
- ✅ **Zone TTL Override:** Optionally configurable per zone — normalizes all response TTLs (except SOA)

## REST API Examples

### Create a Zone

```bash
curl -X POST http://dns1.example.com/api/zones \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "ttl": 3600,
    "ttl_override": 300,
    "records": []
  }'
```

`ttl_override` (optional, 0 = disabled): Normalizes all DNS response TTLs of this zone to the specified value (minimum 60s, maximum 604800s). SOA records are excluded.

### Add an A Record

```bash
curl -X POST http://dns1.example.com/api/zones/example.com/records \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "www",
    "type": "A",
    "ttl": 3600,
    "value": "192.0.2.1"
  }'
```

### PTR Record for Reverse DNS

```bash
# Create reverse zone (for 192.168.100.x)
curl -X POST http://dns1.example.com/api/zones \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"domain": "100.168.192.in-addr.arpa", "ttl": 3600}'

# Add PTR record (192.0.2.1 → router.int.example.com)
curl -X POST "http://dns1.example.com/api/zones/100.168.192.in-addr.arpa/records" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "1", "type": "PTR", "ttl": 3600, "value": "router.int.example.com"}'

# Test reverse DNS
dig -x 192.0.2.1 @192.0.2.1
```

### Update Config Live (no restart required)

```bash
# Switch upstream DNS
curl -X PATCH http://dns1.example.com/api/config \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"dnsserver": {"upstream": ["9.9.9.9", "149.112.112.112"]}}'

# Change log level
curl -X PATCH http://dns1.example.com/api/config \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"system": {"log_level": "debug"}}'
```

### Add a Blocklist URL

```bash
curl -X POST http://dns1.example.com/api/blocklist/urls \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://someonewhocares.org/hosts/hosts", "description": "Dan Pollock Hosts"}'
```

### Create a TSIG Key for DDNS

```bash
# Create a new TSIG key (secret is returned only once!)
curl -X POST http://dns1.example.com/api/ddns/keys \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "dhcp-key", "algorithm": "hmac-sha256"}'

# List all TSIG keys
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://dns1.example.com/api/ddns/keys
```

## DNS Server Architecture

The custom DNS server processes all DNS queries through a multi-stage pipeline:

```
Incoming DNS query (port 53)
    ↓
1. Extract client IP
    ↓
2. Blocklist check
    ├─ Client IP whitelisted? → skip blocklist
    ├─ Domain blocked? → return 0.0.0.0 / ::
    └─ Not blocked →
        ↓
3. Authoritative zone check
    ├─ Zone + record found? → authoritative response (aa flag, 0ms)
    └─ Zone found, but no record (NXDOMAIN)?
        ↓
3.5 FWD fallback (if FWD record at zone apex)
    ├─ FWD record present? → forward to FWD server (no aa flag)
    └─ No FWD record → return NXDOMAIN
        ↓
4. Cache check
    ├─ Cache hit? → cached response (0ms)
    └─ Cache miss →
        ↓
4.5 Conditional forwarding (if rule configured for domain)
    ├─ Rule matches (longest match)? → forward to configured DNS server + cache
    └─ No rule →
        ↓
5. Forward to default upstream
    ├─ Round-robin: 1.1.1.1, 8.8.8.8
    ├─ UDP first, TCP fallback on truncation
    └─ Cache response
        ↓
5.5 DNS Rebinding Protection (if enabled)
    ├─ External domain resolves to private IP? → NXDOMAIN (attack blocked)
    ├─ Domain on whitelist? → allow through
    └─ No attack detected →
        ↓
Return response
```

### Components

- **Server** (`server.go`): UDP/TCP listener, graceful shutdown, live upstream update
- **Handler** (`handler.go`): Query processing pipeline
- **Forwarder** (`forwarder.go`): Upstream DNS forwarding with round-robin, thread-safe upstream update
- **ConditionalForwarder** (`forwarder.go`): Domain-specific forwarding rules, longest match
- **BlocklistManager** (`blocklist.go`): In-memory blocklist + whitelist
- **ZoneManager** (`zones.go`): Authoritative zones from file backend
- **CacheManager** (`cache.go`): LRU cache with TTL expiration + cache warming (`warmup.go`)
- **RebindingProtector** (`rebinding.go`): DNS rebinding protection (RFC1918/loopback detection)
- **DDNSHandler** (`update.go`): RFC 2136 DNS UPDATE with TSIG authentication

## Standalone Operation (single Pi)

**No cluster required.** A single Pi runs fully self-contained:

```yaml
# /etc/domudns/config.yaml — minimal standalone configuration
cluster:
  role: "master"              # Default, can also be omitted
  data_dir: "/var/lib/domudns/data"
  # NO slaves: → no push, no sync, no sync secret required

dnsserver:
  listen: "[::]:53"
  upstream: ["1.1.1.1", "8.8.8.8"]

blocklist:
  enabled: true
  file_path: "/var/lib/domudns/blocklist.hosts"
  fetch_interval: "24h"
  default_urls:
    - "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
```

In standalone mode:
- ✅ Full DNS functionality (blocklist, zones, cache, FWD, PTR, conditional forwarding)
- ✅ Full web UI and REST API (read + write)
- ✅ Blocklist fetch every 24h
- ✅ Prometheus metrics
- No cluster sync (not needed)
- No `DOMUDNS_SYNC_SECRET` required

## Master/Slave Cluster

For HA operation with multiple Raspberry Pis:

```
Pi 1 (Master) ──── HTTP Push ──→ Pi 2 (Slave)
      └──────────── HTTP Push ──→ Pi 3 (Slave)

Pi 2+3 poll master as fallback every 30s
```

- **No external backend:** Data is stored as local JSON files
- **Push protocol:** Master POSTs changes to all slaves (secured with HMAC-SHA256)
- **Fallback polling:** Slaves poll master every 30s if push is missed
- **Slave = read-only:** Configuration changes only possible on master
- **Blocklist fetch:** Only master fetches external lists → propagates to slaves

Full guide: [docs/clustering.md](docs/clustering.md)

## Monitoring

```bash
# Fetch Prometheus metrics
curl http://192.0.2.1:9090/metrics

# Key metrics:
# dns_queries_total{qtype="A", result="forwarded"}
# dns_query_duration_seconds{result="cached"}
# api_requests_total{method="GET", path="/api/zones", status="200"}
```

Monitoring stack (Prometheus + Grafana) in `monitoring/`:

```bash
cd monitoring && docker compose up -d
# Grafana: http://localhost:3000
```

## Troubleshooting

### DNS not working

```bash
# Check service status
sudo systemctl status domudns
sudo journalctl -u domudns -f

# Test DNS query
dig @127.0.0.1 google.com
dig @127.0.0.1 example.com  # Authoritative zone

# Health check
curl http://localhost/api/health
```

### Blocklist not loading

```bash
# Check blocklist status
curl -H "Authorization: Bearer KEY" http://localhost/api/blocklist/urls

# Check logs (fetch errors?)
sudo journalctl -u domudns | grep blocklist

# Reload manually
curl -X POST -H "Authorization: Bearer KEY" http://localhost/api/blocklist/reload
```

### Switch upstream DNS (live, no restart)

```bash
curl -X PATCH http://localhost/api/config \
  -H "Authorization: Bearer KEY" \
  -H "Content-Type: application/json" \
  -d '{"dnsserver": {"upstream": ["9.9.9.9", "149.112.112.112"]}}'
```

### Forgot password

```bash
# Reset auth.json
echo '{}' > /var/lib/domudns/data/auth.json
sudo systemctl restart domudns
# Now login again with admin/admin → setup wizard
```

### Slave not synchronizing

```bash
# Test master connection
curl http://192.0.2.1/api/health

# Check slave logs
sudo journalctl -u domudns | grep -E "poll|sync|push"

# Check sync secret (must be identical on all nodes)
cat /etc/domudns/env | grep SYNC_SECRET
```

## Development

```bash
# Run all tests
make test-unit

# Run a single test
go test -v -run TestBlocklistManager ./internal/dnsserver/
go test -v -run TestValidateRecord ./internal/dns/

# Test DNS server locally (sudo for port 53)
sudo ./build/domudns -config configs/config.dev.yaml

# In another terminal
dig @127.0.0.1 google.com
dig -x 192.168.1.1 @127.0.0.1   # Reverse DNS (PTR)
```

## License

MIT License — see [LICENSE](LICENSE)

