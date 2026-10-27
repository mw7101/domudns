# DomU DNS

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.24-00ADD8.svg)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-ARMv7%20%7C%20ARM64%20%7C%20AMD64-orange.svg)](#)
[![RAM](https://img.shields.io/badge/RAM-%7E25%20MB-brightgreen.svg)](#performance)
[![Domains Blocked](https://img.shields.io/badge/Blocked-220k%2B%20domains-red.svg)](#)

**A lightweight, privacy-first DNS server for Raspberry Pi 3B** — ad blocking, authoritative zones, RFC 2136 DDNS, Split-Horizon, Let's Encrypt DNS-01, and Master/Slave clustering in a single Go binary using ~25 MB RAM.

> **Website & Docs:** [domudns.net](https://domudns.net)

---

## Why DomU DNS?

Every existing DNS solution was either too heavy for a Raspberry Pi 3B or lacked features needed for a proper homelab:

| Feature | DomU DNS | Pi-hole | AdGuard Home | Technitium |
|---|:---:|:---:|:---:|:---:|
| **RAM on Pi 3B** | **~25 MB** | 80–160 MB | 50–130 MB | 200 MB+ |
| Ad blocking (220k+ domains) | ✅ | ✅ | ✅ | ✅ |
| Authoritative DNS zones | ✅ | ❌ | ❌ | ✅ |
| RFC 2136 DDNS (TSIG) | ✅ | ❌ | ❌ | ✅ |
| Split-Horizon DNS | ✅ | ❌ | ❌ | Partial |
| Zone Transfer AXFR/IXFR | ✅ | ❌ | ❌ | ✅ |
| Master/Slave Cluster | ✅ | ❌ | ❌ | ✅ |
| DoH + DoT | ✅ | Partial | ✅ | ✅ |
| Let's Encrypt DNS-01 | ✅ | ❌ | ❌ | Partial |
| DNSSEC signing | ✅ | ❌ | ❌ | ✅ |
| LRU Cache + Warming | ✅ | ❌ | ❌ | ❌ |
| No database required | ✅ | ❌ | ✅ | ✅ |
| Runtime | **Go binary** | C/FTL+dnsmasq | Go | .NET runtime |

---

## Features

- 🛡️ **Ad & Tracker Blocking** — 220k+ domains, O(1) lookup, wildcard/regex support
- 🌐 **Authoritative DNS Zones** — A, AAAA, MX, CNAME, PTR, TXT, SRV, CAA, NS; JSON file backend
- 🔄 **RFC 2136 DDNS** — ISC dhcpd / Kea DHCP integration via TSIG; auto PTR records
- 🔀 **Split-Horizon DNS** — different answers for internal vs. external clients
- 🔗 **Master/Slave Cluster** — HMAC-SHA256, atomic JSON writes, no database
- 🔒 **DoH + DoT** — RFC 8484 / RFC 7858 with your own certificates
- 🔐 **Let's Encrypt DNS-01** — built-in ACME provider; Traefik httpreq, Certbot plugin, acme.sh/Proxmox
- 🚫 **DNS Rebinding Protection** — blocks external domains resolving to private IPs
- ⚡ **LRU Cache + Warming** — preloads top-N query-log domains at startup
- 📊 **Next.js Dashboard** — real-time stats, zone management, query log, cluster status
- 🔁 **Zone Transfer AXFR/IXFR** — ACL-protected, TCP-only
- 📡 **DHCP Lease Sync** — dnsmasq / FritzBox lease files → DNS records
- 🔑 **Named API Keys** — per-service API keys with revocation
- 📈 **Prometheus Metrics** — queries, latency, cache hit rate
- ⚙️ **Live Config Reload** — upstream DNS, block mode, log level without restart

---

## Performance

| Metric | Value |
|--------|-------|
| RAM on Raspberry Pi 3B | ~25 MB |
| Blocklist size | 220,000+ domains |
| Blocklist lookup | O(1) — hash map |
| Response time (cache hit) | 0 ms |
| Response time (authoritative) | 0 ms |
| Response time (upstream) | 1–8 ms |
| Cache capacity | 10,000 entries (~5 MB) |

---

## Quick Start

```bash
# 1. Clone & build for Raspberry Pi 3B (ARMv7)
git clone https://github.com/mw7101/domudns.git
cd domudns && make build-arm

# 2. Copy to Pi
scp build/domudns-arm pi@<PI_IP>:/usr/local/bin/domudns

# 3. Install service & start
scp scripts/domudns.service pi@<PI_IP>:/tmp/
ssh pi@<PI_IP> "sudo mv /tmp/domudns.service /etc/systemd/system/ && sudo systemctl enable --now domudns"

# 4. Open setup wizard
open http://<PI_IP>/setup
```

> **No database required.** All data is stored as JSON files under `/var/lib/domudns/data/`.
> **Full docs:** [domudns.net/docs/quickstart.html](https://domudns.net/docs/quickstart.html)

---

## Installation

### Prerequisites

- Go 1.24+ (build machine only)
- Raspberry Pi 3B with Debian Bookworm/Raspbian — or any Linux AMD64/ARM64/ARMv7
- SSH access to the target host
- Port 53 free (stop `systemd-resolved` if needed)

### Step 1 — Build

```bash
git clone https://github.com/mw7101/domudns.git
cd domudns

# Raspberry Pi 3B (ARMv7)
make build-arm

# ARM64 (Pi 4/5, modern SBCs)
make build-arm64

# AMD64 (x86 server, NAS, VPS)
make build
```

### Step 2 — Install on target host

```bash
# Create directories
ssh pi@<PI_IP> "sudo mkdir -p /etc/domudns /var/lib/domudns/data /usr/local/bin"

# Copy binary
scp build/domudns-arm pi@<PI_IP>:/tmp/domudns
ssh pi@<PI_IP> "sudo mv /tmp/domudns /usr/local/bin/domudns && sudo chmod +x /usr/local/bin/domudns"
```

### Step 3 — Minimal Configuration

Create `/etc/domudns/config.yaml` on the host:

```yaml
cluster:
  role: "master"
  data_dir: "/var/lib/domudns/data"

dnsserver:
  listen: "[::]:53"
  upstream:
    - "9.9.9.9"           # Quad9
    - "149.112.112.112"

http:
  listen: ":80"

system:
  log_level: "info"
```

### Step 4 — Start

```bash
scp scripts/domudns.service pi@<PI_IP>:/tmp/
ssh pi@<PI_IP> "
  sudo mv /tmp/domudns.service /etc/systemd/system/
  sudo systemctl daemon-reload
  sudo systemctl enable --now domudns
"
```

### Step 5 — First-Time Setup

Open `http://<PI_IP>/setup` in your browser. The wizard guides you through:
1. Set admin username and password
2. Generate a secure API key
3. Configure blocklist sources
4. Add your local DNS zones

---

## Configuration

Full reference: [domudns.net/docs/config.html](https://domudns.net/docs/config.html)

```yaml
cluster:
  role: "master"              # "master" | "slave"
  data_dir: "/var/lib/domudns/data"
  # slaves:
  #   - "http://<SLAVE_IP>:80"

dnsserver:
  listen: "[::]:53"
  upstream:
    - "9.9.9.9"
    - "149.112.112.112"
  cache:
    enabled: true
    max_entries: 10000
    warmup_count: 200         # Preload top domains from query log at startup
  # DNS over HTTPS (RFC 8484)
  doh:
    enabled: false
    path: "/dns-query"
  # DNS over TLS (RFC 7858)
  dot:
    enabled: false
    listen: "[::]:853"

blocklist:
  enabled: true
  file_path: "/var/lib/domudns/blocklist.hosts"
  fetch_interval: 24h
  block_mode: "zero_ip"       # "zero_ip" | "nxdomain"
  default_urls:
    - "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

http:
  listen: "0.0.0.0:80"

system:
  log_level: info
  metrics:
    enabled: true
    listen: "0.0.0.0:9090"
```

### Environment Variables

```bash
# Cluster sync secret (HMAC-SHA256, same on all nodes — required for clustering)
export DOMUDNS_SYNC_SECRET="<64-hex-characters>"
```

---

## High Availability Cluster

```
Pi 1 (Master) ──── HTTP Push ──→ Pi 2 (Slave)
```

- Master pushes zone/blocklist/config changes to all slaves via HMAC-SHA256-signed HTTP
- Slaves poll master as fallback every 30s
- Set both IPs as DNS servers in your router's DHCP settings → automatic failover

```yaml
# Master (/etc/domudns/config.yaml)
cluster:
  role: "master"
  slaves:
    - "http://<SLAVE_IP>:80"

# Slave (/etc/domudns/config.yaml)
cluster:
  role: "slave"
  master_url: "http://<MASTER_IP>:80"
```

Full guide: [domudns.net/docs/cluster.html](https://domudns.net/docs/cluster.html)

---

## Let's Encrypt DNS-01

DomU DNS acts as a built-in ACME DNS-01 provider — no open port 80 required. Works with:

- **Traefik** — native httpreq provider support
- **Certbot** — DNS plugin (`certbot-dns-domudns`)
- **acme.sh / Proxmox** — shell hook script included

Full guide: [domudns.net/docs/letsencrypt.html](https://domudns.net/docs/letsencrypt.html)

---

## DNS Architecture

```
Incoming query (port 53)
    ↓
1. Blocklist check (O(1) hash lookup)
    ↓
2. DDNS UPDATE handler (RFC 2136, TSIG)
    ↓
3. AXFR/IXFR handler (zone transfers)
    ↓
4. ACME challenge TXT (_acme-challenge.*)
    ↓
5. Authoritative zone (Split-Horizon view-aware)
    ↓
6. LRU Cache
    ↓
7. Conditional forwarding (domain-specific upstreams)
    ↓
8. Default upstream (round-robin UDP, TCP fallback)
    ↓
9. DNS Rebinding Protection
    ↓
Return response
```

---

## REST API

Full reference: [domudns.net/docs/api.html](https://domudns.net/docs/api.html)

```bash
# Create a zone
curl -X POST http://<PI_IP>/api/zones \
  -H "Authorization: Bearer <API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"domain": "home.lan", "ttl": 3600}'

# Add a record
curl -X POST http://<PI_IP>/api/zones/home.lan/records \
  -H "Authorization: Bearer <API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"name": "nas", "type": "A", "ttl": 3600, "value": "192.168.1.100"}'

# Live config update (no restart)
curl -X PATCH http://<PI_IP>/api/config \
  -H "Authorization: Bearer <API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"dnsserver": {"upstream": ["9.9.9.9", "149.112.112.112"]}}'
```

---

## Operating Modes

| Mode | Description | Config |
|------|-------------|--------|
| **Standalone** | Single node, full functionality | `role: "master"`, no `slaves:` |
| **Master** | Pushes changes to slaves | `role: "master"` + `slaves: [...]` |
| **Slave** | Receives from master, read-only API | `role: "slave"` + `master_url: ...` |

---

## Development

```bash
make test           # All tests (unit + integration + security)
make test-unit
make test-integration
make lint && make fmt
sudo make run       # Port 53 requires root
```

---

## Troubleshooting

```bash
# Service status
sudo systemctl status domudns
sudo journalctl -u domudns -f

# Test DNS
dig @<PI_IP> google.com
dig @<PI_IP> ads.doubleclick.net   # Should return 0.0.0.0 (blocked)

# Health check
curl http://<PI_IP>/api/health

# Reset password (forgot credentials)
echo '{}' > /var/lib/domudns/data/auth.json
sudo systemctl restart domudns
# → login with admin/admin → setup wizard
```

---

## License

MIT License — see [LICENSE](LICENSE)
