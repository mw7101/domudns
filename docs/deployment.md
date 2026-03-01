# Deployment Guide

This guide describes the deployment of DomU DNS on a Raspberry Pi 3B or similar systems.

## Prerequisites

### Hardware
- **Raspberry Pi 3B** (or newer) with 1 GB+ RAM
- **SD card:** At least 16 GB (32 GB recommended)
- **Network:** Ethernet connection recommended (more stable than WiFi for DNS)

### Software
- **Operating system:** Debian Bookworm/Trixie or Raspbian
- **Go:** Version 1.24+ (only for local builds)

> **No external database backend required.** The DNS stack stores all data as local JSON files under `/var/lib/domudns/data/`.

## Operating Modes

| Mode | When | Notes |
|------|------|-------|
| **Standalone** | Single Pi | `cluster.role: "master"`, no `slaves:` — no cluster overhead, no sync secret |
| **Master** | Multi-node, leading node | `slaves:` list + `DOMUDNS_SYNC_SECRET` |
| **Slave** | Multi-node, receiving node | `master_url:` + `DOMUDNS_SYNC_SECRET` |

**Standalone is the default case** and is described in this guide. For multi-node operation: [docs/clustering.md](clustering.md).

### Build Machine
- **Local:** macOS, Linux, or Windows with Go 1.24+
- **Cross-compilation:** Works out of the box (GOARCH=arm GOARM=7)

## Quick Start (Local Build)

### Step 1: Clone the repository

```bash
git clone https://github.com/mw7101/domudns.git
cd domudns
```

### Step 2: Build the binary

```bash
# For local testing (same architecture)
make build

# For Raspberry Pi 3B (ARMv7)
make build-arm
```

The binary will be located at `build/domudns` or `build/domudns-arm` respectively.

### Step 3: Test locally (no database setup required)

```bash
# Create configuration directory
mkdir -p /tmp/dns-test-data

# Adjust config.dev.yaml (data_dir: /tmp/dns-test-data)
sudo ./build/domudns -config configs/config.dev.yaml
```

## Deployment on Raspberry Pi

### Step 1: Create directories

```bash
sudo mkdir -p /etc/domudns /var/lib/domudns/data /usr/local/bin
```

### Step 2: Install binary

```bash
# Stop service if running (caution: "device busy" with active process)
sudo systemctl stop domudns 2>/dev/null || true

# Copy binary and make executable
sudo cp build/domudns-arm /usr/local/bin/domudns
sudo chmod +x /usr/local/bin/domudns
```

### Step 3: Create configuration

`/etc/domudns/config.yaml`:

```yaml
# Cluster configuration — standalone (single Pi, no cluster)
# No slaves: → no push, no sync, no sync secret required
cluster:
  role: "master"
  data_dir: "/var/lib/domudns/data"
  # For multi-node cluster add slaves: and push_timeout (→ docs/clustering.md)

# DNS Server
dnsserver:
  listen: "[::]:53"
  upstream:
    - "1.1.1.1"
    - "8.8.8.8"
  cache:
    enabled: true
    max_entries: 10000
    default_ttl: 3600
    negative_ttl: 300
  udp_size: 4096
  tcp_timeout: "5s"
  # Conditional forwarding (optional): route specific domains to specific DNS servers
  # conditional_forwards:
  #   - domain: "fritz.box"
  #     servers: ["192.168.178.1"]

# Blocklist
blocklist:
  enabled: true
  file_path: "/var/lib/domudns/blocklist.hosts"
  fetch_interval: "24h"
  block_ip4: "0.0.0.0"
  block_ip6: "::"
  default_urls:
    - "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

# HTTP Server
caddy:
  listen: "0.0.0.0:80"
  web_ui:
    enabled: true

# System
system:
  log_level: "info"
  metrics:
    enabled: true
    listen: "0.0.0.0:9090"
  rate_limit:
    enabled: true
    api_requests: 100
  # Query log: record DNS requests (in-memory + optional SQLite)
  query_log:
    enabled: true
    memory_entries: 5000    # ~3 MB RAM
    persist: false          # true = enable SQLite persistence
    # persist_path: ""      # Default: <data_dir>/query.log.db
    # persist_days: 7       # Retention in days
```

### Step 4: Configure environment variables

`/etc/domudns/env`:

```bash
# Sync secret for cluster (optional for standalone)
# DOMUDNS_SYNC_SECRET=<64-hex-characters>
```

```bash
sudo chmod 600 /etc/domudns/env
```

### Step 5: Install systemd service

```bash
sudo cp scripts/domudns.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable domudns
sudo systemctl start domudns
```

`scripts/domudns.service` (contents for reference):

```ini
[Unit]
Description=DomU DNS
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/domudns/env
ExecStart=/usr/local/bin/domudns -config /etc/domudns/config.yaml
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

### Step 6: Check status

```bash
sudo systemctl status domudns
sudo journalctl -u domudns -f
```

Expected log output on first start:

```
starting lightweight dns stack version=dev
file backend initialized data_dir=/var/lib/domudns/data role=master
blocklist: default URL registered url=https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
HTTP server starting addr=0.0.0.0:80
DNS server starting addr=[::]:53
metrics server starting addr=0.0.0.0:9090
setup-wizard active: http://<host>/setup — default login: admin/admin
```

### Step 7: Run the setup wizard

Open a browser and navigate to: `http://<pi-ip>/`
→ Automatic redirect to `/setup`

- Login: `admin` / `admin`
- Set a new password
- Generate an API key
- Click `Save` — setup complete

## Testing the DNS Configuration

```bash
# Test forwarding
dig @<pi-ip> google.com

# Test blocklist (should return 0.0.0.0)
dig @<pi-ip> doubleclick.net

# Test authoritative zone (after creating a zone via API)
dig @<pi-ip> example.com A

# Test reverse DNS (after creating a PTR zone)
dig -x 192.0.2.1 @<pi-ip>

# Check cache (second call should be 0ms)
dig @<pi-ip> google.com | grep "Query time"
```

## Deployment via CI/CD (GitHub)

The project uses GitHub CI/CD for automated deployment. Required variables:

| Variable | Description |
|----------|-------------|
| `SSH_PRIVATE_KEY` | Base64-encoded SSH key for all Pis |

The pipeline script in `.github/workflows/`:
1. Cross-compiles for ARMv7
2. Stops service on all Pis
3. Copies binary via SCP
4. Copies `config.yaml`
5. Starts service

## Configuration via Web UI (Live Reload)

Some settings can be changed without a service restart:

```bash
# Switch upstream DNS (live)
curl -X PATCH http://<pi-ip>/api/config \
  -H "Authorization: Bearer <API-KEY>" \
  -H "Content-Type: application/json" \
  -d '{"dnsserver": {"upstream": ["9.9.9.9", "149.112.112.112"]}}'

# Set conditional forwarding (live)
curl -X PATCH http://<pi-ip>/api/config \
  -H "Authorization: Bearer <API-KEY>" \
  -H "Content-Type: application/json" \
  -d '{"dnsserver": {"conditional_forwards": [{"domain": "fritz.box", "servers": ["192.168.178.1"]}]}}'

# Change log level (live)
curl -X PATCH http://<pi-ip>/api/config \
  -H "Authorization: Bearer <API-KEY>" \
  -H "Content-Type: application/json" \
  -d '{"system": {"log_level": "debug"}}'
```

Changes are saved to `config_overrides.json` and survive restarts.

## Production Checklist

- [ ] Password set via setup wizard (no longer `admin/admin`)
- [ ] API key set and stored securely
- [ ] Blocklist URL(s) configured and fetch successful
- [ ] Trusted client IPs added to whitelist
- [ ] Rate limiting enabled (`system.rate_limit.enabled: true`)
- [ ] Log level set to `warn` for production
- [ ] Upstream DNS servers configured (consider privacy)
- [ ] Prometheus metrics enabled and reachable
- [ ] `DOMUDNS_SYNC_SECRET` set (for cluster setup)
- [ ] Systemd service set to `enable` (autostart after reboot)
- [ ] Firewall: port 53 only for LAN clients, port 80 only for LAN, port 9090 only for monitoring
- [ ] DoT: open port 853/tcp in firewall (if DoT is enabled)
- [ ] DoT: TLS certificate present and configured

## Updates

```bash
# Build new binary
make build-arm

# Deploy (service stops automatically thanks to systemd)
scp build/domudns-arm root@<pi-ip>:/tmp/domudns-new
ssh root@<pi-ip> "systemctl stop domudns && \
  cp /tmp/domudns-new /usr/local/bin/domudns && \
  chmod +x /usr/local/bin/domudns && \
  systemctl start domudns"

# Check status
ssh root@<pi-ip> "systemctl status domudns"
```

> **Important:** Stop the service BEFORE copying (Linux "device busy" error with a running process).

## Troubleshooting

### Service does not start

```bash
sudo journalctl -u domudns -n 50
# Common causes:
# - Port 53 in use (systemd-resolved)
# - Error in config.yaml (YAML syntax)
# - data_dir missing / no write permission
```

### Port 53 in use

```bash
# Disable systemd-resolved (Debian/Ubuntu)
sudo systemctl disable --now systemd-resolved
sudo rm /etc/resolv.conf
echo "nameserver 1.1.1.1" | sudo tee /etc/resolv.conf
```

### Forgotten password / reset setup

```bash
# Delete or clear auth.json
sudo sh -c 'echo "{}" > /var/lib/domudns/data/auth.json'
sudo systemctl restart domudns
# Now again: admin/admin → /setup
```

### Blocklist not loaded

```bash
# Check fetch logs
sudo journalctl -u domudns | grep -i "blocklist\|fetch"

# Manually reload
curl -X POST http://localhost/api/blocklist/reload \
  -H "Authorization: Bearer <API-KEY>"
```

---

