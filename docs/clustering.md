# Clustering Guide: 2 Nodes (dns1 + dns2)

This guide describes how to deploy DomU DNS in a high-availability 2-node configuration.

## Architecture

The system uses a **file-based master/slave model** without an external database backend:

```
dns1 (Master, 192.0.2.151)
  ├── Accepts all API changes
  ├── Stores data locally (/var/lib/domudns/data/)
  ├── Propagates changes immediately to all slaves (HTTP push)
  └── Fetches external blocklists (every 24h)

dns2 (Slave, 192.0.2.152)
  ├── Receives push events from master
  ├── Polls master as fallback (every 30s)
  ├── Read-only API (configuration on master only)
  └── DNS operation fully autonomous
```

## Prerequisites

- 2× Raspberry Pi 3B with Debian Bookworm/Trixie
- Stable network (Ethernet recommended)
- Static IPs for all nodes
- Open ports: 53 (DNS), 80/443 (HTTP/S), 9090 (metrics)
- `DOMUDNS_SYNC_SECRET` (64 hex characters, identical on all nodes)

## Step 1: Generate sync secret

Once on any machine:

```bash
# Generate secret (64 hex = 32 bytes)
openssl rand -hex 32
# Example output: a3f2c...8e91d4b
```

Enter the secret on **both nodes** in `/etc/domudns/env`:

```bash
# On each Pi:
sudo tee /etc/domudns/env << 'EOF'
DOMUDNS_SYNC_SECRET=a3f2c...8e91d4b
EOF
sudo chmod 600 /etc/domudns/env
```

## Step 2: Configure master (dns1)

`/etc/domudns/config.yaml` on dns1 (192.0.2.151):

```yaml
cluster:
  role: "master"
  data_dir: "/var/lib/domudns/data"
  slaves:
    - "http://192.0.2.152:80"
  push_timeout: "30s"
  poll_interval: "30s"

dnsserver:
  listen: "[::]:53"
  upstream:
    - "1.1.1.1"
    - "8.8.8.8"
  cache:
    enabled: true
    max_entries: 10000

blocklist:
  enabled: true
  file_path: "/var/lib/domudns/blocklist.hosts"
  fetch_interval: "24h"
  block_ip4: "0.0.0.0"
  block_ip6: "::"
  default_urls:
    - "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

system:
  log_level: "info"
  metrics:
    enabled: true
    listen: "0.0.0.0:9090"
```

## Step 3: Configure slave (dns2)

`/etc/domudns/config.yaml` on dns2 (192.0.2.152):

```yaml
cluster:
  role: "slave"
  data_dir: "/var/lib/domudns/data"
  master_url: "http://192.0.2.151:80"
  poll_interval: "30s"

dnsserver:
  listen: "[::]:53"
  upstream:
    - "1.1.1.1"
    - "8.8.8.8"
  cache:
    enabled: true
    max_entries: 10000

blocklist:
  enabled: true
  file_path: "/var/lib/domudns/blocklist.hosts"
  block_ip4: "0.0.0.0"
  block_ip6: "::"

system:
  log_level: "info"
  metrics:
    enabled: true
    listen: "0.0.0.0:9090"
```

## Step 4: Deploy binary and service to all Pis

```bash
# Build (on the development machine)
make build-arm

# Run deployment script (deploys both nodes via CI/CD)
# Or manually on each node:
for PI in 192.0.2.151 192.0.2.152; do
  scp build/domudns-arm root@$PI:/tmp/domudns-new
  ssh root@$PI "systemctl stop domudns; \
    cp /tmp/domudns-new /usr/local/bin/domudns; \
    chmod +x /usr/local/bin/domudns; \
    systemctl start domudns"
done
```

## Step 5: First start and initial sync

```bash
# 1. Start master (Pi 1)
ssh root@192.0.2.151 "systemctl start domudns"

# Watch logs:
# "file backend initialized" data_dir=/var/lib/domudns/data role=master
# "blocklist: default URL registered" url=https://raw.githubusercontent.com/...
# "cluster: master mode, propagating changes to slaves"

# 2. Start slave (dns2)
ssh root@192.0.2.152 "systemctl start domudns"

# Slaves immediately poll the master on start → initial sync
# Slave logs: "cluster: slave mode, read-only API"
```

## Step 6: Run setup wizard on master

```bash
# Browser: http://192.0.2.151/setup
# Or curl:
curl -X POST http://192.0.2.151/api/setup/complete \
  -H "Content-Type: application/json" \
  -d '{
    "password": "your-secure-password",
    "api_key": "your-64-hex-api-key"
  }'
```

After setup, the auth configuration is automatically propagated to all slaves.

## Sync Protocol Details

### Push Events

When a change occurs on the master, the `Propagator` immediately sends an HTTP POST to all slaves:

```
POST http://<slave>/api/internal/sync
Content-Type: application/json
X-DNS-Stack-HMAC: <hmac-sha256-signature>

{
  "event": "zone_updated",
  "data": { ... }  // Full state (no delta)
}
```

**All sync event types:**

| Event | Trigger | Payload |
|-------|---------|---------|
| `zone_updated` | Create, update, or delete zone/record | Complete zone |
| `zone_deleted` | Delete zone | Domain string |
| `blocklist_urls` | URL CRUD | All URLs |
| `url_domains` | Blocklist fetch (24h) | Domains (gzip+base64) |
| `manual_domains` | Manual domain blocklist | All domains |
| `allowed_domains` | Whitelist domains | All allowed domains |
| `whitelist_ips` | Client IP whitelist | All CIDRs |
| `auth_config` | Change password/API key | Auth data |
| `config_overrides` | PATCH /api/config | All overrides |

### Fallback Polling

If a push is lost (slave was offline), the slave polls the master every 30s:

```
GET http://192.0.2.151/api/internal/state

→ Response: complete state (all zones, auth, config, blocklist metadata +
   per-URL domain checksums under `url_domains_meta`)
```

Per-URL **domain lists** are too large for the state response, so the state
only carries `{url_id, sha256}` metadata. The slave compares those checksums
with its local `<id>.domains.gz` files and pulls only the stale or missing
sets:

```
GET http://192.0.2.151/api/internal/url-domains/<id>
X-Sync-Timestamp: <unix_nanos>
X-Sync-Nonce:     <random hex>
X-Sync-HMAC:      <HMAC-SHA256 over "url_domains_pull:<ts>:<nonce>:<id>">

→ Response: raw gzip domain set (application/gzip); written verbatim so the
   local checksum matches the master's
```

This makes a lost `url_domains` push self-healing: without it a slave keeps
the stale set until the master's next fetch cycle (up to 24h), because slaves
never fetch external URLs themselves. The pull endpoint is authenticated with
the same HMAC secret as pushes (URL id + timestamp + one-time nonce).

### Slave Read-Only Protection

Write API requests on slave nodes are rejected with HTTP 403:

```json
{
  "error": "This node is a read-only slave. Please use the master node to make changes.",
  "master_url": "http://192.0.2.151:80"
}
```

Exceptions: `/api/health`, `/api/login`, `/api/setup/*`, `/api/internal/*`

## Blocklist Fetch (Master Only)

```
Master fetch loop (every 24h):
  1. FetchURL(url) → domains []string
  2. PropagatingStore.SetURLDomains(id, domains)
       → Writes url_domains/<id>.domains.gz locally
       → Sends EventURLDomains to all slaves
  3. Slave: Writes url_domains/<id>.domains.gz
       → Calls dnsServer.LoadBlocklist()
  4. Master: Calls dnsServer.LoadBlocklist()
```

Slaves **never** fetch external URLs. Only the master fetches and propagates.
If the `EventURLDomains` push is lost, the slave detects the mismatch via the
polled `url_domains_meta` checksums and pulls the set (see Fallback Polling).

## DNS Load Balancing

For HA operation on router/DHCP:

```bash
# OpenWRT / DD-WRT:
# Primary DNS:   192.0.2.151  (dns1, Master)
# Secondary DNS: 192.0.2.152  (dns2, Slave)

# Pi-hole style (dnsmasq):
server=192.0.2.151
server=192.0.2.152
```

Since all slaves are synchronized with the master, any Pi can answer DNS requests.

## Failover Behavior

| Scenario | Behavior |
|----------|----------|
| Slave goes down | Master + other slave handle DNS; on recovery, slave polling catches up with changes |
| Master goes down | Slaves continue serving with last known state; no new config changes possible |
| Push fails | Bounded retry (0/2s/5s); fallback polling after 30s repairs URL domains via checksums |
| Network partition | Slaves continue operating autonomously; master updates slaves after recovery |

**Master failover:** Manual — promote a slave IP to master role in config.yaml and configure all others as slaves. No automatic leader election.

## Monitoring the Cluster

```bash
# Check health of all nodes
for PI in 151 152; do
  echo -n "dns$((PI-150)) ($PI): "
  curl -s http://192.0.2.$PI/api/health | jq -r .status
done

# Sync status (slave logs)
ssh root@192.0.2.152 "journalctl -u domudns --since '10 minutes ago' | grep -E 'sync|poll|push'"

# Compare Prometheus metrics
for PI in 151 152; do
  echo "=== 192.0.2.$PI ==="
  curl -s http://192.0.2.$PI:9090/metrics | grep dns_queries_total | head -3
done
```

## Troubleshooting

### Slave not synchronizing

```bash
# 1. Is master reachable?
curl http://192.0.2.151/api/health

# 2. Sync secret identical on all nodes?
ssh root@192.0.2.151 "grep SYNC_SECRET /etc/domudns/env"
ssh root@192.0.2.152 "grep SYNC_SECRET /etc/domudns/env"

# 3. Check slave logs
ssh root@192.0.2.152 "journalctl -u domudns -f | grep -E 'poll|sync|error'"

# 4. Trigger manual poll (restart slave)
ssh root@192.0.2.152 "systemctl restart domudns"
```

### Zone not present on slave

```bash
# Check zone file on master
ls /var/lib/domudns/data/zones/

# Check zone file on slave
ssh root@192.0.2.152 "ls /var/lib/domudns/data/zones/"

# Force sync: re-saving zone on master triggers push
curl -X PUT http://192.0.2.151/api/zones/example.com \
  -H "Authorization: Bearer KEY" \
  -H "Content-Type: application/json" \
  -d '{"ttl": 3600}'
```

### Push errors

```bash
# Master logs (push errors?)
ssh root@192.0.2.151 "journalctl -u domudns | grep -E 'push|propagat|slave'"

# Is slave port reachable?
curl http://192.0.2.152/api/health
```

---

