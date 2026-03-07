# REST API Reference

Base path: `/api`

All endpoints except `/api/health` require authentication via `Authorization: Bearer <API_KEY>`.

## Authentication

The API key is set via the setup wizard (`/setup`) and stored in `auth.json`.

**API access (curl / scripts):**
```bash
curl -H "Authorization: Bearer <64-hex-character-API-key>" \
  http://192.0.2.1/api/zones
```

**Browser access:** `/login` → username + password → session cookie is sent automatically.

**Retrieve API key:** Dashboard → Settings → Security → show / regenerate API key.

## Health Check

### Check system health
```http
GET /api/health
```

**Authentication:** None required

**Response on success:**
```json
{
  "status": "ok"
}
```

**Response on problems:**
```json
{
  "status": "degraded",
  "details": "database connection failed"
}
```

## Zones (DNS Zones)

### List all zones
```http
GET /api/zones
```

**Response:**
```json
{
  "success": true,
  "zones": [
    {
      "domain": "example.com",
      "ttl": 3600,
      "nameservers": ["ns1.example.com", "ns2.example.com"],
      "admin_email": "admin@example.com",
      "soa": {
        "mname": "ns1.example.com",
        "rname": "admin.example.com",
        "serial": 2026021601,
        "refresh": 3600,
        "retry": 1800,
        "expire": 604800,
        "minimum": 300
      },
      "created_at": "2026-02-16T12:00:00Z",
      "updated_at": "2026-02-16T12:00:00Z"
    }
  ]
}
```

### Get zone details
```http
GET /api/zones/{domain}
```

**Parameter:**
- `domain`: domain name (e.g., `example.com`)

**Response:**
```json
{
  "success": true,
  "zone": {
    "domain": "example.com",
    "ttl": 3600,
    "nameservers": ["ns1.example.com", "ns2.example.com"],
    "admin_email": "admin@example.com",
    "soa": { ... }
  }
}
```

### Create zone
```http
POST /api/zones
Content-Type: application/json
```

**Request Body:**
```json
{
  "domain": "example.com",
  "ttl": 3600,
  "ttl_override": 300,
  "records": []
}
```

**Response:**
```json
{
  "data": {
    "domain": "example.com",
    "ttl": 3600,
    "ttl_override": 300,
    "records": []
  }
}
```

**Fields:**
- `domain` (required): domain name (e.g., `example.com`)
- `ttl` (optional): default TTL in seconds (default: 3600, minimum: 300)
- `ttl_override` (optional): if > 0 — normalizes all DNS response TTLs of this zone to this value (except SOA). Minimum: 60s, maximum: 604800s (7 days).
- `view` (optional): view name for split-horizon DNS (empty = default zone)
- `records` (optional): list of initial DNS records

### Update zone
```http
PUT /api/zones/{domain}
Content-Type: application/json
```

**Request Body:**
```json
{
  "ttl": 7200,
  "nameservers": ["ns1.example.com", "ns2.example.com"],
  "admin_email": "admin@example.com"
}
```

### Delete zone
```http
DELETE /api/zones/{domain}
```

**Response:**
```json
{
  "success": true,
  "message": "Zone deleted successfully"
}
```

## Records (DNS Records)

### List all records of a zone
```http
GET /api/zones/{domain}/records
```

**Response:**
```json
{
  "success": true,
  "records": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "www",
      "type": "A",
      "ttl": 3600,
      "value": "192.168.1.1"
    },
    {
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "name": "mail",
      "type": "MX",
      "ttl": 3600,
      "value": "mail.example.com",
      "priority": 10
    }
  ]
}
```

### Get single record
```http
GET /api/zones/{domain}/records/{id}
```

**Parameter:**
- `domain`: domain name
- `id`: record ID (UUID)

### Create record
```http
POST /api/zones/{domain}/records
Content-Type: application/json
```

**A Record Example:**
```json
{
  "name": "www",
  "type": "A",
  "ttl": 3600,
  "value": "192.168.1.1"
}
```

**AAAA Record Example:**
```json
{
  "name": "www",
  "type": "AAAA",
  "ttl": 3600,
  "value": "2001:db8::1"
}
```

**CNAME Record Example:**
```json
{
  "name": "blog",
  "type": "CNAME",
  "ttl": 3600,
  "value": "www.example.com"
}
```

**MX Record Example:**
```json
{
  "name": "@",
  "type": "MX",
  "ttl": 3600,
  "value": "mail.example.com",
  "priority": 10
}
```

**TXT Record Example:**
```json
{
  "name": "@",
  "type": "TXT",
  "ttl": 3600,
  "value": "v=spf1 include:_spf.example.com ~all"
}
```

**Supported record types:**
- `A` - IPv4 address
- `AAAA` - IPv6 address
- `CNAME` - Canonical Name
- `MX` - Mail Exchange (requires `priority`)
- `TXT` - Text record
- `NS` - Nameserver
- `SOA` - Start of Authority
- `SRV` - Service (requires `priority`, `weight`, `port`)
- `CAA` - Certification Authority Authorization
- `PTR` - Pointer (for reverse DNS)
- `FWD` - Fallback forwarding (internal, `name: "@"` only, not a DNS RR)

**FWD Record Example:**
```json
{
  "name": "@",
  "type": "FWD",
  "ttl": 3600,
  "value": "helium.ns.hetzner.de, 1.1.1.1"
}
```

**FWD behavior:** If the zone is configured locally but a subdomain record does not exist (would result in NXDOMAIN), the request is forwarded to the FWD servers instead. Local records always take precedence. `name` must be `@` (zone apex). `value`: comma-separated IP addresses or FQDNs (port optional, default: 53).

### Update record
```http
PUT /api/zones/{domain}/records/{id}
Content-Type: application/json
```

**Request Body:** Same as for creating

### Delete record
```http
DELETE /api/zones/{domain}/records/{id}
```

## Blocklist

### Get blocklist URLs
```http
GET /api/blocklist/urls
```

**Response:**
```json
{
  "success": true,
  "urls": [
    {
      "id": 1,
      "url": "https://easylist.to/easylist/easylist.txt",
      "description": "EasyList - Standard Adblocker",
      "enabled": true,
      "last_fetched_at": "2026-02-16T12:00:00Z",
      "domain_count": 150000
    }
  ]
}
```

### Add blocklist URL
```http
POST /api/blocklist/urls
Content-Type: application/json
```

**Request Body:**
```json
{
  "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
  "description": "StevenBlack Unified Hosts",
  "enabled": true
}
```

**Supported formats:**
- **Hosts format**: `0.0.0.0 ads.example.com`
- **Plain domain list**: `ads.example.com`
- **Comments**: `# Comment` (are ignored)

### Update blocklist URL
```http
PUT /api/blocklist/urls/{id}
Content-Type: application/json
```

**Request Body:**
```json
{
  "enabled": false,
  "description": "Temporarily disabled"
}
```

### Delete blocklist URL
```http
DELETE /api/blocklist/urls/{id}
```

### Reload blocklist (manual)
```http
POST /api/blocklist/reload
```

**Response:**
```json
{
  "success": true,
  "message": "Blocklist reload initiated",
  "domains_loaded": 220000
}
```

**Note:** This endpoint triggers a manual reload of the blocklist. Normally the blocklist reloads automatically every 24 hours (configurable via `blocklist.fetch_interval`).

### Search blocked domains
```http
GET /api/blocklist/domains?search=ads&limit=100
```

**Query parameters:**
- `search`: search term (optional)
- `limit`: max. number of results (default: 100)

**Response:**
```json
{
  "success": true,
  "domains": [
    "ads.example.com",
    "ads.tracker.com"
  ],
  "total": 2
}
```

## Whitelist (Client IP Whitelist)

### Get whitelisted IPs
```http
GET /api/blocklist/whitelist
```

**Response:**
```json
{
  "success": true,
  "ips": [
    {
      "cidr": "192.168.1.0/24",
      "description": "Admin network",
      "created_at": "2026-02-16T12:00:00Z"
    },
    {
      "cidr": "10.0.0.50/32",
      "description": "Admin laptop",
      "created_at": "2026-02-16T13:00:00Z"
    }
  ]
}
```

### Add IP to whitelist
```http
POST /api/blocklist/whitelist
Content-Type: application/json
```

**Request Body:**
```json
{
  "cidr": "192.168.1.0/24",
  "description": "Admin network - bypasses blocklist"
}
```

**Notes:**
- `cidr` must be valid CIDR notation (e.g., `192.168.1.0/24` or `10.0.0.50/32`)
- Whitelisted IPs bypass the blocklist entirely
- Use case: admin devices, trusted networks

### Remove IP from whitelist
```http
DELETE /api/blocklist/whitelist/{cidr}
```

**Parameter:**
- `cidr`: CIDR block (URL-encoded, e.g., `192.168.1.0%2F24`)

**Example:**
```bash
curl -X DELETE \
  -H "Authorization: Bearer API_KEY" \
  "https://dns1.example.com/api/blocklist/whitelist/192.168.1.0%2F24"
```

## Config (Configuration Overrides)

### Get config
```http
GET /api/config
```

**Response:**
```json
{
  "success": true,
  "data": {
    "dnsserver": {
      "upstream": ["1.1.1.1", "8.8.8.8"],
      "cache": { "enabled": true, "max_entries": 10000 },
      "doh": { "enabled": false, "path": "/dns-query" }
    },
    "blocklist": { "enabled": true, "block_mode": "zero_ip" },
    "system": { "log_level": "info", "auth": { "api_key": "***" } }
  }
}
```

### Update config (with live reload)
```http
PATCH /api/config
Content-Type: application/json
```

**Request Body** (only editable top-level keys):
```json
{
  "dnsserver": {
    "upstream": ["9.9.9.9", "149.112.112.112"]
  }
}
```

**Editable top-level keys:**
- `dnsserver` — DNS server settings (upstream, cache, etc.)
- `caddy` — HTTP server settings
- `blocklist` — blocklist settings
- `system` — log level, metrics, rate limiting
- `performance` — performance tuning

**Live reload (effective immediately, no restart required):**
- `dnsserver.upstream` — switch upstream DNS servers
- `dnsserver.conditional_forwards` — update conditional forwarding rules
- `blocklist.block_mode` — switch block response mode (`zero_ip` → `nxdomain`)
- `system.log_level` — change log level (`debug`, `info`, `warn`, `error`)

**Restart required:**
- `dnsserver.listen`, `dnsserver.cache.*`, `dnsserver.doh.*`, `blocklist.fetch_interval`, `caddy.tls.*`

**Response:**
```json
{
  "success": true,
  "data": { "message": "Config updated. Some changes may require restart." }
}
```

**Note:** Config overrides are stored in `config_overrides.json` in the data directory and loaded automatically on restart. On master nodes, overrides are propagated to all slaves via the `config_overrides` event.

## DNS over HTTPS (DoH, RFC 8484)

The DoH endpoint is **outside** the `/api` path and requires **no authentication**.
It is enabled in `configs/config.yaml`:

```yaml
dnsserver:
  doh:
    enabled: true
    path: "/dns-query"
```

### GET request (base64url-encoded)
```http
GET /dns-query?dns=<base64url-encoded-dns-message>
Accept: application/dns-message
```

**Example with curl:**
```bash
# Query "google.com" A record
DNS_MSG=$(echo -n '\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01' | base64 -w0 | tr '+/' '-_' | tr -d '=')
curl -H "Accept: application/dns-message" "http://192.0.2.1/dns-query?dns=$DNS_MSG"
```

### POST request (wire format)
```http
POST /dns-query
Content-Type: application/dns-message
Accept: application/dns-message
```

**Example with curl:**
```bash
curl -X POST "http://192.0.2.1/dns-query" \
  -H "Content-Type: application/dns-message" \
  -H "Accept: application/dns-message" \
  --data-binary @dns_query.bin
```

**Response:**
- Content-Type: `application/dns-message`
- Body: DNS response in wire format (RFC 1035)
- Cache-Control: `max-age=<minTTL>` (TTL from the DNS response)

**Browser configuration (Firefox):**
```
about:config → network.trr.uri = http://192.0.2.1/dns-query
              network.trr.mode = 3  (DoH only)
```

**Browser configuration (Chrome/Edge):**
```
Settings → Privacy → Security → Secure DNS
→ Provider: Custom → http://192.0.2.1/dns-query
```

**Note:** DoH does not require a restart after activation — however, a restart of domudns is necessary since the HTTP listener is reconfigured. The block response mode (`block_mode`) also applies to DoH requests.

## DNS over TLS (DoT, RFC 7858)

The DoT listener runs on **TCP port 853** and requires a valid TLS certificate.
It is not part of the HTTP server — there is no HTTP endpoint.

Enable in `configs/config.yaml`:

```yaml
dnsserver:
  dot:
    enabled: true
    listen: "[::]:853"
    cert_file: "/etc/letsencrypt/live/example.com/fullchain.pem"
    key_file: "/etc/letsencrypt/live/example.com/privkey.pem"
    # empty = use caddy.tls.cert_file/key_file
```

**Test DoT query:**
```bash
# With kdig (from knot-dnsutils):
kdig @192.0.2.1 -p 853 +tls google.com

# With stubby (systemd-resolved alternative):
stubby -l -C /etc/stubby/stubby.yml

# With systemd-resolved (Ubuntu/Debian):
# In /etc/systemd/resolved.conf:
# DNS=192.0.2.1
# DNSOverTLS=yes
```

**Android configuration:**
```
Settings → Network → Advanced DNS → Private DNS
→ Hostname: 192.0.2.1
```

**iOS configuration:**
```
Settings → Wi-Fi → DNS → Manual
→ DoT via configuration profile (mobileconfig)
```

**Note:** DoT requires a restart — the TCP TLS listener cannot be enabled/disabled without a restart. The block response mode (`block_mode`) also applies to DoT requests.

## Query Log

### Get DNS queries
```http
GET /api/query-log
```

**Query parameters (all optional):**

| Parameter | Description | Example |
|-----------|-------------|---------|
| `client` | Client IP (partial match) | `192.168.1` |
| `domain` | Domain (partial match) | `google` |
| `result` | Result filter | `blocked`, `forwarded`, `cached`, `authoritative`, `error` |
| `qtype` | DNS record type | `A`, `AAAA`, `CNAME` |
| `node` | Node ID (cluster) | `dns-node-1` |
| `since` | Entries from this point in time (RFC3339) | `2026-02-21T10:00:00Z` |
| `until` | Entries up to this point in time | `2026-02-21T11:00:00Z` |
| `limit` | Max. entries (default: 100, max: 1000) | `500` |
| `offset` | Pagination | `100` |

**Response:**
```json
{
  "success": true,
  "data": {
    "entries": [
      {
        "id": "01234567-...",
        "timestamp": "2026-02-21T10:00:00.123Z",
        "client": "192.0.2.1",
        "domain": "ads.example.com.",
        "qtype": "A",
        "result": "blocked",
        "upstream": "",
        "latency_ms": 0,
        "rcode": 0,
        "node": "dns-node-1"
      }
    ],
    "total": 1,
    "limit": 100,
    "offset": 0
  }
}
```

### Get query log statistics
```http
GET /api/query-log/stats
```

**Response:**
```json
{
  "success": true,
  "data": {
    "total_queries": 15420,
    "block_rate": 0.23,
    "top_clients": [
      { "client": "192.0.2.1", "count": 5120 }
    ],
    "top_domains": [
      { "domain": "google.com.", "count": 980 }
    ],
    "top_blocked": [
      { "domain": "ads.example.com.", "count": 340 }
    ],
    "histogram_24h": [
      { "hour": "2026-02-21T09:00:00Z", "count": 640 }
    ]
  }
}
```

## DDNS (RFC 2136) — TSIG Keys

RFC 2136 allows DHCP servers (e.g. ISC dhcpd) to update DNS records directly via DNS UPDATE messages. Authentication is done via TSIG (HMAC-SHA256/SHA512/SHA1).

**Prerequisite:** The target zone must exist in DomU DNS as an authoritative zone.

### List TSIG keys
```http
GET /api/ddns/keys
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "name": "dhcp-key",
      "algorithm": "hmac-sha256",
      "created_at": "2026-02-25T10:00:00Z"
    }
  ]
}
```

**Note:** The secret is not returned for security reasons (only once at creation time).

### Create TSIG key
```http
POST /api/ddns/keys
Content-Type: application/json
```

**Request Body:**
```json
{
  "name": "dhcp-key",
  "algorithm": "hmac-sha256"
}
```

**Fields:**
- `name` (required): unique key name (no spaces or slashes)
- `algorithm` (optional): `hmac-sha256` (default), `hmac-sha512`, `hmac-sha1`

**Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "name": "dhcp-key",
    "algorithm": "hmac-sha256",
    "secret": "base64-encoded-secret-32-bytes",
    "created_at": "2026-02-25T10:00:00Z"
  }
}
```

**Important:** The `secret` is returned **only once** at creation time. Enter it in the ISC dhcpd configuration immediately!

### Delete TSIG key
```http
DELETE /api/ddns/keys/{name}
```

**Response:** `204 No Content`

### Get DDNS runtime status
```http
GET /api/ddns/status
```

Returns key count and runtime statistics of the DDNS handler.

**Response:**
```json
{
  "success": true,
  "data": {
    "key_count": 1,
    "total_updates": 42,
    "last_update_at": "2026-03-07T10:00:00Z",
    "total_failed": 0,
    "last_rejected_reason": "",
    "last_rejected_at": null
  }
}
```

**Fields:**
- `key_count`: number of configured TSIG keys
- `total_updates`: successful UPDATE messages processed since last restart
- `last_update_at`: timestamp of the last successful UPDATE
- `total_failed`: total rejected UPDATE messages (NOTZONE, NOTAUTH, SERVFAIL)
- `last_rejected_reason`: human-readable rejection reason (e.g. `"NOTZONE: home"`, `"NOTAUTH: TSIG-Verifikation fehlgeschlagen"`)
- `last_rejected_at`: timestamp of the last rejection

### ISC dhcpd configuration

After creating a TSIG key, add it to `/etc/dhcp/dhcpd.conf`:

```
# TSIG key (copy from DomU DNS Dashboard)
key "dhcp-key" {
    algorithm hmac-sha256;
    secret "base64-secret-enter-here";
}

# Configure DNS zone
zone home. {
    primary 192.0.2.1;
    key "dhcp-key";
}

# Enable DDNS in dhcpd
ddns-update-style interim;
ddns-updates on;
update-static-leases on;

subnet 192.0.2.1 netmask 255.255.255.0 {
    range 192.0.2.1 192.0.2.1;
    ddns-domainname "home.";
    ddns-rev-domainname "in-addr.arpa.";
}
```

### Supported DNS UPDATE operations

| Class | Meaning | Example |
|-------|---------|---------|
| `IN` (ClassINET) | Add / update record | DHCP lease assigned |
| `NONE` (ClassNONE) | Delete specific record | DHCP lease expired |
| `ANY` (ClassANY) | Delete all records for this name | Release hostname |

**Supported record types in UPDATE messages:** A, AAAA, CNAME, TXT, PTR

### Test DNS UPDATE directly

```bash
# nsupdate for manual DDNS updates
nsupdate -k /etc/named/dhcp-key.conf << EOF
server 192.0.2.1
zone home.
update add mydevice.home. 60 A 192.0.2.1
send
EOF
```

## Cluster Info

### Get cluster configuration
```http
GET /api/cluster
```

**Authentication:** Required

**Purpose:** The frontend uses this endpoint to dynamically load cluster nodes (overview page).

**Response (Master):**
```json
{
  "success": true,
  "data": {
    "role": "master",
    "remote_nodes": [
      {
        "label": "Slave 1",
        "url": "http://192.0.2.2:80",
        "ip": "192.0.2.2",
        "role": "slave"
      }
    ]
  }
}
```

**Response (Slave):**
```json
{
  "success": true,
  "data": {
    "role": "slave",
    "remote_nodes": [
      {
        "label": "Master",
        "url": "http://192.0.2.1:80",
        "ip": "192.0.2.1",
        "role": "master"
      }
    ]
  }
}
```

**Response (Standalone, no cluster):**
```json
{
  "success": true,
  "data": {
    "role": "master",
    "remote_nodes": []
  }
}
```

## ACME DNS-01 Challenge

### Present challenge (create TXT record)
```http
POST /api/acme/dns-01/present
Content-Type: application/json
```

**Request Body:**
```json
{
  "domain": "example.com",
  "txt_value": "base64-encoded-validation-string"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Challenge record created for _acme-challenge.example.com"
}
```

**Usage:** Let's Encrypt (or another ACME CA) calls this endpoint to create a TXT record for the DNS-01 challenge.

### Clean up challenge (delete TXT record)
```http
POST /api/acme/dns-01/cleanup
Content-Type: application/json
```

**Request Body:**
```json
{
  "domain": "example.com"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Challenge record removed for _acme-challenge.example.com"
}
```

## Prometheus Metrics

Separate HTTP server on port 9090 (no auth). Enable via config:

```yaml
system:
  metrics:
    enabled: true
    listen: "0.0.0.0:9090"
```

### Get metrics
```bash
curl http://192.0.2.1:9090/metrics
```

**Available metrics:**
```
# HELP dns_queries_total Total number of DNS queries processed
# TYPE dns_queries_total counter
dns_queries_total{qtype="A",result="blocked"} 12345
dns_queries_total{qtype="A",result="authoritative"} 456
dns_queries_total{qtype="A",result="cached"} 9876
dns_queries_total{qtype="A",result="forwarded"} 3210
dns_queries_total{qtype="A",result="error"} 5

# HELP dns_query_duration_seconds DNS query processing duration
# TYPE dns_query_duration_seconds histogram
dns_query_duration_seconds_bucket{result="forwarded",le="0.005"} 3000
dns_query_duration_seconds_bucket{result="forwarded",le="0.01"} 3150
dns_query_duration_seconds_sum{result="forwarded"} 12.34
dns_query_duration_seconds_count{result="forwarded"} 3210

# HELP api_requests_total Total number of HTTP API requests
# TYPE api_requests_total counter
api_requests_total{method="GET",path="/api/zones",status="200"} 100
```

**result labels:** `blocked`, `authoritative`, `cached`, `forwarded`, `error`

## Error Responses

### Standard error format

```json
{
  "success": false,
  "error": {
    "code": "ZONE_NOT_FOUND",
    "message": "Zone 'example.com' not found"
  }
}
```

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | OK - Successful request |
| 201 | Created - Resource created |
| 400 | Bad Request - Invalid input |
| 401 | Unauthorized - Missing or invalid authentication |
| 404 | Not Found - Resource not found |
| 409 | Conflict - Resource already exists |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error - Server error |
| 503 | Service Unavailable - Service not available |

### Error Codes

| Code | Description |
|------|-------------|
| `INVALID_JSON` | Invalid JSON in request body |
| `INVALID_ZONE` | Zone validation failed |
| `ZONE_NOT_FOUND` | Zone not found |
| `ZONE_EXISTS` | Zone already exists |
| `INVALID_RECORD` | Record validation failed |
| `RECORD_NOT_FOUND` | Record not found |
| `INVALID_CIDR` | Invalid CIDR notation |
| `DB_ERROR` | Database error |
| `UNAUTHORIZED` | Missing or invalid authentication |
| `NOT_FOUND` | Resource not found |
| `RATE_LIMIT_EXCEEDED` | Rate limit exceeded |

## Rate Limiting

Rate limiting is enabled by default:
- **Default**: 100 requests per minute per client IP
- **Configurable**: via `system.rate_limit.requests_per_minute` in config.yaml

**Response when rate limited:**
```json
{
  "success": false,
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Try again in 60 seconds."
  }
}
```

**Headers:**
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1708099200
```

## cURL Examples

### Create zone
```bash
curl -X POST https://dns1.example.com/api/zones \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "ttl": 3600,
    "nameservers": ["ns1.example.com", "ns2.example.com"],
    "admin_email": "admin@example.com"
  }'
```

### Add A record
```bash
curl -X POST https://dns1.example.com/api/zones/example.com/records \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "www",
    "type": "A",
    "ttl": 3600,
    "value": "192.168.1.1"
  }'
```

### Add blocklist URL
```bash
curl -X POST https://dns1.example.com/api/blocklist/urls \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://easylist.to/easylist/easylist.txt",
    "description": "EasyList - Standard Adblocker"
  }'
```

### Add client IP to whitelist
```bash
curl -X POST https://dns1.example.com/api/blocklist/whitelist \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "cidr": "192.168.1.0/24",
    "description": "Admin network"
  }'
```

---

