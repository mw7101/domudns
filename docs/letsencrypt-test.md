# Let's Encrypt DNS-01 with DomU DNS

DomU DNS can answer `_acme-challenge.*` TXT queries directly from its internal challenge store.
Any ACME client that speaks DNS-01 will receive the correct TXT record when it queries your DNS server.

## Prerequisites

1. Public domain whose NS records point to your DomU DNS instance
2. DomU DNS is reachable on port 53 (TCP + UDP) from the public internet **or** you use split-horizon so Let's Encrypt queries the public server
3. A **Named API Key** from the DomU DNS dashboard (Settings → Sicherheit → API-Schlüssel → + Neuer API-Schlüssel)

---

## Option 1: acme.sh (recommended for Linux/Proxmox)

### Install acme.sh

```bash
curl https://get.acme.sh | sh
```

### Copy the hook script

```bash
cp /path/to/domudns/scripts/dns_domudns.sh ~/.acme.sh/dnsapi/dns_domudns.sh
chmod +x ~/.acme.sh/dnsapi/dns_domudns.sh
```

### Issue certificate

```bash
export DOMUDNS_URL=http://192.0.2.1
export DOMUDNS_API_KEY=<named api key from dashboard>

acme.sh --issue --dns dns_domudns -d example.com -d '*.example.com'
```

### Proxmox ACME (Datacenter → ACME → DNS Plugin)

| Field | Value |
|-------|-------|
| Plugin ID | `domudns` |
| API data | `DOMUDNS_URL=http://192.0.2.1` |
| | `DOMUDNS_API_KEY=<named api key>` |

---

## Option 2: Certbot DNS Plugin

### Install

```bash
pip install certbot certbot-dns-domudns
# or from local source:
pip install /path/to/domudns/certbot-dns-domudns/
```

### Credentials file `/etc/letsencrypt/domudns.ini`

```ini
certbot_dns_domudns:dns_domudns_url = http://192.0.2.1
certbot_dns_domudns:dns_domudns_api_key = <named api key from dashboard>
```

```bash
chmod 600 /etc/letsencrypt/domudns.ini
```

### Issue certificate (staging)

```bash
certbot certonly \
  --authenticator dns-domudns \
  --dns-domudns-credentials /etc/letsencrypt/domudns.ini \
  --server https://acme-staging-v02.api.letsencrypt.org/directory \
  -d example.com -d '*.example.com'
```

### Issue certificate (production)

```bash
certbot certonly \
  --authenticator dns-domudns \
  --dns-domudns-credentials /etc/letsencrypt/domudns.ini \
  -d example.com -d '*.example.com'
```

---

## Option 3: Traefik httpreq provider

Traefik's `httpreq` DNS provider uses Basic Auth — the named API key is used as the password.

### Traefik static config

```yaml
certificatesResolvers:
  letsencrypt:
    acme:
      email: admin@example.com
      storage: /acme/acme.json
      dnsChallenge:
        provider: httpreq
```

### Environment variables

```bash
HTTPREQ_ENDPOINT=http://192.0.2.1/api/acme/httpreq
HTTPREQ_USERNAME=traefik           # any string
HTTPREQ_PASSWORD=<named api key>   # from DomU DNS dashboard
```

---

## Option 4: Manual API test

Verify the full flow before using an ACME client:

```bash
API=http://192.0.2.1
KEY=<named api key>

# 1. Store challenge
curl -X POST $API/api/acme/dns-01/present \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","txt_value":"test-token-123"}'

# 2. Query DNS — must return "test-token-123"
dig @192.0.2.1 _acme-challenge.example.com TXT

# 3. Remove challenge
curl -X POST $API/api/acme/dns-01/cleanup \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com"}'
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `dig` returns NXDOMAIN | Challenge not stored yet, or TTL expired (default 60s) |
| "Invalid API key" | Use a Named API Key from Settings → Sicherheit → API-Schlüssel |
| "Connection refused" | DomU DNS HTTP server not reachable on the configured port |
| "Domain does not resolve" | NS records for the domain must point to your DomU DNS server |
| Rate limit exceeded | Use staging: `--server https://acme-staging-v02.api.letsencrypt.org/directory` |
| Traefik: 401 Unauthorized | Check `HTTPREQ_PASSWORD` matches the Named API Key exactly |
