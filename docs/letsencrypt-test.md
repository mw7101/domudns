# Testing Let's Encrypt

## Prerequisites

1. **Public domain** that points to your server
2. **DNS server** from domudns is authoritative for the domain (e.g. `int.example.com`)
3. The domain must point to your NS at the domain registrar

## Use staging (recommended for testing)

Let's Encrypt staging has higher rate limits and does not issue trusted certificates — ideal for testing.

## Option 1: Certbot with manual hooks

### Step 1: Make hooks executable

```bash
chmod +x scripts/certbot-dns-hook.sh scripts/certbot-dns-hook-cleanup.sh
```

### Step 2: Install Certbot

```bash
sudo apt install certbot
```

### Step 3: Request staging certificate

```bash
export DOMUDNS_API_URL="http://127.0.0.1:80"   # or your API URL
export DOMUDNS_API_KEY="your-api-key-from-setup-wizard"

sudo certbot certonly \
  --manual \
  --preferred-challenges dns \
  --manual-auth-hook "$(pwd)/scripts/certbot-dns-hook.sh" \
  --manual-cleanup-hook "$(pwd)/scripts/certbot-dns-hook-cleanup.sh" \
  --server https://acme-staging-v02.api.letsencrypt.org/directory \
  -d your.domain.com
```

### Step 4: Verify DNS is working

Check the TXT record before Certbot runs (after the auth hook, before validation):

```bash
# Must query your DNS server (port 53)
dig @127.0.0.1 _acme-challenge.your.domain.com TXT
```

## Option 2: Test the API manually

### Step 1: Create challenge

```bash
curl -X POST http://127.0.0.1/api/acme/dns-01/present \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"domain": "int.example.com", "txt_value": "test-validation-123"}'
```

### Step 2: Verify DNS query

```bash
dig @127.0.0.1 _acme-challenge.int.example.com TXT
```

Expected: TXT with `test-validation-123`

### Step 3: Remove challenge

```bash
curl -X POST http://127.0.0.1/api/acme/dns-01/cleanup \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"domain": "int.example.com"}'
```

## Common Errors

| Problem | Solution |
|---------|----------|
| "Domain does not resolve" | NS records for the domain must point to your DNS server |
| "Connection refused" | domudns is not running or HTTP server not reachable (port 80/443) |
| "Invalid API key" | Use API key from setup wizard or `/var/lib/domudns/data/auth.json` |
| Rate limit | Use staging server: `--server https://acme-staging-v02.api.letsencrypt.org/directory` |

## Production

For real certificates, omit `--server` (uses production) and make sure the domain is correctly configured.
