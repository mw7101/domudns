# PTR / Reverse DNS Setup

## Overview

PTR records (pointer records) enable reverse DNS lookups: an IP address is resolved to a hostname.

Example: `dig -x 192.0.2.1 @192.0.2.1` → `router.int.example.com`

The custom DNS server fully supports PTR records in authoritative reverse zones.

## How Reverse DNS Works

The DNS request for `192.0.2.1` is internally converted to:
```
1.100.168.192.in-addr.arpa  PTR  ?
```

For IPv6 (`2001:db8::1`) it becomes:
```
1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa  PTR  ?
```

## Step 1: Create a reverse zone

### IPv4 reverse zone (in-addr.arpa)

For the subnet `192.0.2.1/24` the zone name is `100.168.192.in-addr.arpa`:

```bash
curl -X POST http://192.0.2.1/api/zones \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "100.168.192.in-addr.arpa",
    "ttl": 3600
  }'
```

### IPv6 reverse zone (ip6.arpa)

```bash
curl -X POST http://192.0.2.1/api/zones \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
    "ttl": 3600
  }'
```

## Step 2: Add PTR records

### IPv4 PTR record

Name = last octet of the IP address (0-255), value = hostname (FQDN):

```bash
# 192.0.2.1 → router.int.example.com
curl -X POST "http://192.0.2.1/api/zones/100.168.192.in-addr.arpa/records" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "1",
    "type": "PTR",
    "ttl": 3600,
    "value": "router.int.example.com"
  }'

# 192.0.2.1 → webserver.int.example.com
curl -X POST "http://192.0.2.1/api/zones/100.168.192.in-addr.arpa/records" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "5",
    "type": "PTR",
    "ttl": 3600,
    "value": "webserver.int.example.com"
  }'
```

### IPv6 PTR record (ip6.arpa)

In `ip6.arpa` zones the name must be a single hex nibble (0-9, a-f):

```bash
curl -X POST "http://192.0.2.1/api/zones/0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa/records" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "1",
    "type": "PTR",
    "ttl": 3600,
    "value": "host.example.com"
  }'
```

## Step 3: Test

**Important:** Use `dig -x` for reverse DNS lookups (not `dig <ip>`)!

```bash
# IPv4 reverse lookup
dig -x 192.0.2.1 @192.0.2.1

# Expected:
# 1.100.168.192.in-addr.arpa. 3600 IN PTR router.int.example.com.

# Or with host:
host 192.0.2.1 192.0.2.1
# router.int.example.com

# IPv6 reverse lookup
dig -x 2001:db8::1 @192.0.2.1
```

## PTR Record Validation Rules

The DNS stack validates PTR records strictly:

| Field | Rule | Error on violation |
|-------|------|--------------------|
| `value` | Must be a hostname (FQDN) — **not an IP address** | `invalid PTR record: value must be a hostname` |
| `value` | Must be a valid FQDN | `invalid domain name: invalid PTR target name` |
| `name` in in-addr.arpa | Must be `@` or a number 0-255 | `invalid PTR record: name in in-addr.arpa must be a number 0-255` |
| `name` in ip6.arpa | Must be `@` or a hex nibble (0-9, a-f) | `invalid PTR record: name in ip6.arpa must be a hex nibble` |

**Common errors:**

```bash
# WRONG: IP address as value
{"name": "1", "type": "PTR", "value": "192.0.2.1"}
# → Error: value must be a hostname, not an IP address

# WRONG: Hostname as name (instead of number)
{"name": "router", "type": "PTR", "value": "router.example.com"}
# → Error: name in in-addr.arpa must be a number 0-255

# WRONG: Number > 255
{"name": "256", "type": "PTR", "value": "host.example.com"}
# → Error: name in in-addr.arpa must be a number 0-255

# CORRECT:
{"name": "1", "type": "PTR", "value": "router.int.example.com"}
```

## Automatic Zone Reload

After adding or modifying a PTR record, the zone is immediately reloaded in the DNS server — no service restart required:

```bash
# Add record
curl -X POST "http://192.0.2.1/api/zones/100.168.192.in-addr.arpa/records" \
  -H "Authorization: Bearer KEY" \
  -d '{"name":"10","type":"PTR","ttl":3600,"value":"nas.int.example.com"}'

# Test immediately (no restart needed!)
dig -x 192.0.2.1 @192.0.2.1
```

## Subnet Mapping

| Subnet | Zone name |
|--------|-----------|
| 192.0.2.1/24 | `100.168.192.in-addr.arpa` |
| 192.168.1.0/24 | `1.168.192.in-addr.arpa` |
| 10.0.0.0/24 | `0.0.10.in-addr.arpa` |
| 172.16.0.0/24 | `0.16.172.in-addr.arpa` |

For /16 networks:

| Subnet | Zone name |
|--------|-----------|
| 192.168.0.0/16 | `168.192.in-addr.arpa` |
| 10.0.0.0/8 | `10.in-addr.arpa` |

For /16 or /8 zones the name is then the last 2 or 3 octets, e.g. `100.5` for `10.5.100.x`.

## Troubleshooting

| Symptom | Cause | Solution |
|---------|-------|----------|
| `NXDOMAIN` on `dig -x` | Zone not created | Create zone `x.y.z.in-addr.arpa` via API |
| `NXDOMAIN` on `dig -x` | PTR record missing | Create record with correct octet name |
| `SERVFAIL` | DNS server not reachable | Check `systemctl status domudns` |
| Wrong hostname | PTR value incorrect | Update record via API |
| `dig 192.0.2.1` (no -x) | A query instead of PTR query | Use `dig -x 192.0.2.1` |

### Most Common Error: `dig` Without `-x`

```bash
# WRONG: queries for the A record of "192.0.2.1" (NXDOMAIN, because that is not a domain)
dig 192.0.2.1 @192.0.2.1

# CORRECT: PTR reverse lookup
dig -x 192.0.2.1 @192.0.2.1
```

---

