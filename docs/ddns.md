# DDNS (RFC 2136) — Dynamic DNS Updates

DomU DNS supports RFC 2136 DNS UPDATE messages with TSIG authentication.
This allows a DHCP server (e.g. ISC dhcpd) to update DNS records directly when
a device receives or releases an IP address — without external scripts.

## Overview

```
DHCP client (device)
    │ DHCP request
    ↓
ISC dhcpd (DHCP server)
    │ DNS UPDATE (RFC 2136, TSIG-signed, port 53)
    ↓
DomU DNS (authoritative zone)
    │ Add / delete / update A record
    ↓
Zone immediately active in DNS server (no restart)
```

## Prerequisites

- Authoritative zone must exist in DomU DNS (e.g. `home.`)
- ISC dhcpd (isc-dhcp-server) on the same or a different host
- TSIG key created in DomU DNS

## Step 1: Create zone

If not already present:

```bash
curl -X POST http://192.0.2.1/api/zones \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"domain": "home", "ttl": 60}'
```

## Step 2: Create TSIG key

```bash
curl -X POST http://192.0.2.1/api/ddns/keys \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "dhcp-key", "algorithm": "hmac-sha256"}'
```

**Response:**
```json
{
  "success": true,
  "data": {
    "name": "dhcp-key",
    "algorithm": "hmac-sha256",
    "secret": "YOUR-BASE64-SECRET-HERE",
    "created_at": "2026-02-25T10:00:00Z"
  }
}
```

**The secret is only shown once!** Note it immediately and enter it in dhcpd.conf.

Alternatively via dashboard: `DDNS` → `New Key` → copy secret.

## Step 3: Configure ISC dhcpd

In `/etc/dhcp/dhcpd.conf`:

```
# Enable DDNS
ddns-update-style interim;
ddns-updates on;
update-static-leases on;
ignore client-updates;

# TSIG key (from DomU DNS)
key "dhcp-key" {
    algorithm hmac-sha256;
    secret "ENTER-YOUR-BASE64-SECRET-HERE";
}

# DomU DNS as update target
zone home. {
    primary 192.0.2.1;
    key "dhcp-key";
}

# Optional: reverse DNS updates (PTR records)
zone 100.168.192.in-addr.arpa. {
    primary 192.0.2.1;
    key "dhcp-key";
}

# Subnet configuration
subnet 192.0.2.1 netmask 255.255.255.0 {
    range 192.0.2.1 192.0.2.1;
    option routers 192.0.2.1;
    option domain-name "home";
    ddns-domainname "home.";
    ddns-rev-domainname "in-addr.arpa.";
    default-lease-time 3600;
    max-lease-time 86400;
}
```

Then restart dhcpd:

```bash
sudo systemctl restart isc-dhcp-server
```

## Step 4: Functional test

When a DHCP client receives an IP, DomU DNS should automatically create an A record:

```bash
# Check after DHCP lease
dig mydevice.home @192.0.2.1

# Manual test via nsupdate
nsupdate << EOF
server 192.0.2.1
zone home.
key hmac-sha256:dhcp-key YOUR-SECRET-HERE
update add testhost.home. 60 A 192.0.2.1
send
EOF

dig testhost.home @192.0.2.1
```

## ClassINET Semantics (Upsert)

When dhcpd sends an UPDATE with ClassINET (Add), DomU DNS uses **upsert semantics**:
existing records with the same name and type are deleted before the new record is inserted.
This means:

- **IP change:** old A record is automatically replaced — no duplicate
- **dhcpd retry:** same record sent multiple times → only one A record exists

## DDNS Runtime Status

Check the DDNS handler status at any time:

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://192.0.2.1/api/ddns/status
```

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

The dashboard (`DHCP / DDNS` page) shows the same stats as a card grid with contextual diagnosis banners (NOTZONE, NOTAUTH).

## Priorities

If a device name exists both as a static zone record and as a DDNS record,
the following priority applies:

1. **Static zone records** always take precedence (manually created via dashboard/API)
2. **DDNS records** (via RFC 2136 UPDATE) are only used if no static record exists

## Security Notes

- **Never log TSIG secrets** — DomU DNS never writes keys to logs
- **Check tsig_keys.json permissions**: `chmod 600 /var/lib/domudns/data/tsig_keys.json`
- **Only authorized DHCP servers** know the secret — no public access
- DomU DNS rejects all UPDATEs without a valid TSIG (`NOTAUTH`)
- UPDATEs without configured keys are answered with `REFUSED`

## Multiple TSIG Keys

For different clients (e.g. multiple DHCP servers or zones), multiple keys can be created:

```bash
# Key for second DHCP server
curl -X POST http://192.0.2.1/api/ddns/keys \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{"name": "dhcp-key-lan2", "algorithm": "hmac-sha256"}'
```

## Cluster Operation

In master/slave cluster:
- TSIG keys are propagated to all slaves via cluster sync
- Slaves can also receive DNS UPDATEs (optional — clients can target the slave)
- DNS changes from UPDATEs are **not** propagated from slave to master — only master-side UPDATEs are canonical

**Recommendation:** Point DHCP server to master (`primary 192.0.2.1`). The master then automatically propagates zone changes to all slaves.

## Troubleshooting

### UPDATE rejected (NOTAUTH)

```bash
# Check logs
sudo journalctl -u domudns | grep -E "ddns|TSIG|NOTAUTH"
```

Causes:
- Wrong or expired secret in dhcpd.conf
- Key name does not match (case-sensitive)
- dhcpd is using the wrong algorithm (must be exactly `hmac-sha256`, etc.)

### Zone not found (NOTZONE)

```bash
# Check zone on DomU DNS
curl -H "Authorization: Bearer KEY" http://192.0.2.1/api/zones/home
```

The zone must exist in DomU DNS as an authoritative zone.

### No A record created

```bash
# Check DDNS stats (total_updates, last_rejected_reason)
curl -H "Authorization: Bearer KEY" http://192.0.2.1/api/ddns/status

# List DDNS keys
curl -H "Authorization: Bearer KEY" http://192.0.2.1/api/ddns/keys

# Check dhcpd UPDATE log
sudo journalctl -u isc-dhcp-server | grep -i "ddns\|update"

# Check DomU DNS logs for UPDATE arrival
sudo journalctl -u domudns | grep -i "ddns"
```

### dhcpd reports "expected a TSIG or SIG(0)"

This was a known bug in DomU DNS (fixed 2026-03-07): the server processed the UPDATE
successfully (A record was created) but did not sign the response with TSIG. dhcpd and
nsupdate treated the unsigned response as a failure. Fixed in current version — responses
are now properly TSIG-signed.

---

