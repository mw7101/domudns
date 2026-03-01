# Zone Transfer (AXFR/IXFR)

DomU DNS supports DNS zone transfer per RFC 5936 (AXFR) and RFC 1995 (IXFR). This allows external secondary DNS servers (BIND, CoreDNS, nsd, PowerDNS, etc.) to fetch zones directly using the standard DNS protocol.

## Feature Set

- **AXFR** (RFC 5936): Full zone transfer — always available
- **IXFR** (RFC 1995): Incremental transfer — falls back to AXFR (no change history tracking implemented, RFC-conformant)
- **ACL**: Global IP/CIDR whitelist (who may perform zone transfers)
- **Default zones only**: View-specific zones are not transferred (secondary DNS has no view context)
- **TCP only**: AXFR over UDP is rejected with NOTIMP (RFC 5936 §2.2)
- **NOTIFY**: Not implemented (RFC 1996 — out of scope)

## Configuration

In `configs/config.yaml`:

```yaml
dnsserver:
  axfr:
    enabled: true
    allowed_ips:
      - "127.0.0.1/32"       # Loopback
      - "192.168.0.0/16"     # Local network
      - "10.0.0.0/8"         # Private network
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | bool | `false` | Enable zone transfer |
| `allowed_ips` | `[]string` | `[]` | Allowed client IPs/CIDRs. Empty = reject all |

### Live Reload

`allowed_ips` can be changed without a restart:

```bash
curl -X PATCH http://localhost/api/config \
  -H "Authorization: Bearer <KEY>" \
  -d '{"dnsserver": {"axfr": {"enabled": true, "allowed_ips": ["192.168.0.0/16"]}}}'
```

## Verification

### Test AXFR

```bash
# Full zone transfer
dig axfr example.com @127.0.0.1

# With port specification
dig -p 53 axfr example.com @127.0.0.1
```

**Expected output:**
```
example.com.    3600 IN SOA  ns1.example.com. hostmaster.example.com. 2026022600 3600 1800 604800 300
example.com.    300  IN A    1.2.3.4
www.example.com. 300 IN A    1.2.3.5
example.com.    3600 IN SOA  ns1.example.com. hostmaster.example.com. 2026022600 3600 1800 604800 300
```

### Test IXFR (fallback to AXFR)

```bash
# IXFR — answered as a full AXFR
dig ixfr=2026020100 example.com @127.0.0.1
```

### ACL test (rejection)

```bash
# allowed_ips without local IP → REFUSED
dig axfr example.com @127.0.0.1
# Expected: REFUSED (Rcode: 5)
```

### NXDOMAIN for unknown zone

```bash
dig axfr unknown.example.com @127.0.0.1
# Expected: NOTAUTH (Rcode: 9)
```

## Integration with BIND as Secondary

Example `named.conf` for BIND as secondary:

```
zone "example.com" {
    type slave;
    masters { 192.0.2.1; };  # DomU DNS master IP
    file "/var/cache/bind/example.com.db";
};
```

## Security Notes

- **Always set ACL**: `allowed_ips` empty = all requests rejected (secure default configuration)
- **Only add secondary servers**: Not all LAN clients, only dedicated DNS servers
- **Prefer CIDR**: `192.168.1.10/32` instead of `192.168.1.10`
- Zone transfer transmits all zone contents — only allow trusted servers
- The internal cluster sync (HTTP push) continues to run unchanged

## Architecture

The `AXFRHandler` (`internal/dnsserver/axfr.go`) is inserted at phase 2a.5 of the DNS pipeline:

```
1. Extract client IP
2. Blocklist check
2a.  RFC 2136 UPDATE (DDNS)
2a.5 AXFR/IXFR zone transfer  ← here
3. Authoritative zone
...
```

The handler directly uses the `ZoneManager` (`internal/dnsserver/zones.go`) and the existing `recordToRR()` function for record conversion.
