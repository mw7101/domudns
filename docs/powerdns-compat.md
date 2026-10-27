# PowerDNS-compatible API

DomU DNS exposes a small, PowerDNS-compatible subset of the [PowerDNS
Authoritative HTTP API](https://doc.powerdns.com/authoritative/http-api/zone.html)
under the canonical `/api/v1/servers/` path, so third-party ACME DNS-01
tooling that only speaks "PowerDNS" — the Proxmox VE **"DNS-01 PowerDNS
API"** plugin and acme.sh's `dns_pdns` hook — can manage records in an
existing DomU DNS zone.

The historical `/api/pdns/v1/servers/` path is retained as a **legacy alias**
and behaves identically; new integrations should use `/api/v1/servers/`.
acme.sh always inserts `/api/v1/` itself, so the `PDNS_Url` value must be the
host only (see [Proxmox VE configuration](#proxmox-ve-configuration)).

This is an **addition**, not a replacement: DomU DNS's own
`/api/acme/dns-01/*` endpoints (used by `dns_domudns`-style integrations)
keep working unchanged.

## Endpoints

| Method | Path                                                    | Purpose                    |
| ------ | -------------------------------------------------------- | --------------------------- |
| GET    | `/api/v1/servers/{server_id}/zones`                       | List zones                  |
| GET    | `/api/v1/servers/{server_id}/zones/{zone_id}`             | Zone detail (grouped RRsets) |
| PATCH  | `/api/v1/servers/{server_id}/zones/{zone_id}`             | Add/replace/delete RRsets   |
| PUT    | `/api/v1/servers/{server_id}/zones/{zone_id}/notify`      | Notify slaves (no-op, `204`) |

The legacy prefix `/api/pdns/v1/servers/{server_id}/zones...` exposes the
same endpoints as an alias and keeps working unchanged.

`{server_id}` is accepted but never inspected — PowerDNS convention allows
any value (`localhost` is the usual placeholder). `{zone_id}` is the zone
name with a trailing dot, e.g. `example.org.`. The `.../notify` endpoint is
accepted as a no-op (`204 No Content`) — DomU DNS's cluster pushes changes
itself — so acme.sh's post-write notify step succeeds instead of failing
validation.

Authentication uses the standard PowerDNS `X-API-Key` header (see
[Authentication](#authentication)). Responses use PowerDNS's own JSON
shapes, not DomU DNS's `{success,data,error}` envelope, since that's what
these clients expect.

## Record type coverage

Only record types DomU DNS actually serves as live DNS answers are
representable: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SRV`, `PTR`, `CAA`,
`DNAME`, and `SOA` (backed by the zone's `soa` field, not a regular record).

DomU DNS's own synthetic record types (`FWD`, `ALIAS`) and types it stores
but never resolves live (`SPF`, `URI`) are:

- **silently omitted** from `GET` zone detail responses (they don't crash
  the request, they just don't appear as an rrset), and
- **rejected with `422`** on `PATCH` if a client tries to write one.

Per-record `"disabled": true` (a PowerDNS feature) is accepted but has no
DomU DNS equivalent — a disabled record entry in a `REPLACE` is simply not
created at all, rather than stored-but-inactive.

## Examples

Replace the assumption below: `$DOMUDNS` is your DomU DNS host, `$APIKEY` a
Named API Key created under Settings → API Keys (Settings → API Keys →
"Create Key" in the dashboard, or `POST /api/auth/api-keys`).

### List zones

```bash
curl -s -H "X-API-Key: $APIKEY" \
  "https://$DOMUDNS/api/v1/servers/localhost/zones"
```

### Read a zone (grouped RRsets)

```bash
curl -s -H "X-API-Key: $APIKEY" \
  "https://$DOMUDNS/api/v1/servers/localhost/zones/example.org."
```

### Set the ACME DNS-01 TXT record (REPLACE)

```bash
curl -s -X PATCH -H "X-API-Key: $APIKEY" -H "Content-Type: application/json" \
  "https://$DOMUDNS/api/v1/servers/localhost/zones/example.org." \
  -d '{
        "rrsets": [{
          "name": "_acme-challenge.example.org.",
          "type": "TXT",
          "ttl": 300,
          "changetype": "REPLACE",
          "records": [{"content": "\"the-acme-challenge-token\"", "disabled": false}]
        }]
      }'
```

A successful `PATCH` returns `204 No Content`. The rrset `name` is the
record's fully-qualified name; it may be the zone apex (`example.org.`) or
several labels below it — e.g. `_acme-challenge.pve-node.example.org.` is
stored as the zone-relative name `_acme-challenge.pve-node`, so ACME DNS-01
also works for hosts below the zone apex. Note: DomU DNS enforces a
300-second minimum TTL on every record (`ttl_override` aside) — a `ttl`
below 300 is **clamped to 300**, it is not rejected, even though PowerDNS
itself allows lower values.

### Clean up the ACME DNS-01 TXT record (DELETE)

```bash
curl -s -X PATCH -H "X-API-Key: $APIKEY" -H "Content-Type: application/json" \
  "https://$DOMUDNS/api/v1/servers/localhost/zones/example.org." \
  -d '{
        "rrsets": [{
          "name": "_acme-challenge.example.org.",
          "type": "TXT",
          "changetype": "DELETE"
        }]
      }'
```

## Proxmox VE configuration

In Proxmox VE's ACME plugin configuration (`Datacenter → ACME → Add →
DNS`), choose **DNS-01 PowerDNS API** and set:

| Field         | Value                                              |
| ------------- | --------------------------------------------------- |
| API URL       | `https://<domudns-host>` — **host only**            |
| Server ID     | `localhost` (any value works, it's ignored)          |
| API Key       | a DomU DNS Named API Key                             |
| Zone          | the zone name as already configured in DomU DNS (e.g. `example.org`) |

The **API URL must be the host only**, without any path. acme.sh's `dns_pdns`
hook always appends `/api/v1/servers/<ServerId>/...` itself, so a value like
`https://<domudns-host>/api/v1` produces a doubled path and fails. DomU DNS
serves the canonical `/api/v1/servers/...` path for exactly this reason.

The zone referenced must already exist in DomU DNS as an authoritative zone
(create it first via the dashboard or `POST /api/zones`) — this API only
manages records inside an existing zone, it does not create zones.

> **Note — `PDNS_Ttl` is optional.** DomU DNS enforces a 300-second minimum
> TTL (`dns.MinRecordTTL`), but the PowerDNS-compat `PATCH` **clamps** a
> requested `ttl` below 300 to 300 instead of rejecting it (`422`), so the
> record is always written. acme.sh's default `PDNS_Ttl` of 60 therefore
> yields a 300-second record — there is no need to raise it, though setting
> it to `300` or higher is still fine.

## Operational note: delegation

The ACME CA validates `_acme-challenge.<domain>` by querying the public DNS
system, not DomU DNS directly. For the TXT record this API writes to
actually be seen by the CA, the zone (or at minimum an NS delegation for
`_acme-challenge.<domain>`) must already resolve to a DomU DNS instance
reachable from the internet. If the domain's authoritative nameservers at
the registrar don't point to DomU DNS, the CA will never see the answer and
the DNS-01 challenge will time out — this is a delegation/DNS-topology
prerequisite, not something this API can fix.
