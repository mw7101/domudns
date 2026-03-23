# Split-Horizon DNS

Split-horizon DNS allows the same domain to return different responses to different clients — depending on the client's network location.

## Use Cases

| Scenario | Client network | Response |
|----------|----------------|---------|
| NAS on home network | 192.168.0.0/16 (internal) | 192.168.1.100 (direct) |
| NAS via internet | external | NXDOMAIN (not reachable) |
| Internal API server | 10.0.0.0/8 (internal) | 10.0.5.20 |
| External access to internal server | external | Different hostname / CNAME |
| Apex alias to CDN (per view) | internal / external | ALIAS `@` → different CDN per view |

## Concept

- **Views**: Named groups with associated CIDR ranges.
- **View zones**: Zones assigned to a view (`view: "internal"`).
- **Default zones**: Zones without a view (`view: ""`), globally visible.
- **Lookup order**: View zone (if client view matches) → default zone → no match.
- **Backward compatible**: Existing zones without a view behave unchanged.

## Configuration

### config.yaml

```yaml
dnsserver:
  split_horizon:
    enabled: true
    views:
      - name: internal
        subnets:
          - "192.168.0.0/16"
          - "10.0.0.0/8"
      # Optional: catch-all view (empty subnets list)
      # - name: external
      #   subnets: []
```

### REST API (Live Reload)

```bash
# Get current state
curl http://localhost/api/split-horizon \
  -H "Authorization: Bearer KEY"

# Update configuration (no restart required)
curl -X PUT http://localhost/api/split-horizon \
  -H "Authorization: Bearer KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "views": [
      {"name": "internal", "subnets": ["192.168.0.0/16", "10.0.0.0/8"]}
    ]
  }'
```

## Zone Management

### Create a view zone

```bash
# Create zone for view "internal"
curl -X POST http://localhost/api/zones \
  -H "Authorization: Bearer KEY" \
  -H "Content-Type: application/json" \
  -d '{"domain": "nas.home", "view": "internal", "ttl": 300}'

# Add record to view zone (compound key: domain@view)
curl -X POST "http://localhost/api/zones/nas.home/records?view=internal" \
  -H "Authorization: Bearer KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "@", "type": "A", "ttl": 300, "value": "192.168.1.100"}'

# Default zone for external clients
curl -X POST http://localhost/api/zones \
  -H "Authorization: Bearer KEY" \
  -H "Content-Type: application/json" \
  -d '{"domain": "nas.home", "ttl": 300}'

# A record in default zone (or leave empty for NXDOMAIN for externals)
curl -X POST "http://localhost/api/zones/nas.home/records" \
  -H "Authorization: Bearer KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "@", "type": "A", "ttl": 300, "value": "203.0.113.10"}'
```

### ALIAS at apex in view zones

ALIAS records work at the zone apex — useful when different views should resolve `@` to different targets:

```bash
# Internal view: apex → internal CDN/server
curl -X POST "http://localhost/api/zones/example.com/records?view=internal" \
  -H "Authorization: Bearer KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "@", "type": "ALIAS", "ttl": 300, "value": "internal-lb.example.com"}'

# Default (external) view: apex → public CDN
curl -X POST "http://localhost/api/zones/example.com/records" \
  -H "Authorization: Bearer KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "@", "type": "ALIAS", "ttl": 300, "value": "cdn.cloudflare.com"}'
```

ALIAS resolution uses the same upstream forwarder as the view's DNS context.

### Read and delete a view zone

```bash
# Read view zone
curl "http://localhost/api/zones/nas.home?view=internal" \
  -H "Authorization: Bearer KEY"

# Delete view zone (default zone remains)
curl -X DELETE "http://localhost/api/zones/nas.home?view=internal" \
  -H "Authorization: Bearer KEY"
```

## File Backend

View zones are stored as `{domain}@{view}.json`:

```
/var/lib/domudns/data/
  nas.home.json           # Default zone
  nas.home@internal.json  # View zone for "internal"
  example.com.json
```

## View Resolution

```
Client IP: 192.168.1.50
→ SplitHorizonResolver.GetView(192.168.1.50)
→ Subnet check: 192.168.0.0/16 ✓
→ View: "internal"

DNS query: nas.home A?
→ ZoneManager.FindZone("internal", "nas.home.")
→ viewZones["nas.home"]["internal"] → view zone found
→ Response: 192.168.1.100
```

```
Client IP: 8.8.8.8
→ SplitHorizonResolver.GetView(8.8.8.8)
→ No subnet match
→ View: "" (no view)

DNS query: nas.home A?
→ ZoneManager.FindZone("", "nas.home.")
→ zones["nas.home"] → default zone found
→ Response: 203.0.113.10
```

## Match Rules

- **First-match-wins**: Views are checked in the configured order.
- **Catch-all**: A view with an empty `subnets` list matches all clients not otherwise assigned.
- **Fallback**: If a client has a view but no view zone exists for it, the default zone is used.
- **Split-horizon disabled**: `clientView` is always `""` → only default zones are queried (identical behavior to before the feature).

## Dashboard

In the dashboard under **Settings → Split-Horizon DNS**:
- Toggle to enable/disable
- Manage views with name and subnets
- Changes take effect immediately (no restart)

Under **Zones**:
- View zones are displayed with a purple badge `internal`
- When creating a zone, an optional view name can be specified

## Cluster Synchronization

View zones are automatically synchronized between master and slave just like default zones:
- `ListZones()` returns all zones (default + view)
- When deleting a view zone, the master propagates an `EventZoneDeleted` event with the compound key `"domain@view"` to all slaves
