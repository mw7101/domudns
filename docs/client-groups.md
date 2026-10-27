# Client-Gruppen-Policies

Per-client-group blocklist category activation. Assign different IP ranges (e.g. a children's subnet) to groups with different blocklist categories enabled.

## Overview

DomU DNS supports six blocklist categories:

| Category | Typical content |
|----------|----------------|
| `ads` | Advertising networks, ad trackers |
| `malware` | Malware domains, phishing, C2 servers |
| `adult` | Adult content |
| `social` | Social media platforms |
| `gambling` | Online gambling sites |
| `tracking` | Analytics, user tracking |

Each blocklist URL can be tagged with one category. Untagged entries (empty category) are **always active** for all clients.

## How It Works

When a DNS query arrives, DomU DNS resolves the client's active categories:

1. Look up the client IP against configured client groups (first-match-wins)
2. If no group matches → default: `ads` + `malware` active
3. Check the blocklist: uncategorized domains always checked; categorized domains only if their category is in the active list

```
Client 192.168.2.5
    │
    ↓  ClientGroupResolver (first-match-wins)
    ├─ Group "kids":  CIDRs [192.168.2.0/24] → categories: [ads, malware, adult, gambling]
    └─ No match      → DefaultCategories: [ads, malware]

Active categories → BlocklistManager.IsBlocked(domain, activeCats)
    ├─ Uncategorized domain → always checked
    └─ Category "adult" domain → checked only if "adult" in activeCats
```

## Configuration

Client groups are managed via the API or the Dashboard (Settings → Client-Gruppen).

### API

**Get current groups:**
```bash
curl http://dns1.example.com/api/client-groups \
  -H "Authorization: Bearer YOUR_KEY"
```

**Set groups (full replace):**
```bash
curl -X PUT http://dns1.example.com/api/client-groups \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '[
    {
      "name": "kids",
      "cidrs": ["192.168.2.0/24"],
      "categories": ["ads", "malware", "adult", "gambling"]
    },
    {
      "name": "strict",
      "cidrs": ["192.168.3.0/24"],
      "categories": ["ads", "malware", "adult", "social", "gambling", "tracking"]
    }
  ]'
```

**Remove all groups (restore defaults):**
```bash
curl -X PUT http://dns1.example.com/api/client-groups \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '[]'
```

### Dashboard

Navigate to **Settings → Client-Gruppen**:

- Click **+ Gruppe hinzufügen**
- Enter a name (e.g. `kids`)
- Enter CIDRs (comma-separated, e.g. `192.168.2.0/24`)
- Check the desired categories
- Click **Speichern**

## Blocklist URL Categories

When adding a blocklist URL, assign a category so it only activates for groups that have that category enabled:

```bash
curl -X POST http://dns1.example.com/api/blocklist/urls \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/adult-domains.txt",
    "category": "adult",
    "enabled": true
  }'
```

URLs without a category are **always active** (uncategorized). Use this for base security lists (malware, phishing) that should apply to all clients.

## Example Setup

### Family Network

```
Subnet           Group     Active categories
192.168.1.0/24   (none)    ads + malware (default)
192.168.2.0/24   kids      ads + malware + adult + gambling
```

Steps:
1. Tag base security URLs as `malware` or `ads` (or leave untagged for all-clients)
2. Tag adult/gambling lists as `adult` and `gambling`
3. Create group "kids" for 192.168.2.0/24 with `["ads","malware","adult","gambling"]`
4. Clients in 192.168.1.0/24 use default policy (ads + malware only)

## Cluster Sync

Client group configuration is automatically propagated to all slave nodes via the `EventClientGroups` sync event. No manual action required.

## Notes and Limitations (V1)

- **Wildcard and regex patterns** in the blocklist are always uncategorized — they apply to all clients regardless of group.
- **First-match-wins**: if a client IP matches multiple groups, the first group in the list wins.
- **No per-record categories**: record-level blocklist entries (manually added domains) are always uncategorized.
- Groups are stored in `client_groups.json` in the data directory.
