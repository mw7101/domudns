# Reddit Post — r/selfhosted

## Titel

```
I built a DNS server for Raspberry Pi 3B because Pi-hole + Unbound + BIND9 was three daemons too many
```

## Post-Text

---

For years I ran the classic homelab DNS stack: Pi-hole for ad blocking, Unbound as a recursive resolver, and BIND9 for authoritative zones. Three separate daemons, three configs, three things that could break at 2am.

I wanted something simpler: one binary, all features, low RAM. I didn't find it, so I built it.

**DomU DNS** is a DNS server written in Go, designed for Raspberry Pi 3B. It combines everything into a single ~25 MB binary:

- 🛡️ Ad blocking with 220,000+ domains (O(1) hash lookup, wildcard/regex support)
- 🌐 Full authoritative DNS zones (A, AAAA, MX, CNAME, PTR, TXT, SRV, CAA, NS)
- 🔄 RFC 2136 DDNS — your DHCP server sends updates directly, no scripts
- 🔀 Split-Horizon DNS — internal clients get LAN IPs, external get public IPs
- 🔗 Master/Slave cluster — two Pis, HMAC-SHA256 sync, automatic failover
- 🔐 Let's Encrypt DNS-01 built-in — Traefik httpreq, Certbot plugin, acme.sh/Proxmox
- ⚡ LRU cache with warmup — resolves your top-N domains at startup
- 📊 Next.js dashboard — zones, query log, stats, cluster status

**RAM comparison on Raspberry Pi 3B:**

| | RAM |
|---|---|
| DomU DNS | ~25 MB |
| Pi-hole v6 | 80–160 MB |
| AdGuard Home | 50–130 MB |
| Technitium | 200 MB+ |

The whole thing is a single binary. No database, no Docker required — just copy it, write a YAML config, and run it as a systemd service. First-time setup is a web wizard.

I've been running this on two Raspberry Pi 3Bs (Master/Slave) for several months. It handles ~2,000 queries/day, blocks about 30% of them, and serves local zones for all my containers and VMs.

**Links:**
- Website + docs: https://domudns.net
- GitHub: https://github.com/mw7101/domudns
- Quick Start: https://domudns.net/docs/quickstart.html

Happy to answer questions. Still early days — feedback on features, docs, and rough edges very welcome.

---

## Flair

`Show and Tell`

## Crosspost-Kandidaten (nach r/selfhosted)

- r/homelab — gleicher Post, Fokus auf den HA-Cluster + Proxmox/DDNS-Integration
- r/raspberry_pi — Fokus auf RAM-Effizienz und den Pi 3B als vollwertigen DNS-Server
- r/pihole — Vorsichtig: Framing als "Alternative mit mehr Features", nicht als Kritik
