# awesome-selfhosted PR — DomU DNS

## Schritt 1 — Repository forken

Forke: https://github.com/awesome-selfhosted/awesome-selfhosted

## Schritt 2 — Eintrag einfügen

In `README.md` unter dem Abschnitt **DNS** (alphabetisch nach D, nach "Blocky", vor "CoreDNS"):

```markdown
- [DomU DNS](https://domudns.net) - Lightweight, privacy-first DNS server for Raspberry Pi 3B. Ad blocking with 220,000+ domains, authoritative zones, RFC 2136 DDNS, Split-Horizon, DoH/DoT, Let's Encrypt DNS-01 (Traefik/Certbot/acme.sh), and Master/Slave clustering — single Go binary, ~25 MB RAM. ([Source Code](https://github.com/mw7101/domudns)) `MIT` `Go`
```

## Schritt 3 — `awesome-selfhosted-data` (wird von einem Bot geprüft)

Das Repo nutzt auch eine YAML-Datei unter `./software/`. Neue Einträge brauchen eine Datei:

Datei: `software/domudns.yml`

```yaml
name: DomU DNS
website_url: https://domudns.net
source_code_url: https://github.com/mw7101/domudns
description: >-
  Lightweight, privacy-first DNS server for Raspberry Pi 3B. Ad blocking
  with 220,000+ domains, authoritative zones, RFC 2136 DDNS, Split-Horizon,
  DoH/DoT, Let's Encrypt DNS-01, and Master/Slave clustering — single Go
  binary, ~25 MB RAM. No database required.
licenses:
  - MIT
platforms:
  - Go
tags:
  - dns
  - ad-blocking
  - raspberry-pi
  - homelab
  - ddns
  - authoritative-dns
demo_url: ~
related_software_url: ~
```

## Schritt 4 — PR öffnen

Titel: `Add DomU DNS to DNS section`

PR-Text:
```
DomU DNS is a lightweight open-source DNS server for Raspberry Pi 3B that
fills the gap between Pi-hole (ad blocking only, no authoritative DNS) and
Technitium (full-featured but 200 MB+ RAM on .NET runtime).

Key differentiators vs existing entries:
- ~25 MB RAM (vs 80–200 MB for alternatives)
- Single Go binary, no database, no runtime dependency
- Built-in Let's Encrypt DNS-01 ACME provider
- RFC 2136 DDNS with TSIG (ISC dhcpd / Kea / OPNsense)
- Master/Slave clustering with HMAC-SHA256

MIT licensed, actively maintained.
```
