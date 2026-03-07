# Changelog

All notable changes to DomU DNS will be documented in this file.

## [v.1.1]

### 2026-03-07

#### Added
- **RFC 2136 DDNS fully operational** — ISC dhcpd integration end-to-end working. DNS records are created/updated automatically from DHCP leases via TSIG-authenticated RFC 2136 UPDATE messages.
- **DDNS runtime statistics + dashboard** (`internal/dnsserver/update.go`, `internal/caddy/api/ddns.go`, `dashboard/`): `DDNSStats` struct tracks total updates, failures, last error and rejection reason. `GET /api/ddns/status` exposes these stats. Dashboard shows a 4-card stats grid with contextual diagnosis banners (NOTZONE, NOTAUTH) and a dhcpd config guide (pre-filled `dhcpd.conf` snippet with key name and algorithm).

#### Fixed
- **DDNS UPDATE packets rejected with NOTIMP** (`internal/dnsserver/server.go`): miekg/dns `DefaultMsgAcceptFunc` rejects `OpcodeUpdate` (5) before the handler is called. Fixed by setting a custom `ddnsMsgAcceptFunc` on all server instances (UDP, TCP, DoT).
- **TSIG key lookup failing silently** (`internal/dnsserver/update.go`): `UpdateKeys()` and `GetSecrets()` now add trailing dots to key names in `TsigSecret`. miekg looks up keys as FQDNs — without the trailing dot the lookup silently failed, causing every UPDATE to be rejected with NOTAUTH.
- **TSIG signature missing from responses** (`internal/dnsserver/update.go`): `respond()` now calls `resp.SetTsig()` before `WriteMsg()`. miekg only signs responses when the response message already contains a TSIG RR — without this, dhcpd reported `expected a TSIG or SIG(0)` and treated successful updates as failures.
- **Duplicate records on dhcpd retries** (`internal/dnsserver/update.go`): `applyUpdate` for ClassINET now uses upsert semantics — existing records with the same name+type are deleted before inserting the new one. Previously, dhcpd retries created duplicate A/TXT records.

#### Tests
- `TestDDNS_TsigSecret_TrailingDot`: trailing-dot regression test for `UpdateKeys()` / `GetSecrets()`.
- `TestDDNS_Stats_SuccessfulUpdate`, `TestDDNS_Stats_NotZoneRejection`, `TestDDNS_Stats_NotAuthRejection`, `TestDDNS_Stats_AccumulatesAcrossMultipleCalls`: DDNS stats unit tests.
