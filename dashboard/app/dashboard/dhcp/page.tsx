'use client'

import { useEffect, useState, useCallback } from 'react'
import { Topbar } from '@/components/layout/Topbar'
import { ddns, dhcpLeaseSync, type TSIGKey, type TSIGKeyCreateResponse, type DDNSStatus, type DHCPLease, type DHCPSyncStatus } from '@/lib/api'

// ─── Hilfsfunktion ───────────────────────────────────────────────────────────

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text).catch(() => {})
}

function fmtTime(ts: string): string {
  if (!ts || ts === '0001-01-01T00:00:00Z') return '—'
  const d = new Date(ts)
  return d.toLocaleString('de-DE', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

// ─── RFC 2136 DDNS-Sektion ────────────────────────────────────────────────────

function DDNSStatusCards({ status, keys }: { status: DDNSStatus | null; keys: TSIGKey[] }) {
  const hasFailures = (status?.total_failed ?? 0) > 0
  const hasSuccess = (status?.total_updates ?? 0) > 0
  const noKeys = (status?.key_count ?? 0) === 0

  return (
    <>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
        <div className="bg-[var(--surface-2)] neon-card rounded-xl p-4">
          <div className="text-xs text-[var(--muted)] mb-1">TSIG-Keys</div>
          <div className={`text-2xl font-semibold ${noKeys ? 'text-yellow-400' : 'text-[var(--text)]'}`}>
            {status?.key_count ?? '—'}
          </div>
          {noKeys && <div className="text-xs text-yellow-400/70 mt-0.5">Kein Key — Updates werden abgelehnt</div>}
        </div>
        <div className="bg-[var(--surface-2)] neon-card rounded-xl p-4">
          <div className="text-xs text-[var(--muted)] mb-1">Erfolgreiche Updates</div>
          <div className="text-2xl font-semibold text-[var(--text)]">
            {status?.total_updates?.toLocaleString('de-DE') ?? '—'}
          </div>
          <div className="text-xs text-[var(--muted)] mt-0.5">
            {status?.last_update_at ? `Zuletzt: ${fmtTime(status.last_update_at)}` : 'Noch keines'}
          </div>
        </div>
        <div className="bg-[var(--surface-2)] neon-card rounded-xl p-4">
          <div className="text-xs text-[var(--muted)] mb-1">Abgelehnte Updates</div>
          <div className={`text-2xl font-semibold ${hasFailures ? 'text-red-400' : 'text-[var(--text)]'}`}>
            {status?.total_failed?.toLocaleString('de-DE') ?? '—'}
          </div>
          <div className="text-xs text-[var(--muted)] mt-0.5">
            {status?.last_rejected_at ? `Zuletzt: ${fmtTime(status.last_rejected_at)}` : 'Keine'}
          </div>
        </div>
        <div className="bg-[var(--surface-2)] neon-card rounded-xl p-4">
          <div className="text-xs text-[var(--muted)] mb-1">Status</div>
          {hasFailures && !hasSuccess ? (
            <div className="text-sm font-semibold text-red-400">Fehler</div>
          ) : hasSuccess ? (
            <div className="text-lg font-semibold text-green-400">OK</div>
          ) : (
            <div className="text-sm font-semibold text-[var(--muted)]">Kein Traffic</div>
          )}
        </div>
      </div>

      {/* Diagnose-Banner bei Ablehnungen */}
      {hasFailures && status?.last_rejected_reason && (
        <div className="mb-4 p-3 bg-red-900/20 border border-red-500/30 rounded-lg">
          <div className="text-xs font-semibold text-red-400 mb-1">Letzter Ablehnungsgrund</div>
          <div className="font-mono text-xs text-red-300">{status.last_rejected_reason}</div>
          <div className="text-xs text-[var(--muted)] mt-1">{fmtTime(status.last_rejected_at)}</div>
          {status.last_rejected_reason.startsWith('NOTZONE') && (
            <div className="mt-2 text-xs text-yellow-400/80">
              Die Zone existiert nicht in DomU DNS. Lege sie unter <strong>Zonen</strong> an, bevor der DHCP-Server Updates senden kann.
            </div>
          )}
          {status.last_rejected_reason.startsWith('NOTAUTH') && (
            <div className="mt-2 text-xs text-yellow-400/80">
              TSIG-Verifikation fehlgeschlagen. Prüfe ob Key-Name, Algorithmus und Secret in dhcpd.conf und DomU DNS übereinstimmen.
            </div>
          )}
        </div>
      )}

      {/* Hinweis wenn noch keine Updates ankamen */}
      {!hasSuccess && !hasFailures && !noKeys && (
        <div className="mb-4 p-3 bg-[var(--surface-2)] border border-[var(--border)] rounded-lg text-xs text-[var(--muted)]">
          Noch keine RFC 2136 Updates empfangen. Stelle sicher dass der DHCP-Server auf Port 53 dieser Adresse sendet
          und die Zielzone in DomU DNS existiert.
        </div>
      )}

      {/* Konfigurationsanleitung wenn noch kein Traffic */}
      {!hasSuccess && !hasFailures && !noKeys && (
        <DHCPDConfigGuide keys={keys} />
      )}
    </>
  )
}

function TSIGKeyTable({
  keys,
  onDelete,
}: {
  keys: TSIGKey[]
  onDelete: (name: string) => void
}) {
  return (
    <div className="bg-[var(--surface-2)] neon-card rounded-xl overflow-hidden mb-4">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[var(--border)]">
              <th className="text-left px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Name</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider hidden sm:table-cell">Algorithmus</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider hidden md:table-cell">Erstellt</th>
              <th className="px-4 py-3" />
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--border)]/50">
            {keys.length === 0 ? (
              <tr>
                <td colSpan={4} className="px-4 py-6 text-center text-[var(--muted)] text-sm">
                  Keine TSIG-Keys konfiguriert
                </td>
              </tr>
            ) : (
              keys.map((k) => (
                <tr key={k.name} className="hover:bg-[var(--surface-3)]/50 transition-colors">
                  <td className="px-4 py-3 font-medium text-[var(--text)] font-mono text-xs">{k.name}</td>
                  <td className="px-4 py-3 text-[var(--muted-2)] text-xs hidden sm:table-cell">{k.algorithm}</td>
                  <td className="px-4 py-3 text-[var(--muted)] text-xs hidden md:table-cell">{fmtTime(k.created_at)}</td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => onDelete(k.name)}
                      className="text-xs text-red-400 hover:text-red-300 transition-colors px-2 py-1 rounded hover:bg-red-900/20"
                    >
                      Löschen
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function CreateKeyForm({
  onCreate,
}: {
  onCreate: (name: string, algorithm: string) => Promise<string | null>
}) {
  const [name, setName] = useState('')
  const [algorithm, setAlgorithm] = useState('hmac-sha256')
  const [secret, setSecret] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim()) return
    setLoading(true)
    setError('')
    try {
      const s = await onCreate(name.trim(), algorithm)
      setSecret(s)
      setName('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Fehler beim Erstellen')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="bg-[var(--surface-2)] neon-card rounded-xl p-4">
      <div className="text-sm font-medium text-[var(--muted-2)] mb-3">Neuen TSIG-Key erstellen</div>

      {secret && (
        <div className="mb-4 p-3 bg-yellow-900/20 border border-yellow-500/30 rounded-lg">
          <div className="text-xs font-semibold text-yellow-400 mb-1">
            Secret — wird nur einmalig angezeigt!
          </div>
          <div className="font-mono text-xs text-yellow-300 break-all select-all bg-yellow-900/20 rounded p-2">
            {secret}
          </div>
          <button
            onClick={() => { navigator.clipboard.writeText(secret); setSecret(null) }}
            className="mt-2 text-xs text-yellow-400 hover:text-yellow-300 underline"
          >
            Kopieren &amp; schließen
          </button>
        </div>
      )}

      {error && (
        <div className="mb-3 text-xs text-red-400">{error}</div>
      )}

      <form onSubmit={handleSubmit} className="flex flex-wrap gap-2 items-end">
        <div className="flex-1 min-w-40">
          <label className="block text-xs text-[var(--muted)] mb-1">Name</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="z.B. dhcpd-key"
            className="w-full px-3 py-2 rounded-lg bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm placeholder-[#5A5A6E] focus:outline-none focus:border-amber-500/30"
          />
        </div>
        <div>
          <label className="block text-xs text-[var(--muted)] mb-1">Algorithmus</label>
          <select
            value={algorithm}
            onChange={(e) => setAlgorithm(e.target.value)}
            className="px-3 py-2 rounded-lg bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500/30"
          >
            <option value="hmac-sha256">HMAC-SHA256</option>
            <option value="hmac-sha512">HMAC-SHA512</option>
            <option value="hmac-sha1">HMAC-SHA1</option>
          </select>
        </div>
        <button
          type="submit"
          disabled={loading || !name.trim()}
          className="px-4 py-2 rounded-lg bg-amber-500 hover:bg-amber-500 disabled:opacity-40 text-white text-sm font-medium transition-colors"
        >
          {loading ? 'Erstelle…' : 'Erstellen'}
        </button>
      </form>
    </div>
  )
}

// ─── dhcpd Konfigurationsanleitung ───────────────────────────────────────────

function DHCPDConfigGuide({ keys }: { keys: TSIGKey[] }) {
  const [zone, setZone] = useState('home.example.local')
  const [copied, setCopied] = useState(false)
  const firstKey = keys[0]
  const keyName = firstKey?.name ?? 'dhcp-key'
  const algo = firstKey?.algorithm ?? 'hmac-sha256'

  const serverHost = typeof window !== 'undefined' ? window.location.hostname : '<DomU-DNS-IP>'

  const globalSnippet =
`# /etc/dhcp/dhcpd.conf — Globale DDNS-Einstellungen (am Dateianfang)
ddns-update-style interim;
ddns-updates on;
update-static-leases on;
ignore client-updates;`

  const keySnippet =
`# TSIG-Key (Secret wurde beim Erstellen angezeigt)
key "${keyName}" {
    algorithm ${algo};
    secret "HIER-DEN-BASE64-SECRET-EINTRAGEN";
}`

  const zoneSnippet =
`# Forward-Zone
zone ${zone}. {
    primary ${serverHost};
    key "${keyName}";
}

# Reverse-Zone (optional, für PTR-Records)
# zone 100.168.192.in-addr.arpa. {
#     primary ${serverHost};
#     key "${keyName}";
# }`

  const subnetSnippet =
`# Im subnet-Block ergänzen:
ddns-domainname "${zone}.";
ddns-rev-domainname "in-addr.arpa.";`

  const fullSnippet = [globalSnippet, '', keySnippet, '', zoneSnippet, '', subnetSnippet].join('\n')

  const handleCopy = () => {
    copyToClipboard(fullSnippet)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="mb-4 bg-[var(--surface-2)] neon-card rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="text-sm font-medium text-[var(--muted-2)]">dhcpd Konfigurationsanleitung</div>
        <button
          onClick={handleCopy}
          className="text-xs text-amber-400 hover:text-amber-400 transition-colors px-2 py-1 rounded hover:bg-amber-500/10"
        >
          {copied ? 'Kopiert!' : 'Alles kopieren'}
        </button>
      </div>

      <div className="mb-3">
        <label className="block text-xs text-[var(--muted)] mb-1">Zonenname (für Snippet)</label>
        <input
          type="text"
          value={zone}
          onChange={(e) => setZone(e.target.value)}
          placeholder="z.B. home.example.local"
          className="w-full sm:w-72 px-3 py-1.5 rounded-lg bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-xs placeholder-[#5A5A6E] focus:outline-none focus:border-amber-500/30"
        />
      </div>

      <div className="space-y-2 text-xs">
        <div className="p-1 text-[var(--muted)]">
          1. Globale Einstellungen an den Anfang von <code className="bg-[var(--border)] px-1 rounded">/etc/dhcp/dhcpd.conf</code> einfügen:
        </div>
        <pre className="bg-[var(--surface)] rounded-lg p-3 overflow-x-auto text-[var(--muted-2)] font-mono leading-relaxed text-[11px]">{globalSnippet}</pre>

        <div className="p-1 text-[var(--muted)]">2. TSIG-Key-Block einfügen (Secret aus DomU DNS beim Erstellen des Keys):</div>
        <pre className="bg-[var(--surface)] rounded-lg p-3 overflow-x-auto text-[var(--muted-2)] font-mono leading-relaxed text-[11px]">{keySnippet}</pre>

        <div className="p-1 text-[var(--muted)]">3. Zone-Block einfügen:</div>
        <pre className="bg-[var(--surface)] rounded-lg p-3 overflow-x-auto text-[var(--muted-2)] font-mono leading-relaxed text-[11px]">{zoneSnippet}</pre>

        <div className="p-1 text-[var(--muted)]">4. Im <code className="bg-[var(--border)] px-1 rounded">subnet</code>-Block ergänzen:</div>
        <pre className="bg-[var(--surface)] rounded-lg p-3 overflow-x-auto text-[var(--muted-2)] font-mono leading-relaxed text-[11px]">{subnetSnippet}</pre>

        <div className="p-2 bg-yellow-900/20 border border-yellow-500/20 rounded-lg text-yellow-400/80">
          Nach Änderungen: <code className="bg-[var(--border)] px-1 rounded">sudo systemctl restart isc-dhcp-server</code>
          {' '}— dhcpd sendet dann beim nächsten DHCPACK automatisch ein RFC 2136 UPDATE.
        </div>
      </div>
    </div>
  )
}

// ─── File-basierter DHCP-Sync ─────────────────────────────────────────────────

function DHCPStatusCard({ status }: { status: DHCPSyncStatus }) {
  const sourceLabels: Record<string, string> = {
    dnsmasq: 'dnsmasq',
    dhcpd: 'ISC dhcpd',
    fritzbox: 'FritzBox (TR-064)',
  }

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
      <div className="bg-[var(--surface-2)] neon-card rounded-xl p-4">
        <div className="text-xs text-[var(--muted)] mb-1">Quelle</div>
        <div className="text-lg font-semibold text-[var(--text)]">
          {sourceLabels[status.source] ?? status.source}
        </div>
        <div className="text-xs text-[var(--muted)] mt-0.5">
          {status.enabled ? 'Aktiv' : 'Deaktiviert'}
        </div>
      </div>
      <div className="bg-[var(--surface-2)] neon-card rounded-xl p-4">
        <div className="text-xs text-[var(--muted)] mb-1">Leases</div>
        <div className="text-lg font-semibold text-[var(--text)]">
          {status.lease_count.toLocaleString('de-DE')}
        </div>
        <div className="text-xs text-[var(--muted)] mt-0.5">
          {status.record_count.toLocaleString('de-DE')} DNS-Records
        </div>
      </div>
      <div className="bg-[var(--surface-2)] neon-card rounded-xl p-4">
        <div className="text-xs text-[var(--muted)] mb-1">Letzte Synchronisierung</div>
        <div className="text-sm font-semibold text-[var(--text)]">
          {fmtTime(status.last_sync)}
        </div>
      </div>
      <div className="bg-[var(--surface-2)] neon-card rounded-xl p-4">
        <div className="text-xs text-[var(--muted)] mb-1">Status</div>
        {status.last_error ? (
          <div className="text-sm font-semibold text-red-400 truncate" title={status.last_error}>
            {status.last_error}
          </div>
        ) : (
          <div className="text-lg font-semibold text-green-400">OK</div>
        )}
      </div>
    </div>
  )
}

// ─── Hauptseite ───────────────────────────────────────────────────────────────

export default function DHCPPage() {
  const [ddnsStatus, setDdnsStatus] = useState<DDNSStatus | null>(null)
  const [keys, setKeys] = useState<TSIGKey[]>([])
  const [ddnsError, setDdnsError] = useState('')

  const [leases, setLeases] = useState<DHCPLease[]>([])
  const [dhcpStatus, setDhcpStatus] = useState<DHCPSyncStatus | null>(null)
  const [dhcpEnabled, setDhcpEnabled] = useState(false)
  const [dhcpLoading, setDhcpLoading] = useState(true)
  const [search, setSearch] = useState('')

  const fetchDDNS = useCallback(async () => {
    try {
      const [statusRes, keysRes] = await Promise.all([
        ddns.getStatus(),
        ddns.listKeys(),
      ])
      setDdnsStatus(statusRes.data ?? null)
      setKeys(keysRes.data ?? [])
      setDdnsError('')
    } catch (err) {
      setDdnsError(err instanceof Error ? err.message : 'Fehler beim Laden')
    }
  }, [])

  const fetchDHCP = useCallback(async () => {
    try {
      const [leasesRes, statusRes] = await Promise.all([
        dhcpLeaseSync.getLeases(),
        dhcpLeaseSync.getStatus(),
      ])
      setLeases(leasesRes.data ?? [])
      setDhcpStatus(statusRes.data ?? null)
      setDhcpEnabled(true)
    } catch {
      setDhcpEnabled(false)
    } finally {
      setDhcpLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchDDNS()
    fetchDHCP()
    const id = setInterval(() => { fetchDDNS(); fetchDHCP() }, 30000)
    return () => clearInterval(id)
  }, [fetchDDNS, fetchDHCP])

  const handleCreateKey = async (name: string, algorithm: string): Promise<string | null> => {
    const res = await ddns.createKey({ name, algorithm })
    const created = res.data as TSIGKeyCreateResponse
    await fetchDDNS()
    return created.secret ?? null
  }

  const handleDeleteKey = async (name: string) => {
    await ddns.deleteKey(name)
    await fetchDDNS()
  }

  const filtered = leases.filter((l) => {
    if (!search) return true
    const q = search.toLowerCase()
    return (
      l.hostname.toLowerCase().includes(q) ||
      l.ip.includes(q) ||
      l.mac.toLowerCase().includes(q)
    )
  })

  return (
    <div className="flex flex-col min-h-screen bg-[var(--surface)]">
      <Topbar title="DDNS / DHCP" />
      <main className="flex-1 p-4 lg:p-6 max-w-7xl mx-auto w-full space-y-8">

        {/* ── Sektion 1: RFC 2136 DDNS ── */}
        <section>
          <h2 className="text-base font-semibold text-[var(--text)] mb-4">RFC 2136 DDNS</h2>

          {ddnsError && (
            <div className="mb-4 p-3 bg-red-900/20 border border-red-500/30 rounded-lg text-red-400 text-sm">
              {ddnsError}
            </div>
          )}

          <DDNSStatusCards status={ddnsStatus} keys={keys} />

          <TSIGKeyTable keys={keys} onDelete={handleDeleteKey} />

          <CreateKeyForm onCreate={handleCreateKey} />
        </section>

        {/* ── Sektion 2: File-basierter DHCP-Lease-Sync ── */}
        <section>
          <h2 className="text-base font-semibold text-[var(--text)] mb-4">DHCP-Lease-Sync</h2>

          {!dhcpLoading && !dhcpEnabled ? (
            <div className="bg-[var(--surface-2)] neon-card rounded-xl p-6 text-sm text-[var(--muted)]">
              <div className="font-semibold mb-1 text-[var(--muted-2)]">Nicht konfiguriert</div>
              <div>
                Für File-basiertes Lease-Polling aktiviere{' '}
                <code className="bg-[var(--border)] px-1 rounded">dhcp_lease_sync.enabled: true</code>{' '}
                in der <code className="bg-[var(--border)] px-1 rounded">config.yaml</code>.
                Für RFC 2136 verwende den TSIG-Key-Bereich oben.
              </div>
            </div>
          ) : dhcpStatus ? (
            <>
              <DHCPStatusCard status={dhcpStatus} />

              <div className="mb-4">
                <input
                  type="text"
                  placeholder="Hostname, IP oder MAC suchen..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="w-full sm:w-80 px-3 py-2 rounded-lg bg-[var(--surface-2)] border border-[var(--border)] text-[var(--text)] text-sm placeholder-[#5A5A6E] focus:outline-none focus:border-amber-500/30"
                />
              </div>

              <div className="bg-[var(--surface-2)] neon-card rounded-xl overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-[var(--border)]">
                        <th className="text-left px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">Hostname</th>
                        <th className="text-left px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider">IP-Adresse</th>
                        <th className="text-left px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider hidden sm:table-cell">MAC-Adresse</th>
                        <th className="text-left px-4 py-3 text-xs font-medium text-[var(--muted)] uppercase tracking-wider hidden md:table-cell">Aktualisiert</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[var(--border)]/50">
                      {filtered.length === 0 ? (
                        <tr>
                          <td colSpan={4} className="px-4 py-8 text-center text-[var(--muted)]">
                            {search ? 'Keine Treffer' : 'Keine DHCP-Leases vorhanden'}
                          </td>
                        </tr>
                      ) : (
                        filtered.map((lease) => (
                          <tr key={lease.ip} className="hover:bg-[var(--surface-3)]/50 transition-colors">
                            <td className="px-4 py-3 font-medium text-[var(--text)]">{lease.hostname}</td>
                            <td className="px-4 py-3 text-[var(--muted-2)] font-mono text-xs">{lease.ip}</td>
                            <td className="px-4 py-3 text-[var(--muted-2)] font-mono text-xs hidden sm:table-cell">{lease.mac}</td>
                            <td className="px-4 py-3 text-[var(--muted)] text-xs hidden md:table-cell">{fmtTime(lease.updated_at)}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
                {filtered.length > 0 && (
                  <div className="px-4 py-2 border-t border-[var(--border)] text-xs text-[var(--muted)]">
                    {filtered.length} {filtered.length === 1 ? 'Lease' : 'Leases'}
                    {search && filtered.length !== leases.length && ` (von ${leases.length} gesamt)`}
                  </div>
                )}
              </div>
            </>
          ) : null}
        </section>

      </main>
    </div>
  )
}
