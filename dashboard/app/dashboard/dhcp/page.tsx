'use client'

import { useEffect, useState, useCallback } from 'react'
import { Topbar } from '@/components/layout/Topbar'
import { dhcpLeaseSync, type DHCPLease, type DHCPSyncStatus } from '@/lib/api'

function fmtTime(ts: string): string {
  if (!ts || ts === '0001-01-01T00:00:00Z') return '—'
  const d = new Date(ts)
  return d.toLocaleString('de-DE', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

function StatusCard({ status }: { status: DHCPSyncStatus | null }) {
  if (!status) return null

  const sourceLabels: Record<string, string> = {
    dnsmasq: 'dnsmasq',
    dhcpd: 'ISC dhcpd',
    fritzbox: 'FritzBox (TR-064)',
  }

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
      <div className="bg-[#100c1e] neon-card rounded-xl p-4">
        <div className="text-xs text-[#6b5f8a] mb-1">Quelle</div>
        <div className="text-lg font-semibold text-[#f0eeff]">
          {sourceLabels[status.source] ?? status.source}
        </div>
        <div className="text-xs text-[#6b5f8a] mt-0.5">
          {status.enabled ? 'Aktiv' : 'Deaktiviert'}
        </div>
      </div>
      <div className="bg-[#100c1e] neon-card rounded-xl p-4">
        <div className="text-xs text-[#6b5f8a] mb-1">Leases</div>
        <div className="text-lg font-semibold text-[#f0eeff]">
          {status.lease_count.toLocaleString('de-DE')}
        </div>
        <div className="text-xs text-[#6b5f8a] mt-0.5">
          {status.record_count.toLocaleString('de-DE')} DNS-Records
        </div>
      </div>
      <div className="bg-[#100c1e] neon-card rounded-xl p-4">
        <div className="text-xs text-[#6b5f8a] mb-1">Letzte Synchronisierung</div>
        <div className="text-sm font-semibold text-[#f0eeff]">
          {fmtTime(status.last_sync)}
        </div>
      </div>
      <div className="bg-[#100c1e] neon-card rounded-xl p-4">
        <div className="text-xs text-[#6b5f8a] mb-1">Status</div>
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

export default function DHCPPage() {
  const [leases, setLeases] = useState<DHCPLease[]>([])
  const [status, setStatus] = useState<DHCPSyncStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')

  const fetchData = useCallback(async () => {
    try {
      const [leasesRes, statusRes] = await Promise.all([
        dhcpLeaseSync.getLeases(),
        dhcpLeaseSync.getStatus(),
      ])
      setLeases(leasesRes.data ?? [])
      setStatus(statusRes.data ?? null)
      setError('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Fehler beim Laden')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
    const id = setInterval(fetchData, 30000)
    return () => clearInterval(id)
  }, [fetchData])

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
    <div className="flex flex-col min-h-screen bg-[#080612]">
      <Topbar title="DHCP-Leases" />
      <main className="flex-1 p-4 lg:p-6 max-w-7xl mx-auto w-full">
        {error && !status && (
          <div className="bg-red-900/30 border border-red-500/30 rounded-xl p-4 mb-6 text-red-400 text-sm">
            {error === 'DHCP-Lease-Sync not configured' ? (
              <div>
                <div className="font-semibold mb-1">DHCP-Lease-Sync nicht konfiguriert</div>
                <div className="text-red-400/70">
                  Aktiviere den DHCP-Lease-Sync in der <code className="bg-red-900/50 px-1 rounded">config.yaml</code> unter <code className="bg-red-900/50 px-1 rounded">dhcp_lease_sync.enabled: true</code>
                </div>
              </div>
            ) : error}
          </div>
        )}

        <StatusCard status={status} />

        {/* Search bar */}
        <div className="mb-4">
          <input
            type="text"
            placeholder="Hostname, IP oder MAC suchen..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full sm:w-80 px-3 py-2 rounded-lg bg-[#100c1e] border border-[#2a1f42] text-[#f0eeff] text-sm placeholder-[#6b5f8a] focus:outline-none focus:border-violet-500/50"
          />
        </div>

        {/* Lease table */}
        <div className="bg-[#100c1e] neon-card rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#2a1f42]">
                  <th className="text-left px-4 py-3 text-xs font-medium text-[#6b5f8a] uppercase tracking-wider">Hostname</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-[#6b5f8a] uppercase tracking-wider">IP-Adresse</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-[#6b5f8a] uppercase tracking-wider hidden sm:table-cell">MAC-Adresse</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-[#6b5f8a] uppercase tracking-wider hidden md:table-cell">Aktualisiert</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#2a1f42]/50">
                {loading ? (
                  <tr>
                    <td colSpan={4} className="px-4 py-8 text-center text-[#6b5f8a]">
                      Lade DHCP-Leases...
                    </td>
                  </tr>
                ) : filtered.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="px-4 py-8 text-center text-[#6b5f8a]">
                      {search ? 'Keine Treffer' : 'Keine DHCP-Leases vorhanden'}
                    </td>
                  </tr>
                ) : (
                  filtered.map((lease) => (
                    <tr key={lease.ip} className="hover:bg-[#2a1f42]/30 transition-colors">
                      <td className="px-4 py-3 font-medium text-[#f0eeff]">{lease.hostname}</td>
                      <td className="px-4 py-3 text-[#9a8cbf] font-mono text-xs">{lease.ip}</td>
                      <td className="px-4 py-3 text-[#9a8cbf] font-mono text-xs hidden sm:table-cell">{lease.mac}</td>
                      <td className="px-4 py-3 text-[#6b5f8a] text-xs hidden md:table-cell">{fmtTime(lease.updated_at)}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          {!loading && filtered.length > 0 && (
            <div className="px-4 py-2 border-t border-[#2a1f42] text-xs text-[#6b5f8a]">
              {filtered.length} {filtered.length === 1 ? 'Lease' : 'Leases'}
              {search && filtered.length !== leases.length && ` (von ${leases.length} gesamt)`}
            </div>
          )}
        </div>
      </main>
    </div>
  )
}
