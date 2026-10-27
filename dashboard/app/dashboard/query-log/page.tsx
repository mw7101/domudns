'use client'

import { useEffect, useState, useCallback, useRef } from 'react'
import { Topbar } from '@/components/layout/Topbar'
import { queryLog, blocklist, type QueryLogEntry } from '@/lib/api'

// ─── Types ────────────────────────────────────────────────────────────────────

type ResultFilter = '' | 'blocked' | 'cached' | 'authoritative' | 'forwarded' | 'error'

interface Filter {
  client: string
  domain: string
  result: ResultFilter
  qtype: string
  limit: number
}

// ─── Helper Functions ─────────────────────────────────────────────────────────

function resultBadge(result: string) {
  const styles: Record<string, string> = {
    blocked:      'bg-red-500/15 text-red-400 border border-red-500/20',
    cached:       'bg-emerald-500/15 text-emerald-400 border border-emerald-500/20',
    authoritative:'bg-violet-500/15 text-violet-400 border border-violet-500/20',
    forwarded:    'bg-slate-500/15 text-slate-300 border border-slate-500/20',
    error:        'bg-orange-500/15 text-orange-400 border border-orange-500/20',
    allowed:      'bg-green-500/20 text-green-400 border border-green-500/30',
  }
  const labels: Record<string, string> = {
    blocked:       'Blockiert',
    cached:        'Gecacht',
    authoritative: 'Autoritativ',
    forwarded:     'Weitergeleitet',
    error:         'Fehler',
    allowed:       '✓ Freigegeben',
  }
  return (
    <span className={`inline-flex px-1.5 py-0.5 rounded text-[10px] font-medium ${styles[result] ?? 'bg-slate-700 text-slate-300'}`}>
      {labels[result] ?? result}
    </span>
  )
}

function fmtLatency(us: number): string {
  if (us < 1000) return `${us}µs`
  return `${(us / 1000).toFixed(1)}ms`
}

function fmtTime(ts: string): string {
  const d = new Date(ts)
  return d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

// ─── Filter Bar ───────────────────────────────────────────────────────────────

function FilterBar({ filter, onChange }: { filter: Filter; onChange: (f: Filter) => void }) {
  return (
    <div className="flex flex-wrap gap-2">
      <input
        type="text"
        placeholder="Client-IP..."
        value={filter.client}
        onChange={e => onChange({ ...filter, client: e.target.value })}
        className="bg-[#100c1e] border border-[#2a1f42] rounded-lg px-3 py-1.5 text-sm text-[#f0eeff] placeholder-[#6b5f8a] focus:outline-none focus:border-violet-500/50 w-36"
      />
      <input
        type="text"
        placeholder="Domain..."
        value={filter.domain}
        onChange={e => onChange({ ...filter, domain: e.target.value })}
        className="bg-[#100c1e] border border-[#2a1f42] rounded-lg px-3 py-1.5 text-sm text-[#f0eeff] placeholder-[#6b5f8a] focus:outline-none focus:border-violet-500/50 w-44"
      />
      <select
        value={filter.result}
        onChange={e => onChange({ ...filter, result: e.target.value as ResultFilter })}
        className="bg-[#100c1e] border border-[#2a1f42] rounded-lg px-3 py-1.5 text-sm text-[#9a8cbf] focus:outline-none focus:border-violet-500/50"
      >
        <option value="">Alle Ergebnisse</option>
        <option value="blocked">Blockiert</option>
        <option value="forwarded">Weitergeleitet</option>
        <option value="cached">Gecacht</option>
        <option value="authoritative">Autoritativ</option>
        <option value="error">Fehler</option>
      </select>
      <select
        value={filter.qtype}
        onChange={e => onChange({ ...filter, qtype: e.target.value })}
        className="bg-[#100c1e] border border-[#2a1f42] rounded-lg px-3 py-1.5 text-sm text-[#9a8cbf] focus:outline-none focus:border-violet-500/50"
      >
        <option value="">Alle Typen</option>
        {['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'PTR', 'SRV'].map(t => (
          <option key={t} value={t}>{t}</option>
        ))}
      </select>
      <select
        value={filter.limit}
        onChange={e => onChange({ ...filter, limit: Number(e.target.value) })}
        className="bg-[#100c1e] border border-[#2a1f42] rounded-lg px-3 py-1.5 text-sm text-[#9a8cbf] focus:outline-none focus:border-violet-500/50"
      >
        <option value={50}>50 Einträge</option>
        <option value={100}>100 Einträge</option>
        <option value={250}>250 Einträge</option>
        <option value={500}>500 Einträge</option>
      </select>
    </div>
  )
}

// ─── Row Menu ─────────────────────────────────────────────────────────────────

function RowMenu({ entry, onWhitelisted, onError }: { entry: QueryLogEntry; onWhitelisted: (domain: string) => void; onError: (msg: string) => void }) {
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [done, setDone] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  // Click outside closes menu
  useEffect(() => {
    if (!open) return
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open])

  const handleAllow = async () => {
    setLoading(true)
    try {
      // Remove trailing dot (DNS names are in FQDN format with a trailing dot)
      const domain = entry.domain.replace(/\.$/, '')
      await blocklist.addAllowed(domain)
      setDone(true)
      setOpen(false)
      onWhitelisted(entry.domain)
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Unbekannter Fehler'
      onError(`Fehler beim Freigeben: ${msg}`)
      setOpen(false)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(v => !v)}
        className="p-1 rounded text-[#6b5f8a] hover:text-[#9a8cbf] hover:bg-[#2a1f42] transition-colors"
        title="Aktionen"
      >
        <span className="text-base leading-none">⋯</span>
      </button>

      {open && (
        <div className="absolute right-0 top-6 z-50 w-48 bg-[#100c1e] neon-card rounded-xl shadow-xl py-1">
          <button
            onClick={handleAllow}
            disabled={loading || done}
            className="flex items-center gap-2 w-full px-3 py-2 text-xs text-left hover:bg-[#2a1f42] transition-colors disabled:opacity-50"
          >
            {done ? (
              <span className="text-emerald-400">✓ Freigegeben</span>
            ) : loading ? (
              <>
                <span className="inline-block w-3 h-3 border border-current border-t-transparent rounded-full animate-spin" />
                <span className="text-[#9a8cbf]">Wird freigegeben…</span>
              </>
            ) : (
              <>
                <span className="text-emerald-400">✓</span>
                <span className="text-[#f0eeff]">Domain freigeben</span>
              </>
            )}
          </button>
          <div className="px-3 py-1 text-[10px] text-[#6b5f8a] border-t border-[#2a1f42] mt-1 pt-1 truncate">
            {entry.domain}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Log Table ─────────────────────────────────────────────────────────────────

function LogTable({ entries, loading, onWhitelisted, onError }: {
  entries: QueryLogEntry[]
  loading: boolean
  onWhitelisted: (domain: string) => void
  onError: (msg: string) => void
}) {
  if (loading && entries.length === 0) {
    return (
      <div className="flex items-center justify-center py-16 text-[#6b5f8a]">
        <span className="inline-block w-4 h-4 border-2 border-violet-500 border-t-transparent rounded-full animate-spin mr-2" />
        Lade Query-Log...
      </div>
    )
  }

  if (!loading && entries.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-[#6b5f8a]">
        <div className="text-2xl mb-2">◈</div>
        <div className="text-sm">Keine Einträge — Query-Log ist leer oder nicht aktiviert.</div>
        <div className="text-xs mt-1 text-[#2a1f42]">Aktiviere <code className="text-violet-400">system.query_log.enabled: true</code> in der Config.</div>
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-[#2a1f42] text-[#6b5f8a]">
            <th className="text-left py-2 px-3 font-medium">Zeit</th>
            <th className="text-left py-2 px-3 font-medium">Client</th>
            <th className="text-left py-2 px-3 font-medium">Domain</th>
            <th className="text-left py-2 px-3 font-medium">Typ</th>
            <th className="text-left py-2 px-3 font-medium">Ergebnis</th>
            <th className="text-left py-2 px-3 font-medium">Latenz</th>
            <th className="text-left py-2 px-3 font-medium hidden lg:table-cell">Upstream</th>
            <th className="text-left py-2 px-3 font-medium hidden lg:table-cell">Node</th>
            <th className="py-2 px-2" />
          </tr>
        </thead>
        <tbody>
          {entries.map((e, i) => (
            <tr
              key={i}
              className={`border-b border-[#100c1e] hover:bg-[#100c1e]/60 transition-colors group ${
                e.result === 'allowed' ? 'bg-green-500/[0.04]' :
                e.blocked ? 'bg-red-500/[0.03]' : ''
              }`}
            >
              <td className="py-1.5 px-3 text-[#6b5f8a] whitespace-nowrap">{fmtTime(e.ts)}</td>
              <td className="py-1.5 px-3 text-[#9a8cbf] font-mono">{e.client}</td>
              <td className="py-1.5 px-3 font-mono max-w-[200px] truncate" title={e.domain}>
                <span className={
                  e.result === 'allowed' ? 'text-green-400' :
                  e.blocked ? 'text-red-400' : 'text-[#f0eeff]'
                }>{e.domain}</span>
              </td>
              <td className="py-1.5 px-3">
                <span className="text-[#6b5f8a] font-mono">{e.qtype}</span>
              </td>
              <td className="py-1.5 px-3">{resultBadge(e.result)}</td>
              <td className="py-1.5 px-3 text-[#6b5f8a] font-mono">{fmtLatency(e.latency_us)}</td>
              <td className="py-1.5 px-3 text-[#6b5f8a] font-mono hidden lg:table-cell">{e.upstream || '—'}</td>
              <td className="py-1.5 px-3 text-[#6b5f8a] hidden lg:table-cell">{e.node}</td>
              <td className="py-1 px-2">
                {/* Menu visible only for blocked domains; for others visible on hover */}
                <div className={e.blocked ? 'opacity-100' : 'opacity-0 group-hover:opacity-100 transition-opacity'}>
                  <RowMenu entry={e} onWhitelisted={onWhitelisted} onError={onError} />
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ─── Module-level: Whitelisted domains persist across page navigations ────────
// In Next.js this Set is retained during client-side navigation (no page reload needed).
const _whitelistedDomains = new Set<string>()

// ─── Main Page ──────────────────────────────────────────────────────────────

export default function QueryLogPage() {
  const [entries, setEntries] = useState<QueryLogEntry[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [filter, setFilter] = useState<Filter>({ client: '', domain: '', result: '', qtype: '', limit: 100 })
  const [toast, setToast] = useState<{ msg: string; type: 'success' | 'error' } | null>(null)
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const fetchLog = useCallback(async () => {
    try {
      const resp = await queryLog.list({
        client: filter.client || undefined,
        domain: filter.domain || undefined,
        result: filter.result || undefined,
        qtype: filter.qtype || undefined,
        limit: filter.limit,
      })
      const rawEntries = resp.data?.entries ?? []
      // Restore whitelist status for already whitelisted domains
      // (persists across page navigations thanks to module-level Set)
      const enriched = _whitelistedDomains.size > 0
        ? rawEntries.map(e =>
            _whitelistedDomains.has(e.domain) ? { ...e, blocked: false, result: 'allowed' } : e
          )
        : rawEntries
      setEntries(enriched)
      setTotal(resp.data?.total ?? 0)
    } catch {
      // Query log not enabled → show empty list
      setEntries([])
    } finally {
      setLoading(false)
    }
  }, [filter])

  const handleWhitelisted = useCallback((domain: string) => {
    // Remember domain as permanently whitelisted (persists across page navigations)
    _whitelistedDomains.add(domain)
    // Remove trailing dot for toast display
    const displayDomain = domain.replace(/\.$/, '')
    setToast({ msg: `✓ "${displayDomain}" zur Erlaubt-Liste hinzugefügt`, type: 'success' })
    setTimeout(() => setToast(null), 4000)
    // Immediately set row to "allowed" → green color as visual feedback
    setEntries(prev => prev.map(e =>
      e.domain === domain ? { ...e, blocked: false, result: 'allowed' } : e
    ))
  }, [])

  useEffect(() => {
    setLoading(true)
    fetchLog()
  }, [fetchLog])

  useEffect(() => {
    if (!autoRefresh) {
      if (intervalRef.current) clearInterval(intervalRef.current)
      return
    }
    intervalRef.current = setInterval(() => {
      fetchLog()
    }, 5000)
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
  }, [autoRefresh, fetchLog])

  return (
    <>
      <Topbar title="Query-Log" />
      <div className="p-4 lg:p-6 space-y-4">

        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-[#f0eeff]">DNS Query-Log</h2>
            <p className="text-xs text-[#6b5f8a]">
              {total > 0 ? `${total.toLocaleString('de-DE')} Einträge im Speicher` : 'Alle DNS-Anfragen in Echtzeit'}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setAutoRefresh(v => !v)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                autoRefresh
                  ? 'bg-violet-500/15 text-violet-400 border-violet-500/20'
                  : 'bg-[#100c1e] text-[#6b5f8a] border-[#2a1f42] hover:text-[#9a8cbf]'
              }`}
            >
              <span className={`w-1.5 h-1.5 rounded-full ${autoRefresh ? 'bg-violet-400 animate-pulse' : 'bg-[#6b5f8a]'}`} />
              {autoRefresh ? 'Live' : 'Pausiert'}
            </button>
            <button
              onClick={() => { setLoading(true); fetchLog() }}
              className="px-3 py-1.5 rounded-lg text-xs font-medium bg-[#100c1e] border border-[#2a1f42] text-[#9a8cbf] hover:text-[#f0eeff] transition-colors"
            >
              ↻ Aktualisieren
            </button>
          </div>
        </div>

        {/* Filter */}
        <FilterBar filter={filter} onChange={f => { setFilter(f); setLoading(true) }} />

        {/* Table */}
        <div className="bg-[#100c1e] neon-card rounded-xl overflow-hidden">
          <LogTable entries={entries} loading={loading} onWhitelisted={handleWhitelisted} onError={msg => { setToast({ msg, type: 'error' }); setTimeout(() => setToast(null), 5000) }} />
        </div>

      </div>
      {/* Toast notification */}
      {toast && (
        <div className={`fixed bottom-6 left-1/2 -translate-x-1/2 z-50 flex items-center gap-2 px-4 py-2.5 text-sm rounded-xl shadow-lg backdrop-blur-sm border ${
          toast.type === 'error'
            ? 'bg-red-500/20 border-red-500/30 text-red-400'
            : 'bg-emerald-500/20 border-emerald-500/30 text-emerald-400'
        }`}>
          {toast.msg}
        </div>
      )}
    </>
  )
}
