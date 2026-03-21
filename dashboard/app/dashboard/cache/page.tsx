'use client'

import { useEffect, useState, useCallback } from 'react'
import { Topbar } from '@/components/layout/Topbar'
import { KpiCard } from '@/components/shared/KpiCard'
import { useToast } from '@/components/shared/Toast'
import { cache as cacheApi, type CacheStats, type CacheEntryInfo } from '@/lib/api'
import { Trash2, RefreshCw } from 'lucide-react'

function Spinner() {
  return (
    <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin inline-block" />
  )
}

function ttlColor(ttl: number): string {
  if (ttl >= 60) return 'text-green-400'
  if (ttl >= 10) return 'text-amber-400'
  return 'text-red-400'
}

function formatTime(unixTs: number): string {
  return new Date(unixTs * 1000).toLocaleTimeString('de-DE')
}

export default function CachePage() {
  const { showToast } = useToast()
  const [stats, setStats] = useState<CacheStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [flushing, setFlushing] = useState(false)
  const [deletingKey, setDeletingKey] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const fetchData = useCallback(async () => {
    try {
      const res = await cacheApi.stats()
      setStats(res.data)
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Fehler beim Laden')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
    const id = setInterval(fetchData, 5000)
    return () => clearInterval(id)
  }, [fetchData])

  const handleFlush = async () => {
    if (!confirm('Wirklich alle Cache-Einträge löschen?')) return
    setFlushing(true)
    try {
      await cacheApi.flush()
      showToast('Cache geleert', 'success')
      await fetchData()
    } catch (e) {
      showToast(e instanceof Error ? e.message : 'Fehler beim Leeren', 'error')
    } finally {
      setFlushing(false)
    }
  }

  const handleDelete = async (entry: CacheEntryInfo) => {
    const key = entry.name + ':' + entry.type
    if (!confirm(`Eintrag "${entry.name} (${entry.type})" löschen?`)) return
    setDeletingKey(key)
    try {
      await cacheApi.deleteEntry(entry.name, entry.type)
      showToast('Eintrag gelöscht', 'success')
      await fetchData()
    } catch (e) {
      showToast(e instanceof Error ? e.message : 'Fehler beim Löschen', 'error')
    } finally {
      setDeletingKey(null)
    }
  }

  return (
    <div className="flex flex-col h-full">
      <Topbar title="Cache" />

      <div className="flex-1 overflow-auto p-6 space-y-6">
        {/* KPI Cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <KpiCard
            label="Einträge"
            value={loading ? '—' : (stats?.entries ?? 0).toLocaleString('de-DE')}
          />
          <KpiCard
            label="Trefferquote"
            value={loading ? '—' : (stats?.hit_rate ?? 0).toFixed(1) + ' %'}
            variant={
              !stats ? 'default'
              : stats.hit_rate >= 50 ? 'success'
              : stats.hit_rate >= 20 ? 'warning'
              : 'error'
            }
          />
          <KpiCard
            label="Treffer"
            value={loading ? '—' : (stats?.hits ?? 0).toLocaleString('de-DE')}
          />
          <KpiCard
            label="Fehlschläge"
            value={loading ? '—' : (stats?.misses ?? 0).toLocaleString('de-DE')}
          />
        </div>

        {/* Entry list */}
        <div className="rounded-xl border border-[var(--border)] bg-[var(--surface)] overflow-hidden">
          <div className="flex items-center justify-between px-5 py-4 border-b border-[var(--border)]">
            <div>
              <h2 className="text-sm font-semibold text-[var(--text)]">Cache-Einträge</h2>
              <p className="text-xs text-neutral-500 mt-0.5">
                Bis zu 500 Einträge, sortiert nach verbleibender TTL
              </p>
            </div>
            <button
              onClick={handleFlush}
              disabled={flushing || loading}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium
                bg-red-500/10 text-red-400 border border-red-500/20
                hover:bg-red-500/20 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {flushing ? <Spinner /> : <Trash2 className="w-3.5 h-3.5" />}
              Cache leeren
            </button>
          </div>

          {loading ? (
            <div className="flex items-center justify-center h-32">
              <div className="w-6 h-6 border-2 border-amber-500 border-t-transparent rounded-full animate-spin" />
            </div>
          ) : error ? (
            <div className="flex items-center justify-center h-32 text-sm text-red-400">
              {error}
            </div>
          ) : !stats || stats.entry_list.length === 0 ? (
            <div className="flex items-center justify-center h-32 text-sm text-neutral-500">
              Keine Cache-Einträge vorhanden.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--border)] text-xs text-neutral-500 uppercase tracking-wide">
                    <th className="px-4 py-3 text-left font-medium">Name</th>
                    <th className="px-4 py-3 text-left font-medium">Typ</th>
                    <th className="px-4 py-3 text-left font-medium">Verbl. TTL</th>
                    <th className="px-4 py-3 text-left font-medium">Im Cache seit</th>
                    <th className="px-4 py-3 text-left font-medium">Läuft ab</th>
                    <th className="px-4 py-3 text-right font-medium"></th>
                  </tr>
                </thead>
                <tbody>
                  {stats.entry_list.map((entry) => {
                    const key = entry.name + ':' + entry.type
                    const isDeleting = deletingKey === key
                    return (
                      <tr
                        key={key}
                        className="border-b border-[var(--border)] last:border-0 hover:bg-white/[0.02] transition-colors"
                      >
                        <td className="px-4 py-3 font-mono text-xs text-[var(--text)] max-w-[220px]">
                          <span
                            title={entry.name}
                            className="block truncate"
                          >
                            {entry.name}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="px-1.5 py-0.5 rounded text-xs font-mono bg-blue-500/10 text-blue-400 border border-blue-500/20">
                            {entry.type}
                          </span>
                        </td>
                        <td className={`px-4 py-3 font-mono text-xs ${ttlColor(entry.remaining_ttl)}`}>
                          {entry.remaining_ttl} s
                        </td>
                        <td className="px-4 py-3 text-xs text-neutral-400">
                          {formatTime(entry.cached_at)}
                        </td>
                        <td className="px-4 py-3 text-xs text-neutral-400">
                          {formatTime(entry.expires_at)}
                        </td>
                        <td className="px-4 py-3 text-right">
                          <button
                            onClick={() => handleDelete(entry)}
                            disabled={isDeleting || flushing}
                            title="Eintrag löschen"
                            className="p-1.5 rounded hover:bg-red-500/10 text-neutral-500 hover:text-red-400
                              transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                          >
                            {isDeleting ? <Spinner /> : <Trash2 className="w-3.5 h-3.5" />}
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
