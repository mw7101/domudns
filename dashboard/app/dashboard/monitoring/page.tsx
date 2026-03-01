'use client'

import { useEffect, useState, useCallback, useRef } from 'react'
import { Topbar } from '@/components/layout/Topbar'
import { KpiCard } from '@/components/shared/KpiCard'
import { metrics as metricsApi, config, MetricsSnapshot } from '@/lib/api'
import { fmtNum, parsePrometheus, getMetric } from '@/lib/utils'
import { cn } from '@/lib/utils'
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from 'recharts'
import { InfoTooltip } from '@/components/shared/InfoTooltip'

const COLORS = ['#a855f7', '#22c55e', '#f59e0b', '#ef4444', '#c084fc', '#7c3aed']

interface MetricsSample {
  ts: number
  metrics: ReturnType<typeof parsePrometheus>
}

/** Sum of all samples whose label contains `result="<result>"` */
function getResultSum(
  parsed: ReturnType<typeof parsePrometheus>,
  result: string
): number | null {
  const m = parsed['dns_queries_total']
  if (!m) return null
  const matching = m.samples.filter((s) => s.labels.includes(`result="${result}"`))
  if (matching.length === 0) return null
  return matching.reduce((acc, s) => acc + s.value, 0)
}

const RANGE_LABELS: Record<'1h' | '24h' | '7d' | '30d', string> = {
  '1h': '1 Stunde',
  '24h': '24 Stunden',
  '7d': '1 Woche',
  '30d': '1 Monat',
}

export default function MonitoringPage() {
  const [metricsText, setMetricsText] = useState('')
  const [metricsEnabled, setMetricsEnabled] = useState(false)
  const [history, setHistory] = useState<MetricsSample[]>([])
  const [dayHistory, setDayHistory] = useState<MetricsSnapshot[]>([])
  const [loading, setLoading] = useState(true)
  const [lastUpdated, setLastUpdated] = useState('')
  const [range, setRange] = useState<'1h' | '24h' | '7d' | '30d'>('1h')
  const historyRef = useRef<MetricsSample[]>([])

  const fetchDayHistory = useCallback(async () => {
    try {
      const res = await metricsApi.history(range)
      setDayHistory(res?.data?.samples ?? [])
    } catch {
      // History stays empty if API is unavailable
    }
  }, [range])

  const fetchData = useCallback(async () => {
    const [metricsResult, cfgResult] = await Promise.allSettled([
      metricsApi.get(),
      config.get(),
    ])

    const cfg = cfgResult.status === 'fulfilled' ? cfgResult.value?.data : {}
    setMetricsEnabled(cfg?.system?.metrics?.enabled ?? false)

    if (metricsResult.status === 'fulfilled') {
      const text = metricsResult.value ?? ''
      setMetricsText(text)
      if (text.trim()) {
        const parsed = parsePrometheus(text)
        const sample: MetricsSample = { ts: Date.now(), metrics: parsed }
        historyRef.current = [...historyRef.current, sample].slice(-20)
        setHistory([...historyRef.current])
      }
    }
    setLastUpdated('Aktualisiert ' + new Date().toLocaleTimeString('de-DE', { timeStyle: 'short' }))
    setLoading(false)
  }, [])

  useEffect(() => {
    fetchData()
    fetchDayHistory()
    const timer = setInterval(fetchData, 30000)
    // Reload history every 10 seconds
    const dayTimer = setInterval(fetchDayHistory, 10000)
    return () => {
      clearInterval(timer)
      clearInterval(dayTimer)
    }
  }, [fetchData, fetchDayHistory])

  // Reload immediately when the time range changes
  useEffect(() => {
    fetchDayHistory()
  }, [range, fetchDayHistory])

  const metricsAvailable = metricsText.trim().length > 0
  const parsed = parsePrometheus(metricsText)

  const queries = getMetric(parsed, 'dns_queries_total')
  const blocked = getResultSum(parsed, 'blocked')
  const cacheHits = getResultSum(parsed, 'cached')
  const cacheMisses = getResultSum(parsed, 'forwarded')
  const upstreamErrors = getResultSum(parsed, 'error')
  const goroutines = getMetric(parsed, 'go_goroutines')
  const memAlloc = getMetric(parsed, 'go_memstats_alloc_bytes')

  // Rate from live history (last two measurement values)
  let queryRate: number | null = null
  let hitRate: string | null = null
  if (history.length >= 2) {
    const prev = history[history.length - 2]
    const cur = history[history.length - 1]
    const dt = (cur.ts - prev.ts) / 1000
    const qCur = getMetric(cur.metrics, 'dns_queries_total')
    const qPrev = getMetric(prev.metrics, 'dns_queries_total')
    if (qCur != null && qPrev != null && dt > 0) {
      queryRate = Math.max(0, (qCur - qPrev) / dt)
    }
    const hCur = getResultSum(cur.metrics, 'cached')
    const hPrev = getResultSum(prev.metrics, 'cached')
    const mCur = getResultSum(cur.metrics, 'forwarded')
    const mPrev = getResultSum(prev.metrics, 'forwarded')
    if (hCur != null && hPrev != null && mCur != null && mPrev != null) {
      const hDiff = hCur - hPrev
      const mDiff = mCur - mPrev
      const total = hDiff + mDiff
      hitRate = total > 0 ? ((hDiff / total) * 100).toFixed(1) : null
    }
  }

  // History chart data: compute differences → rate/s
  const dayChartData = dayHistory.map((snap, i) => {
    const time = new Date(snap.ts * 1000).toLocaleTimeString('de-DE', { timeStyle: 'short' })
    if (i === 0) return { time, queries: 0, blocked: 0, cached: 0, errors: 0 }
    const prev = dayHistory[i - 1]
    const dt = snap.ts - prev.ts
    if (dt <= 0) return { time, queries: 0, blocked: 0, cached: 0, errors: 0 }
    return {
      time,
      queries: parseFloat((Math.max(0, snap.queries - prev.queries) / dt).toFixed(3)),
      blocked: parseFloat((Math.max(0, snap.blocked - prev.blocked) / dt).toFixed(3)),
      cached: parseFloat((Math.max(0, snap.cached - prev.cached) / dt).toFixed(3)),
      errors: parseFloat((Math.max(0, snap.errors - prev.errors) / dt).toFixed(3)),
    }
  }).slice(1)

  const cacheChartData =
    cacheHits != null && cacheMisses != null
      ? [
          { name: 'Cache-Treffer', value: cacheHits },
          { name: 'Cache-Fehltreffer', value: cacheMisses },
        ]
      : []

  const blockedChartData =
    queries != null && blocked != null
      ? [
          { name: 'Weitergeleitet', value: Math.max(0, queries - (blocked ?? 0)) },
          { name: 'Blockiert', value: blocked ?? 0 },
        ]
      : []

  const allMetrics = Object.entries(parsed).filter(
    ([k]) => !k.startsWith('go_') && !k.startsWith('process_')
  )
  const goMetrics = Object.entries(parsed)
    .filter(([k]) => k.startsWith('go_') || k.startsWith('process_'))
    .slice(0, 12)

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-6 h-6 border-2 border-violet-500 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  return (
    <>
      <Topbar title="Monitoring" isRefreshing lastUpdated={lastUpdated} />
      <div className="p-4 lg:p-6 space-y-6">

        {/* Metrics unavailable banner */}
        {!metricsAvailable && (
          <div className="flex items-start gap-3 px-5 py-4 rounded-2xl border border-amber-500/30 bg-amber-500/10 text-amber-300 text-sm">
            <span className="text-lg mt-0.5">⚠</span>
            <div>
              <div className="font-semibold mb-1">Prometheus Metriken nicht verfügbar</div>
              <div className="text-amber-400/80">
                Metriken sind {metricsEnabled ? 'aktiviert, aber leer' : 'deaktiviert'}.
                Aktivieren unter Einstellungen → System → Metriken.
              </div>
            </div>
          </div>
        )}

        {/* DNS KPIs */}
        <section>
          <div className="mb-3">
            <div className="flex items-center gap-2">
              <h2 className="text-base font-semibold text-[#f0eeff]">DNS Metriken</h2>
              <InfoTooltip text="Alle benutzerdefinierten Prometheus-Metriken des DNS-Stacks." />
            </div>
            <p className="text-xs text-[#6b5f8a]">Live-Daten · Alle 30 Sekunden aktualisiert</p>
          </div>
          <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-3">
            <KpiCard
              label="Anfragen gesamt"
              value={queries != null ? fmtNum(queries) : '–'}
              hint={queryRate != null ? `${queryRate.toFixed(2)}/s aktuell` : 'Kein Verlauf'}
              info="Kumulative DNS-Anfragen seit Server-Start. Rate = Anfragen pro Sekunde (letzte 30s)."
              variant={queries != null ? 'accent' : 'default'}
            />
            <KpiCard
              label="Blockiert"
              value={blocked != null ? fmtNum(blocked) : '–'}
              hint={
                queries && blocked
                  ? `${((blocked / queries) * 100).toFixed(1)}% aller Anfragen`
                  : ''
              }
              info="Von der Blocklist abgewiesene Domains. Prozent = Anteil aller Anfragen."
              variant={blocked != null ? 'error' : 'default'}
            />
            <KpiCard
              label="Cache-Treffer"
              value={cacheHits != null ? fmtNum(cacheHits) : '–'}
              hint={hitRate != null ? `Trefferquote: ${hitRate}%` : ''}
              info="Anfragen, die direkt aus dem RAM-Cache beantwortet wurden (0ms Latenz)."
              variant={cacheHits != null ? 'success' : 'default'}
            />
            <KpiCard
              label="Cache-Fehltreffer"
              value={cacheMisses != null ? fmtNum(cacheMisses) : '–'}
              info="Anfragen, bei denen der Cache leer war → Upstream-Abfrage nötig."
            />
            <KpiCard
              label="Upstream-Fehler"
              value={upstreamErrors != null ? fmtNum(upstreamErrors) : '–'}
              info="Fehlgeschlagene Weiterleitungen an externe DNS-Server (1.1.1.1, 8.8.8.8)."
              variant={upstreamErrors != null && upstreamErrors > 0 ? 'error' : 'default'}
            />
            <KpiCard
              label="RAM"
              value={memAlloc != null ? `${(memAlloc / 1024 / 1024).toFixed(1)}MB` : '–'}
              hint={goroutines != null ? `${goroutines} Goroutines` : ''}
              info="Aktuell genutzter Heap-Speicher des DNS-Prozesses. Ziel: unter 150 MB."
            />
          </div>
        </section>

        {/* Charts */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* History chart with time range selector */}
          <div className="lg:col-span-2 bg-[#100c1e] neon-card rounded-2xl p-4">
            <div className="flex items-center justify-between mb-4 flex-wrap gap-2">
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold text-[#9a8cbf]">
                  Verlauf — {RANGE_LABELS[range]}
                </span>
                <InfoTooltip text="Anfragen/s, Blockiert/s, Cache-Treffer/s und Fehler/s aus dem Backend-Ring-Buffer." />
              </div>
              <div className="flex items-center gap-1">
                {(['1h', '24h', '7d', '30d'] as const).map((r) => (
                  <button
                    key={r}
                    onClick={() => setRange(r)}
                    className={cn(
                      'px-3 py-1 text-xs rounded-lg transition-colors',
                      range === r
                        ? 'bg-violet-600 text-white'
                        : 'bg-[#080612] text-[#6b5f8a] hover:text-[#f0eeff]'
                    )}
                  >
                    {RANGE_LABELS[r]}
                  </button>
                ))}
              </div>
            </div>
            {dayChartData.length >= 2 ? (
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={dayChartData}>
                  <CartesianGrid stroke="#1a1230" strokeDasharray="3 3" />
                  <XAxis dataKey="time" tick={{ fill: '#6b5f8a', fontSize: 10 }} interval="preserveStartEnd" />
                  <YAxis tick={{ fill: '#6b5f8a', fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{ background: '#100c1e', border: '1px solid #2a1f42', borderRadius: 8 }}
                    labelStyle={{ color: '#f0eeff' }}
                    formatter={(v: number) => v.toFixed(3) + '/s'}
                  />
                  <Line type="monotone" dataKey="queries" stroke="#a855f7" strokeWidth={2} dot={false} name="Anfragen/s" />
                  <Line type="monotone" dataKey="blocked" stroke="#ef4444" strokeWidth={1.5} dot={false} name="Blockiert/s" />
                  <Line type="monotone" dataKey="cached" stroke="#22c55e" strokeWidth={1.5} dot={false} name="Cache/s" />
                  <Line type="monotone" dataKey="errors" stroke="#f59e0b" strokeWidth={1.5} dot={false} name="Fehler/s" />
                  <Legend iconType="circle" wrapperStyle={{ fontSize: 12, color: '#9a8cbf' }} />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-48 text-[#6b5f8a] text-sm text-center px-4">
                Noch keine Daten für {RANGE_LABELS[range]} — Verlauf wird aufgebaut
              </div>
            )}
          </div>
        </div>

        {/* DNS Metrics Detail */}
        {allMetrics.length > 0 && (
          <div className="bg-[#100c1e] neon-card rounded-2xl p-4">
            <div className="flex items-center gap-2 mb-4">
              <span className="text-sm font-semibold text-[#9a8cbf]">DNS Metriken Detail</span>
              <InfoTooltip text="Alle benutzerdefinierten Prometheus-Metriken des DNS-Stacks." />
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
              {allMetrics.map(([name, m]) => (
                <div key={name} className="bg-[#080612]/60 border border-[#2a1f42]/50 rounded-xl p-3">
                  <div className="text-xs text-[#6b5f8a] mb-1 truncate">{name}</div>
                  <div className="text-sm font-bold text-[#f0eeff]">{fmtNum(m.total)}</div>
                  {m.samples.length > 1 && (
                    <div className="text-xs text-[#6b5f8a] mt-0.5">{m.samples.length} Label-Varianten</div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Go Runtime */}
        {goMetrics.length > 0 && (
          <div className="bg-[#100c1e] neon-card rounded-2xl p-4">
            <div className="flex items-center gap-2 mb-4">
              <span className="text-sm font-semibold text-[#9a8cbf]">Go Runtime</span>
              <InfoTooltip text="Interne Go-Runtime-Metriken: Goroutines, GC, Speicherstatistiken." />
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
              {goMetrics.map(([name, m]) => (
                <div key={name} className="bg-[#080612]/60 border border-[#2a1f42]/50 rounded-xl p-3">
                  <div className="text-xs text-[#6b5f8a] mb-1 truncate">
                    {name.replace(/^(go_|process_)/, '')}
                  </div>
                  <div className="text-sm font-bold text-[#f0eeff]">
                    {name.includes('bytes')
                      ? `${(m.total / 1024 / 1024).toFixed(2)} MB`
                      : name.includes('seconds')
                      ? `${m.total.toFixed(3)}s`
                      : fmtNum(m.total)}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </>
  )
}
