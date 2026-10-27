'use client'

import { useEffect, useState, useCallback } from 'react'
import { Topbar } from '@/components/layout/Topbar'
import { KpiCard } from '@/components/shared/KpiCard'
import {
  health, zones, blocklist, config, cluster, checkNodeHealth,
  queryLog, dhcpLeaseSync,
  type Zone, type BlocklistUrl, type Config, type ClusterNode,
  type QueryLogStats, type DHCPSyncStatus,
} from '@/lib/api'
import { fmtNum, fmtDate, cn } from '@/lib/utils'
import {
  PieChart, Pie, Cell, Legend, Tooltip, ResponsiveContainer,
} from 'recharts'
import { useRouter } from 'next/navigation'
import { InfoTooltip } from '@/components/shared/InfoTooltip'

const COLORS = ['#F59E0B', '#22c55e', '#f59e0b', '#ef4444', '#FCD34D', '#D97706']

const CHART_TOOLTIP_STYLE = {
  background: 'var(--surface-2)',
  border: '1px solid rgba(168,85,247,0.45)',
  borderRadius: 8,
  color: '#F4F4EF',
}

interface NodeStatus {
  online: boolean
  status: string
}

export default function OverviewPage() {
  const router = useRouter()
  const [data, setData] = useState<{
    healthStatus: string
    zoneList: Zone[]
    blUrls: BlocklistUrl[]
    blDomains: string[]
    cfg: Config
  } | null>(null)
  const [remoteNodes, setRemoteNodes] = useState<ClusterNode[]>([])
  const [clusterRole, setClusterRole] = useState<string>('master')
  const [nodeStatuses, setNodeStatuses] = useState<Record<string, NodeStatus>>({})
  const [qlStats, setQlStats] = useState<QueryLogStats | null>(null)
  const [dhcpStatus, setDhcpStatus] = useState<DHCPSyncStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [lastUpdated, setLastUpdated] = useState('')
  const [isRefreshing, setIsRefreshing] = useState(false)

  const fetchData = useCallback(async () => {
    try {
      const [healthRes, zonesRes, blUrlsRes, blDomsRes, cfgRes, qlStatsRes, dhcpRes] =
        await Promise.allSettled([
          health.get(),
          zones.list(),
          blocklist.listUrls(),
          blocklist.listDomains(),
          config.get(),
          queryLog.stats(),
          dhcpLeaseSync.getStatus(),
        ])

      setData({
        healthStatus:
          healthRes.status === 'fulfilled'
            ? healthRes.value?.data?.status ?? 'ok'
            : 'error',
        zoneList: zonesRes.status === 'fulfilled' ? (zonesRes.value?.data ?? []) : [],
        blUrls: blUrlsRes.status === 'fulfilled' ? (blUrlsRes.value?.data ?? []) : [],
        blDomains: blDomsRes.status === 'fulfilled' ? (blDomsRes.value?.data ?? []) : [],
        cfg: cfgRes.status === 'fulfilled' ? (cfgRes.value?.data ?? {}) : {},
      })

      if (qlStatsRes.status === 'fulfilled') {
        setQlStats(qlStatsRes.value?.data ?? null)
      }

      if (dhcpRes.status === 'fulfilled') {
        setDhcpStatus(dhcpRes.value?.data ?? null)
      }

      setLastUpdated('Aktualisiert ' + new Date().toLocaleTimeString('de-DE', { timeStyle: 'short' }))
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [])

  const checkNodes = useCallback((nodes: ClusterNode[]) => {
    nodes.forEach((node) => {
      checkNodeHealth(node.url).then((result) => {
        setNodeStatuses((prev) => ({ ...prev, [node.url]: result }))
      })
    })
  }, [])

  useEffect(() => {
    cluster.info().then((res) => {
      const nodes = res.data?.remote_nodes ?? []
      setClusterRole(res.data?.role ?? 'master')
      setRemoteNodes(nodes)
      checkNodes(nodes)
    }).catch(() => {
      setRemoteNodes([])
    })

    fetchData()
    setIsRefreshing(true)
    const timer = setInterval(() => {
      fetchData()
      setRemoteNodes((nodes) => {
        checkNodes(nodes)
        return nodes
      })
    }, 30000)
    return () => {
      clearInterval(timer)
      setIsRefreshing(false)
    }
  }, [fetchData, checkNodes])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-6 h-6 border-2 border-amber-500 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  const { healthStatus, zoneList, blUrls, blDomains, cfg } = data ?? {
    healthStatus: 'error',
    zoneList: [],
    blUrls: [],
    blDomains: [],
    cfg: {},
  }

  // Calculations
  let totalRecords = 0
  const typeCounts: Record<string, number> = {}
  for (const z of zoneList) {
    for (const r of z.records ?? []) {
      totalRecords++
      typeCounts[r.type] = (typeCounts[r.type] ?? 0) + 1
    }
  }
  const blActive = blUrls.filter((u) => u.enabled).length
  const dns = cfg.dnsserver ?? cfg.coredns ?? {}
  const blocklistEnabled = cfg.blocklist?.enabled ?? false
  const cacheEnabled = dns.cache?.enabled ?? false
  const doHEnabled = dns.doh?.enabled ?? false
  const doHPath = dns.doh?.path ?? '/dns-query'
  const doTEnabled = dns.dot?.enabled ?? false
  const doTListen = dns.dot?.listen ?? '[::]:853'
  const upstream = (dns.upstream ?? []).join(', ') || '–'
  const cacheMax = ('max_entries' in (dns.cache ?? {}) ? dns.cache?.max_entries : undefined) ?? 0

  const typeChartData = Object.entries(typeCounts).map(([name, value]) => ({ name, value }))
  const blChartData = [
    { name: 'Aktiv', value: blActive },
    { name: 'Inaktiv', value: blUrls.length - blActive },
  ].filter((d) => d.value > 0)

  // Query-Log Stats
  const blockRate = qlStats ? (qlStats.block_rate * 100).toFixed(1) : null
  const topClients = qlStats?.top_clients?.slice(0, 5) ?? []
  const topBlocked = qlStats?.top_blocked?.slice(0, 5) ?? []

  // Max values for relative bars
  const maxClientCount = topClients[0]?.count ?? 1
  const maxBlockedCount = topBlocked[0]?.count ?? 1

  return (
    <>
      <Topbar title="Übersicht" isRefreshing={isRefreshing} lastUpdated={lastUpdated} />
      <div className="p-4 lg:p-6 space-y-6">

        {/* Cluster Status */}
        <section>
          <div className="mb-3">
            <div className="flex items-center gap-2">
              <h2 className="text-base font-semibold text-[var(--text)]">Cluster-Status</h2>
              <InfoTooltip text="Live-Erreichbarkeits-Check aller Nodes via HTTP-Health-Endpoint." />
            </div>
            <p className="text-xs text-[var(--muted)]">
              {remoteNodes.length > 0
                ? `${remoteNodes.length + 1} Node${remoteNodes.length + 1 !== 1 ? 's' : ''} — Live-Statuscheck`
                : 'Dieser Server — Live-Statuscheck'}
            </p>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {/* This server (self) */}
            <div className={cn('rounded-2xl bg-[var(--surface-2)] neon-card p-5', healthStatus === 'ok' ? 'border border-green-500/30' : 'border border-red-500/30')}>
              <div className={cn('text-xs font-semibold mb-2 flex items-center gap-1.5', healthStatus === 'ok' ? 'text-green-400' : 'text-red-400')}>
                <span>Dieser Server</span>
                <span className="text-[10px] font-normal text-amber-400 bg-amber-500/10 px-1.5 py-0.5 rounded-full">{clusterRole}</span>
              </div>
              <div className="text-2xl font-bold text-[var(--text)] leading-none mb-2">
                {healthStatus === 'ok' ? '✓' : '✗'}
              </div>
              <div className="text-xs text-[var(--muted)]">
                {typeof window !== 'undefined' ? window.location.hostname : '—'} — {healthStatus === 'ok' ? 'Online' : 'Offline'}
              </div>
            </div>
            {/* Remote Nodes */}
            {remoteNodes.map((node) => {
              const st = nodeStatuses[node.url]
              const online = st?.online
              return (
                <div key={node.url} className={cn('rounded-2xl bg-[var(--surface-2)] neon-card p-5', !st ? '' : online ? 'border border-green-500/30' : 'border border-red-500/30')}>
                  <div className={cn('text-xs font-semibold mb-2 flex items-center gap-1.5', !st ? 'text-[var(--muted-2)]' : online ? 'text-green-400' : 'text-red-400')}>
                    <span>{node.label}</span>
                    <span className="text-[10px] font-normal text-[var(--muted-2)] bg-[var(--muted)]/20 px-1.5 py-0.5 rounded-full">{node.role}</span>
                  </div>
                  <div className="text-2xl font-bold text-[var(--text)] leading-none mb-2">
                    {!st ? '…' : online ? '✓' : '✗'}
                  </div>
                  <div className="text-xs text-[var(--muted)]">
                    {node.ip} — {!st ? 'Prüfe …' : online ? 'Online' : 'Offline'}
                  </div>
                </div>
              )
            })}
          </div>
        </section>

        {/* KPI Cards — Server-Status */}
        <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-3">
          <KpiCard
            label="API-Status"
            value={healthStatus === 'ok' ? '✓' : '✗'}
            hint={healthStatus === 'ok' ? 'Verbindung OK' : 'Verbindungsproblem'}
            info="Verbindungsstatus zur DNS-Stack-API."
            variant={healthStatus === 'ok' ? 'success' : 'error'}
          />
          <KpiCard
            label="DNS-Zonen"
            value={zoneList.length}
            hint={`${totalRecords} Einträge gesamt`}
            info="Anzahl der autoritativen DNS-Zonen."
            variant="accent"
          />
          <KpiCard
            label="Blocklist"
            value={blocklistEnabled ? 'AN' : 'AUS'}
            hint={`${blActive} aktive URL${blActive !== 1 ? 's' : ''} · ${blDomains.length} manuell`}
            info="Blockiert unerwünschte Domains (Werbung, Tracking, Malware)."
            variant={blocklistEnabled ? 'success' : 'warning'}
          />
          <KpiCard
            label="DNS-Cache"
            value={cacheEnabled ? 'AN' : 'AUS'}
            hint={`Max ${fmtNum(cacheMax)} Einträge`}
            info="Speichert DNS-Antworten im RAM für schnellere Auflösung."
            variant={cacheEnabled ? 'success' : 'warning'}
          />
          <KpiCard
            label="Upstream"
            value={<span className="text-base">{upstream.split(',')[0].trim() || '–'}</span>}
            hint={upstream}
            info="Übergeordneter DNS-Server (Round-Robin)."
          />
          <KpiCard
            label="DoH"
            value={doHEnabled ? 'AN' : 'AUS'}
            hint={doHEnabled ? doHPath : 'Deaktiviert'}
            info="DNS over HTTPS (RFC 8484)."
            variant={doHEnabled ? 'success' : 'warning'}
          />
          <KpiCard
            label="DoT"
            value={doTEnabled ? 'AN' : 'AUS'}
            hint={doTEnabled ? doTListen : 'Deaktiviert'}
            info="DNS over TLS (RFC 7858) — Port 853."
            variant={doTEnabled ? 'success' : 'warning'}
          />
        </div>

        {/* KPI Cards — Query-Log Statistics */}
        {(qlStats || dhcpStatus) && (
          <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
            {qlStats && (
              <>
                <KpiCard
                  label="Gesamt-Anfragen"
                  value={fmtNum(qlStats.total_queries)}
                  hint="Query-Log gesamt"
                  info="Gesamtzahl der DNS-Anfragen im Query-Log."
                  variant="accent"
                />
                <KpiCard
                  label="Block-Rate"
                  value={`${blockRate}%`}
                  hint="Blockierte Anfragen"
                  info="Anteil der blockierten Anfragen an allen Anfragen."
                  variant={parseFloat(blockRate ?? '0') > 20 ? 'warning' : 'success'}
                />
                <KpiCard
                  label="Top-Client"
                  value={<span className="text-sm truncate">{qlStats.top_clients?.[0]?.client ?? '—'}</span>}
                  hint={qlStats.top_clients?.[0] ? `${fmtNum(qlStats.top_clients[0].count)} Anfragen` : 'Keine Daten'}
                  info="Client mit den meisten DNS-Anfragen."
                />
              </>
            )}
            {dhcpStatus && (
              <KpiCard
                label="DHCP-Leases"
                value={fmtNum(dhcpStatus.lease_count)}
                hint={dhcpStatus.enabled ? `${fmtNum(dhcpStatus.record_count)} Records erstellt` : 'Sync deaktiviert'}
                info="Aktive DHCP-Leases aus dem Lease-Sync."
                variant={dhcpStatus.enabled ? 'success' : 'warning'}
              />
            )}
          </div>
        )}

        {/* Top Clients + Top blocked domains */}
        {(topClients.length > 0 || topBlocked.length > 0) && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Top Clients */}
            {topClients.length > 0 && (
              <div className="bg-[var(--surface-2)] neon-card rounded-2xl p-4">
                <div className="flex items-center gap-2 mb-4">
                  <span className="text-sm font-semibold text-[var(--muted-2)]">Top 5 Clients</span>
                  <InfoTooltip text="Clients mit den meisten DNS-Anfragen laut Query-Log." />
                </div>
                <div className="space-y-3">
                  {topClients.map((c, i) => (
                    <div key={c.client}>
                      <div className="flex items-center justify-between text-xs mb-1">
                        <span className="text-amber-400 font-mono truncate max-w-[60%]">
                          {i + 1}. {c.client}
                        </span>
                        <span className="text-[var(--muted-2)]">{fmtNum(c.count)}</span>
                      </div>
                      <div className="h-1.5 bg-[var(--border)] rounded-full overflow-hidden">
                        <div
                          className="h-full bg-amber-500 rounded-full"
                          style={{ width: `${(c.count / maxClientCount) * 100}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Top blocked domains */}
            {topBlocked.length > 0 && (
              <div className="bg-[var(--surface-2)] neon-card rounded-2xl p-4">
                <div className="flex items-center gap-2 mb-4">
                  <span className="text-sm font-semibold text-[var(--muted-2)]">Top 5 blockierte Domains</span>
                  <InfoTooltip text="Domains, die am häufigsten durch die Blocklist geblockt wurden." />
                </div>
                <div className="space-y-3">
                  {topBlocked.map((d, i) => (
                    <div key={d.domain}>
                      <div className="flex items-center justify-between text-xs mb-1">
                        <span className="text-red-400 font-mono truncate max-w-[60%]">
                          {i + 1}. {d.domain}
                        </span>
                        <span className="text-[var(--muted-2)]">{fmtNum(d.count)}</span>
                      </div>
                      <div className="h-1.5 bg-[var(--border)] rounded-full overflow-hidden">
                        <div
                          className="h-full bg-red-500/70 rounded-full"
                          style={{ width: `${(d.count / maxBlockedCount) * 100}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Charts — Record types + Blocklist */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="bg-[var(--surface-2)] neon-card rounded-2xl p-4">
            <div className="flex items-center gap-2 mb-4">
              <span className="text-sm font-semibold text-[var(--muted-2)]">Record-Typen Verteilung</span>
              <InfoTooltip text="Verteilung der DNS-Record-Typen über alle konfigurierten Zonen." />
            </div>
            {typeChartData.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={typeChartData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80}>
                    {typeChartData.map((_, i) => (
                      <Cell key={i} fill={COLORS[i % COLORS.length] + 'CC'} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={CHART_TOOLTIP_STYLE} labelStyle={{ color: '#F4F4EF' }} />
                  <Legend iconType="circle" wrapperStyle={{ fontSize: 12, color: '#9A9AAE' }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-48 text-[var(--muted)] text-sm">
                Noch keine Records vorhanden
              </div>
            )}
          </div>

          <div className="bg-[var(--surface-2)] neon-card rounded-2xl p-4">
            <div className="flex items-center gap-2 mb-4">
              <span className="text-sm font-semibold text-[var(--muted-2)]">Blocklist-URLs Status</span>
              <InfoTooltip text="Verhältnis aktiver zu inaktiver Blocklist-Quell-URLs." />
            </div>
            {blChartData.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={blChartData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80}>
                    {blChartData.map((_, i) => (
                      <Cell key={i} fill={COLORS[i % COLORS.length] + 'CC'} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={CHART_TOOLTIP_STYLE} labelStyle={{ color: '#F4F4EF' }} />
                  <Legend iconType="circle" wrapperStyle={{ fontSize: 12, color: '#9A9AAE' }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-48 text-[var(--muted)] text-sm">
                Keine Blocklist-URLs konfiguriert
              </div>
            )}
          </div>
        </div>

        {/* Zones Table */}
        <div className="bg-[var(--surface-2)] neon-card rounded-2xl overflow-hidden">
          <div className="flex items-center justify-between px-5 py-4 border-b border-[var(--border)]">
            <h3 className="text-sm font-semibold text-[var(--text)]">Zonen</h3>
            <button
              onClick={() => router.push('/dashboard/zones/')}
              className="text-xs text-amber-400 hover:text-amber-400 font-medium"
            >
              + Zone
            </button>
          </div>
          {zoneList.length > 0 ? (
            <div className="divide-y divide-[var(--surface)]">
              {zoneList.slice(0, 10).map((z) => (
                <div
                  key={z.domain}
                  className="flex items-center justify-between px-5 py-3 hover:bg-[var(--surface-3)] transition-colors cursor-pointer"
                  onClick={() => router.push(`/dashboard/zones/?d=${encodeURIComponent(z.domain)}`)}
                >
                  <div>
                    <div className="text-sm font-medium text-amber-400">{z.domain}</div>
                    <div className="text-xs text-[var(--muted)]">
                      {(z.records ?? []).length} Records · TTL {z.ttl ?? 3600}
                    </div>
                  </div>
                  <button
                    className="text-xs text-[var(--muted)] hover:text-[var(--muted-2)] px-2 py-1 rounded border border-[var(--border)] hover:border-[var(--muted)] transition-colors"
                    onClick={(e) => {
                      e.stopPropagation()
                      router.push(`/dashboard/zones/?d=${encodeURIComponent(z.domain)}`)
                    }}
                  >
                    Details
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-12 gap-3">
              <div className="text-2xl">🌐</div>
              <div className="text-sm font-medium text-[var(--text)]">Noch keine Zonen</div>
              <div className="text-xs text-[var(--muted)]">Erstelle die erste DNS-Zone</div>
              <button
                onClick={() => router.push('/dashboard/zones/')}
                className="mt-2 px-4 py-2 rounded-xl bg-amber-500/10 text-amber-400 text-sm font-medium hover:bg-amber-500/10 transition-colors"
              >
                + Zone hinzufügen
              </button>
            </div>
          )}
        </div>

        {/* Blocklist URLs */}
        <div className="bg-[var(--surface-2)] neon-card rounded-2xl overflow-hidden">
          <div className="flex items-center justify-between px-5 py-4 border-b border-[var(--border)]">
            <h3 className="text-sm font-semibold text-[var(--text)]">Blocklist-URLs</h3>
            <button
              onClick={() => router.push('/dashboard/blocklist/')}
              className="text-xs text-amber-400 hover:text-amber-400 font-medium"
            >
              Verwalten
            </button>
          </div>
          {blUrls.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--border)]">
                    {['URL', 'Status', 'Letzter Abruf'].map((h) => (
                      <th key={h} className="px-5 py-2 text-left text-xs font-semibold uppercase tracking-wider text-[var(--muted-2)]">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--surface)]">
                  {blUrls.slice(0, 8).map((u) => (
                    <tr key={u.id} className="hover:bg-[var(--surface-3)] transition-colors">
                      <td className="px-5 py-2.5 max-w-xs">
                        <a
                          href={u.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-amber-400 hover:text-amber-400 truncate block text-xs"
                        >
                          {u.url}
                        </a>
                      </td>
                      <td className="px-5 py-2.5">
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${
                            u.enabled
                              ? 'bg-green-500/15 text-green-400'
                              : 'bg-[var(--muted)]/15 text-[var(--muted-2)]'
                          }`}
                        >
                          {u.enabled ? 'Aktiv' : 'Inaktiv'}
                        </span>
                      </td>
                      <td className="px-5 py-2.5 text-xs text-[var(--muted)]">{fmtDate(u.last_fetched_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-10 gap-2">
              <div className="text-xs text-[var(--muted)]">Noch keine Blocklist-URLs konfiguriert</div>
              <button
                onClick={() => router.push('/dashboard/blocklist/')}
                className="mt-1 text-xs text-amber-400 hover:text-amber-400"
              >
                Blocklist einrichten →
              </button>
            </div>
          )}
        </div>

      </div>
    </>
  )
}
