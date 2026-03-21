'use client'

import { useEffect, useState, useCallback, Suspense } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { Topbar } from '@/components/layout/Topbar'
import { AnimatedModal } from '@/components/ui/animated-modal'
import { MovingBorderButton } from '@/components/ui/moving-border'
import { useToast } from '@/components/shared/Toast'
import { zones as zonesApi, records as recordsApi, type Zone, type DnsRecord, type ImportResult } from '@/lib/api'
import { formatRecordValue, RECORD_TYPE_COLORS } from '@/lib/utils'

const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'PTR', 'CAA', 'FWD']

const TYPE_HINTS: Record<string, string> = {
  A: 'IPv4-Adresse',
  AAAA: 'IPv6-Adresse',
  CNAME: 'Ziel-Hostname (FQDN)',
  MX: 'Mail-Server (FQDN)',
  TXT: 'Text-Inhalt',
  NS: 'Nameserver (FQDN)',
  SRV: 'Ziel-Hostname',
  PTR: 'Hostname',
  CAA: 'Wert (z.B. letsencrypt.org)',
  FWD: 'DNS-Server für Fallback-Forwarding (kommagetrennt, z.B. 1.1.1.1, 8.8.8.8)',
}

function ZonesContent() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const { showToast } = useToast()
  const domainParam = searchParams.get('d')

  const [zoneList, setZoneList] = useState<Zone[]>([])
  const [selectedZone, setSelectedZone] = useState<Zone | null>(null)
  const [loading, setLoading] = useState(true)

  // Loading states for actions
  const [addingZone, setAddingZone] = useState(false)
  const [deletingZone, setDeletingZone] = useState<string | null>(null)
  const [savingRecord, setSavingRecord] = useState(false)
  const [deletingRecord, setDeletingRecord] = useState<number | null>(null)
  const [exportingZone, setExportingZone] = useState(false)
  const [importing, setImporting] = useState(false)

  // Import Modal
  const [importOpen, setImportOpen] = useState(false)
  const [importTab, setImportTab] = useState<'file' | 'axfr'>('file')
  const [importFile, setImportFile] = useState<File | null>(null)
  const [importDomain, setImportDomain] = useState('')
  const [importView, setImportView] = useState('')
  const [axfrServer, setAxfrServer] = useState('')
  const [axfrDomain, setAxfrDomain] = useState('')
  const [axfrView, setAxfrView] = useState('')

  // Add Zone Modal
  const [addZoneOpen, setAddZoneOpen] = useState(false)
  const [zoneDomain, setZoneDomain] = useState('')
  const [zoneView, setZoneView] = useState('')
  const [zoneTtl, setZoneTtl] = useState(3600)
  const [zoneTtlOverride, setZoneTtlOverride] = useState(0)

  // Record Modal
  const [recordModalOpen, setRecordModalOpen] = useState(false)
  const [editingRecord, setEditingRecord] = useState<DnsRecord | null>(null)
  const [recordDomain, setRecordDomain] = useState('')
  const [rForm, setRForm] = useState({
    name: '@',
    type: 'A',
    ttl: 3600,
    value: '',
    priority: 10,
    weight: 10,
    port: 443,
    tag: 'issue',
  })

  const loadZones = useCallback(async () => {
    try {
      const res = await zonesApi.list()
      setZoneList(res.data ?? [])
    } catch {
      showToast('Fehler beim Laden der Zonen', 'error')
    } finally {
      setLoading(false)
    }
  }, [showToast])

  const loadZoneDetail = useCallback(
    async (domain: string) => {
      try {
        const res = await zonesApi.get(domain)
        setSelectedZone(res.data)
      } catch {
        showToast('Zone nicht gefunden', 'error')
      }
    },
    [showToast]
  )

  useEffect(() => {
    loadZones()
  }, [loadZones])

  useEffect(() => {
    if (domainParam) loadZoneDetail(domainParam)
    else setSelectedZone(null)
  }, [domainParam, loadZoneDetail])

  // FWD record must always use @ as name
  useEffect(() => {
    if (rForm.type === 'FWD') {
      setRForm((f) => ({ ...f, name: '@' }))
    }
  }, [rForm.type])

  const openZoneDetail = (domain: string) => {
    router.push(`/dashboard/zones/?d=${encodeURIComponent(domain)}`)
  }

  const handleDeleteZone = async (domain: string) => {
    if (!confirm(`Zone ${domain} wirklich löschen?`)) return
    if (deletingZone !== null) return
    setDeletingZone(domain)
    try {
      await zonesApi.delete(domain)
      showToast('Zone gelöscht')
      router.push('/dashboard/zones/')
      await loadZones()
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler', 'error')
    } finally {
      setDeletingZone(null)
    }
  }

  const handleAddZone = async () => {
    if (addingZone) return
    setAddingZone(true)
    try {
      const payload: { domain: string; view?: string; ttl: number; ttl_override?: number; records: [] } = {
        domain: zoneDomain.trim(),
        ttl: zoneTtl,
        records: [],
      }
      if (zoneView.trim()) payload.view = zoneView.trim()
      if (zoneTtlOverride > 0) payload.ttl_override = zoneTtlOverride
      await zonesApi.create(payload)
      showToast('Zone erstellt')
      setAddZoneOpen(false)
      setZoneDomain('')
      setZoneView('')
      setZoneTtlOverride(0)
      await loadZones()
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler', 'error')
    } finally {
      setAddingZone(false)
    }
  }

  const openRecordModal = (domain: string, record?: DnsRecord) => {
    setRecordDomain(domain)
    setEditingRecord(record ?? null)
    setRForm({
      name: record?.name ?? '@',
      type: record?.type ?? 'A',
      ttl: record?.ttl ?? 3600,
      value: record?.value ?? '',
      priority: record?.priority ?? 10,
      weight: record?.weight ?? 10,
      port: record?.port ?? 443,
      tag: record?.tag ?? 'issue',
    })
    setRecordModalOpen(true)
  }

  const handleSaveRecord = async () => {
    if (savingRecord) return
    setSavingRecord(true)
    try {
      const payload: Omit<DnsRecord, 'id'> = {
        name: rForm.name || '@',
        type: rForm.type,
        ttl: rForm.ttl,
        value: rForm.value,
      }
      if (rForm.type === 'MX') payload.priority = rForm.priority
      if (rForm.type === 'SRV') {
        payload.priority = rForm.priority
        payload.weight = rForm.weight
        payload.port = rForm.port
      }
      if (rForm.type === 'CAA') payload.tag = rForm.tag

      if (editingRecord) {
        await recordsApi.update(recordDomain, editingRecord.id, { ...payload, id: editingRecord.id })
        showToast('Record gespeichert')
      } else {
        await recordsApi.create(recordDomain, payload)
        showToast('Record hinzugefügt')
      }
      setRecordModalOpen(false)
      await loadZoneDetail(recordDomain)
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler', 'error')
    } finally {
      setSavingRecord(false)
    }
  }

  const handleDeleteRecord = async (domain: string, id: number) => {
    if (!confirm('Record löschen?')) return
    if (deletingRecord !== null) return
    setDeletingRecord(id)
    try {
      await recordsApi.delete(domain, id)
      showToast('Record gelöscht')
      await loadZoneDetail(domain)
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler', 'error')
    } finally {
      setDeletingRecord(null)
    }
  }

  const handleExportZone = async (domain: string, view?: string) => {
    if (exportingZone) return
    setExportingZone(true)
    try {
      const content = await zonesApi.export(domain, view)
      const blob = new Blob([content], { type: 'text/plain' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = domain + '.zone'
      a.click()
      URL.revokeObjectURL(url)
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Export fehlgeschlagen', 'error')
    } finally {
      setExportingZone(false)
    }
  }

  const showImportResult = (res: { data: ImportResult }) => {
    const { imported, merged, zone } = res.data
    showToast(`Zone ${zone}: ${imported} Records importiert, ${merged} zusammengeführt`, 'success')
  }

  const handleImportFile = async () => {
    if (!importFile || importing) return
    setImporting(true)
    try {
      const res = await zonesApi.importFile(
        importFile,
        importDomain.trim() || undefined,
        importView.trim() || undefined
      )
      showImportResult(res)
      setImportOpen(false)
      setImportFile(null)
      setImportDomain('')
      setImportView('')
      await loadZones()
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Import fehlgeschlagen', 'error')
    } finally {
      setImporting(false)
    }
  }

  const handleImportAXFR = async () => {
    if (!axfrServer.trim() || !axfrDomain.trim() || importing) return
    setImporting(true)
    try {
      const res = await zonesApi.importAXFR(
        axfrServer.trim(),
        axfrDomain.trim(),
        axfrView.trim() || undefined
      )
      showImportResult(res)
      setImportOpen(false)
      setAxfrServer('')
      setAxfrDomain('')
      setAxfrView('')
      await loadZones()
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'AXFR-Import fehlgeschlagen', 'error')
    } finally {
      setImporting(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-6 h-6 border-2 border-violet-500 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  // Zone Detail View
  if (selectedZone) {
    const typeStats: Record<string, number> = {}
    for (const r of selectedZone.records ?? []) {
      typeStats[r.type] = (typeStats[r.type] ?? 0) + 1
    }

    return (
      <>
        <Topbar title={selectedZone.domain} />
        <div className="p-4 lg:p-6 space-y-5">
          <button
            onClick={() => router.push('/dashboard/zones/')}
            className="text-sm text-violet-400 hover:text-violet-300 flex items-center gap-1"
          >
            ← Zurück zu Zonen
          </button>

          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold text-[#f0eeff]">{selectedZone.domain}</h2>
              <p className="text-xs text-[#6b5f8a]">
                {(selectedZone.records ?? []).length} Records · TTL {selectedZone.ttl ?? 3600}s
                {selectedZone.ttl_override ? ` · Override ${selectedZone.ttl_override}s` : ''} ·{' '}
                {Object.entries(typeStats)
                  .map(([t, n]) => `${n}× ${t}`)
                  .join(' · ')}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => handleExportZone(selectedZone.domain, selectedZone.view)}
                disabled={exportingZone}
                className="text-xs text-[#9a8cbf] hover:text-[#f0eeff] disabled:opacity-50 px-3 py-1.5 rounded-lg border border-[#2a1f42] hover:border-[#6b5f8a] transition-colors"
              >
                {exportingZone ? '…' : '↓ Export .zone'}
              </button>
              <MovingBorderButton onClick={() => openRecordModal(selectedZone.domain)}>
                + Record
              </MovingBorderButton>
            </div>
          </div>

          <div className="bg-[#100c1e] neon-card rounded-2xl overflow-hidden">
            {(selectedZone.records ?? []).length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#2a1f42]">
                      {['Name', 'Typ', 'TTL', 'Wert', 'Aktionen'].map((h) => (
                        <th key={h} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-[#9a8cbf]">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#080612]">
                    {(selectedZone.records ?? []).map((r) => {
                      const isDeletingThis = deletingRecord === r.id
                      return (
                      <tr key={r.id} className="hover:bg-[#1a1230] transition-colors">
                        <td className="px-4 py-3 font-mono text-xs text-[#f0eeff]">{r.name ?? '@'}</td>
                        <td className="px-4 py-3">
                          <span
                            className="inline-flex items-center px-2 py-0.5 rounded text-xs font-bold"
                            style={{
                              background: (RECORD_TYPE_COLORS[r.type] ?? '#5a5a72') + '25',
                              color: RECORD_TYPE_COLORS[r.type] ?? '#9a8cbf',
                            }}
                          >
                            {r.type}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs text-[#6b5f8a]">{r.ttl}s</td>
                        <td className="px-4 py-3 font-mono text-xs text-[#f0eeff] max-w-xs truncate">
                          {formatRecordValue(r)}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => openRecordModal(selectedZone.domain, r)}
                              disabled={isDeletingThis}
                              className="text-xs text-[#9a8cbf] hover:text-[#f0eeff] disabled:opacity-50 px-2 py-1 rounded border border-[#2a1f42] hover:border-[#6b5f8a] transition-colors"
                            >
                              Bearbeiten
                            </button>
                            <button
                              onClick={() => handleDeleteRecord(selectedZone.domain, r.id)}
                              disabled={isDeletingThis}
                              className="min-w-[60px] flex items-center justify-center gap-1 text-xs text-red-400 hover:text-red-300 disabled:opacity-50 disabled:cursor-wait px-2 py-1 rounded border border-red-500/30 hover:border-red-400/50 transition-colors"
                            >
                              {isDeletingThis
                                ? <><span className="inline-block w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" /> …</>
                                : 'Löschen'}
                            </button>
                          </div>
                        </td>
                      </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-12 gap-3">
                <div className="text-2xl">📋</div>
                <div className="text-sm font-medium text-[#f0eeff]">Keine Records</div>
                <div className="text-xs text-[#6b5f8a]">Füge den ersten DNS-Record hinzu.</div>
                <MovingBorderButton onClick={() => openRecordModal(selectedZone.domain)} className="mt-1">
                  + Record hinzufügen
                </MovingBorderButton>
              </div>
            )}
          </div>
        </div>

        {/* Record Modal */}
        <AnimatedModal
          isOpen={recordModalOpen}
          onClose={() => setRecordModalOpen(false)}
          title={editingRecord ? 'Record bearbeiten' : 'Record hinzufügen'}
        >
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-[#9a8cbf] uppercase tracking-wider mb-2">
                Name (@ = Zone-Apex)
              </label>
              <input
                value={rForm.name}
                onChange={(e) => setRForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="@ oder www"
                readOnly={rForm.type === 'FWD'}
                className="w-full px-3 py-2 rounded-xl bg-[#080612] border border-[#2a1f42] text-[#f0eeff] text-sm focus:outline-none focus:border-violet-500 transition-colors read-only:opacity-60 read-only:cursor-not-allowed"
              />
              <p className="text-xs text-[#6b5f8a] mt-1">@ = Zone selbst, sonst Subdomain</p>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-semibold text-[#9a8cbf] uppercase tracking-wider mb-2">Typ</label>
                <select
                  value={rForm.type}
                  onChange={(e) => setRForm((f) => ({ ...f, type: e.target.value }))}
                  className="w-full px-3 py-2 rounded-xl bg-[#080612] border border-[#2a1f42] text-[#f0eeff] text-sm focus:outline-none focus:border-violet-500 transition-colors"
                >
                  {RECORD_TYPES.map((t) => (
                    <option key={t} value={t}>{t}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs font-semibold text-[#9a8cbf] uppercase tracking-wider mb-2">TTL (s)</label>
                <input
                  type="number"
                  value={rForm.ttl}
                  onChange={(e) => setRForm((f) => ({ ...f, ttl: parseInt(e.target.value) || 3600 }))}
                  min={60}
                  className="w-full px-3 py-2 rounded-xl bg-[#080612] border border-[#2a1f42] text-[#f0eeff] text-sm focus:outline-none focus:border-violet-500 transition-colors"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-[#9a8cbf] uppercase tracking-wider mb-2">
                Wert
              </label>
              <input
                value={rForm.value}
                onChange={(e) => setRForm((f) => ({ ...f, value: e.target.value }))}
                placeholder={TYPE_HINTS[rForm.type] ?? 'Wert'}
                className="w-full px-3 py-2 rounded-xl bg-[#080612] border border-[#2a1f42] text-[#f0eeff] text-sm focus:outline-none focus:border-violet-500 transition-colors"
              />
              <p className="text-xs text-[#6b5f8a] mt-1">{TYPE_HINTS[rForm.type] ?? ''}</p>
            </div>

            {rForm.type === 'MX' && (
              <div>
                <label className="block text-xs font-semibold text-[#9a8cbf] uppercase tracking-wider mb-2">Priorität</label>
                <input
                  type="number"
                  value={rForm.priority}
                  onChange={(e) => setRForm((f) => ({ ...f, priority: parseInt(e.target.value) || 10 }))}
                  min={0} max={65535}
                  className="w-full px-3 py-2 rounded-xl bg-[#080612] border border-[#2a1f42] text-[#f0eeff] text-sm focus:outline-none focus:border-violet-500 transition-colors"
                />
              </div>
            )}

            {rForm.type === 'SRV' && (
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-[#9a8cbf] uppercase tracking-wider mb-2">Prio</label>
                  <input type="number" value={rForm.priority} onChange={(e) => setRForm((f) => ({ ...f, priority: parseInt(e.target.value) || 0 }))} className="w-full px-3 py-2 rounded-xl bg-[#080612] border border-[#2a1f42] text-[#f0eeff] text-sm focus:outline-none focus:border-violet-500 transition-colors" />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-[#9a8cbf] uppercase tracking-wider mb-2">Gewicht</label>
                  <input type="number" value={rForm.weight} onChange={(e) => setRForm((f) => ({ ...f, weight: parseInt(e.target.value) || 10 }))} className="w-full px-3 py-2 rounded-xl bg-[#080612] border border-[#2a1f42] text-[#f0eeff] text-sm focus:outline-none focus:border-violet-500 transition-colors" />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-[#9a8cbf] uppercase tracking-wider mb-2">Port</label>
                  <input type="number" value={rForm.port} onChange={(e) => setRForm((f) => ({ ...f, port: parseInt(e.target.value) || 443 }))} className="w-full px-3 py-2 rounded-xl bg-[#080612] border border-[#2a1f42] text-[#f0eeff] text-sm focus:outline-none focus:border-violet-500 transition-colors" />
                </div>
              </div>
            )}

            {rForm.type === 'CAA' && (
              <div>
                <label className="block text-xs font-semibold text-[#9a8cbf] uppercase tracking-wider mb-2">Tag</label>
                <select value={rForm.tag} onChange={(e) => setRForm((f) => ({ ...f, tag: e.target.value }))} className="w-full px-3 py-2 rounded-xl bg-[#080612] border border-[#2a1f42] text-[#f0eeff] text-sm focus:outline-none focus:border-violet-500 transition-colors">
                  <option value="issue">issue</option>
                  <option value="issuewild">issuewild</option>
                  <option value="iodef">iodef</option>
                </select>
              </div>
            )}

            <div className="flex gap-3 pt-2">
              <button
                onClick={() => setRecordModalOpen(false)}
                disabled={savingRecord}
                className="flex-1 px-4 py-2 rounded-xl border border-[#2a1f42] text-[#9a8cbf] text-sm hover:text-[#f0eeff] hover:border-[#6b5f8a] disabled:opacity-50 transition-colors"
              >
                Abbrechen
              </button>
              <MovingBorderButton onClick={handleSaveRecord} disabled={savingRecord} className="flex-1">
                {savingRecord
                  ? <span className="flex items-center justify-center gap-2"><span className="inline-block w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" /> Speichert …</span>
                  : editingRecord ? 'Speichern' : 'Hinzufügen'}
              </MovingBorderButton>
            </div>
          </div>
        </AnimatedModal>
      </>
    )
  }

  // Zone List View
  return (
    <>
      <Topbar title="Zonen" />
      <div className="p-4 lg:p-6 space-y-5">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-[#f0eeff]">Zonen</h2>
            <p className="text-xs text-[#6b5f8a]">
              {zoneList.length} autoritative DNS-Zone{zoneList.length !== 1 ? 'n' : ''}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setImportOpen(true)}
              className="text-xs text-[#9a8cbf] hover:text-[#f0eeff] px-3 py-1.5 rounded-lg border border-[#2a1f42] hover:border-[#6b5f8a] transition-colors"
            >
              ↑ Importieren
            </button>
            <MovingBorderButton onClick={() => setAddZoneOpen(true)}>+ Zone hinzufügen</MovingBorderButton>
          </div>
        </div>

        <div className="bg-[#100c1e] neon-card rounded-2xl overflow-hidden">
          {zoneList.length > 0 ? (
            <div className="divide-y divide-[#080612]">
              {zoneList.map((z) => {
                const isDeletingThis = deletingZone === z.domain
                return (
                <div
                  key={z.domain}
                  className="flex items-center justify-between px-5 py-4 hover:bg-[#1a1230] transition-colors"
                >
                  <div
                    className="flex-1 cursor-pointer"
                    onClick={() => openZoneDetail(z.domain)}
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-violet-400">{z.domain}</span>
                      {z.view && (
                        <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold bg-violet-900/40 text-violet-400 border border-violet-500/30">
                          {z.view}
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-[#6b5f8a] mt-0.5">
                      {(z.records ?? []).length} Records · TTL {z.ttl ?? 3600}s
                      {z.ttl_override ? ` · Override ${z.ttl_override}s` : ''}{' '}
                      {(z.records ?? [])
                        .slice(0, 4)
                        .map((r) => (
                          <span
                            key={r.id}
                            className="inline-flex items-center px-1.5 py-0 rounded text-[10px] font-bold ml-1"
                            style={{
                              background: (RECORD_TYPE_COLORS[r.type] ?? '#5a5a72') + '25',
                              color: RECORD_TYPE_COLORS[r.type] ?? '#9a8cbf',
                            }}
                          >
                            {r.type}
                          </span>
                        ))}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 ml-4">
                    <button
                      onClick={() => openZoneDetail(z.domain)}
                      disabled={isDeletingThis}
                      className="text-xs text-[#9a8cbf] hover:text-[#f0eeff] disabled:opacity-50 px-2 py-1 rounded border border-[#2a1f42] hover:border-[#6b5f8a] transition-colors"
                    >
                      Records
                    </button>
                    <button
                      onClick={() => handleDeleteZone(z.domain)}
                      disabled={isDeletingThis}
                      className="min-w-[60px] flex items-center justify-center gap-1 text-xs text-red-400 hover:text-red-300 disabled:opacity-50 disabled:cursor-wait px-2 py-1 rounded border border-red-500/30 hover:border-red-400/50 transition-colors"
                    >
                      {isDeletingThis
                        ? <><span className="inline-block w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" /> …</>
                        : 'Löschen'}
                    </button>
                  </div>
                </div>
                )
              })}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-16 gap-3">
              <div className="text-3xl">🌐</div>
              <div className="text-sm font-medium text-[#f0eeff]">Noch keine Zonen</div>
              <div className="text-xs text-[#6b5f8a]">
                Erstellen Sie eine autoritative Zone, um DNS-Records zu verwalten.
              </div>
              <MovingBorderButton onClick={() => setAddZoneOpen(true)} className="mt-2">
                + Zone hinzufügen
              </MovingBorderButton>
            </div>
          )}
        </div>

        {/* Import Modal */}
        <AnimatedModal
          isOpen={importOpen}
          onClose={() => { setImportOpen(false); setImportFile(null) }}
          title="Zone importieren"
        >
          <div className="space-y-4">
            {/* Tabs */}
            <div className="flex gap-1 bg-[#080612] rounded-xl p-1">
              {(['file', 'axfr'] as const).map((tab) => (
                <button
                  key={tab}
                  onClick={() => setImportTab(tab)}
                  className={`flex-1 py-1.5 text-xs font-semibold rounded-lg transition-colors ${
                    importTab === tab
                      ? 'bg-violet-600/30 text-violet-300 border border-violet-500/50'
                      : 'text-[#6b5f8a] hover:text-[#9a8cbf]'
                  }`}
                >
                  {tab === 'file' ? 'Zone File' : 'AXFR Transfer'}
                </button>
              ))}
            </div>

            {importTab === 'file' ? (
              <>
                <div>
                  <label className="block text-xs font-semibold text-[#9a8cbf] uppercase tracking-wider mb-2">
                    Zone-Datei *
                  </label>
                  <input
                    type="file"
                    accept=".zone,.txt,text/plain"
                    onChange={(e) => setImportFile(e.target.files?.[0] ?? null)}
                    className="w-full text-sm text-[#9a8cbf] file:mr-3 file:px-3 file:py-1 file:rounded-lg file:border file:border-[#2a1f42] file:bg-[#100c1e] file:text-[#9a8cbf] file:text-xs file:cursor-pointer hover:file:text-[#f0eeff] transition-colors cursor-pointer"
                  />
                  <p className="text-xs text-[#6b5f8a] mt-1">RFC 1035 Zonendatei (BIND-Format, z.B. example.zone)</p>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-[#9a8cbf] uppercase tracking-wider mb-2">
                    Domain (optional)
                  </label>
                  <input
                    value={importDomain}
                    onChange={(e) => setImportDomain(e.target.value)}
                    placeholder="example.com — wird aus SOA ermittelt"
                    className="w-full px-3 py-2 rounded-xl bg-[#080612] border border-[#2a1f42] text-[#f0eeff] text-sm focus:outline-none focus:border-violet-500 transition-colors placeholder-[#6b5f8a]"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-[#9a8cbf] uppercase tracking-wider mb-2">
                    View (optional)
                  </label>
                  <input
                    value={importView}
                    onChange={(e) => setImportView(e.target.value)}
                    placeholder="internal"
                    className="w-full px-3 py-2 rounded-xl bg-[#080612] border border-[#2a1f42] text-[#f0eeff] text-sm focus:outline-none focus:border-violet-500 transition-colors placeholder-[#6b5f8a]"
                  />
                </div>
                <div className="flex gap-3 pt-1">
                  <button
                    onClick={() => { setImportOpen(false); setImportFile(null) }}
                    disabled={importing}
                    className="flex-1 px-4 py-2 rounded-xl border border-[#2a1f42] text-[#9a8cbf] text-sm hover:text-[#f0eeff] disabled:opacity-50 transition-colors"
                  >
                    Abbrechen
                  </button>
                  <MovingBorderButton onClick={handleImportFile} disabled={importing || !importFile} className="flex-1">
                    {importing
                      ? <span className="flex items-center justify-center gap-2"><span className="inline-block w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" /> Importiert …</span>
                      : 'Zone importieren'}
                  </MovingBorderButton>
                </div>
              </>
            ) : (
              <>
                <div>
                  <label className="block text-xs font-semibold text-[#9a8cbf] uppercase tracking-wider mb-2">
                    DNS-Server *
                  </label>
                  <input
                    value={axfrServer}
                    onChange={(e) => setAxfrServer(e.target.value)}
                    placeholder="192.168.1.1 oder 192.168.1.1:53"
                    className="w-full px-3 py-2 rounded-xl bg-[#080612] border border-[#2a1f42] text-[#f0eeff] text-sm focus:outline-none focus:border-violet-500 transition-colors placeholder-[#6b5f8a]"
                  />
                  <p className="text-xs text-[#6b5f8a] mt-1">IP oder Hostname des Quell-DNS-Servers (Standard: Port 53)</p>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-[#9a8cbf] uppercase tracking-wider mb-2">
                    Domain *
                  </label>
                  <input
                    value={axfrDomain}
                    onChange={(e) => setAxfrDomain(e.target.value)}
                    placeholder="example.com"
                    className="w-full px-3 py-2 rounded-xl bg-[#080612] border border-[#2a1f42] text-[#f0eeff] text-sm focus:outline-none focus:border-violet-500 transition-colors placeholder-[#6b5f8a]"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-[#9a8cbf] uppercase tracking-wider mb-2">
                    View (optional)
                  </label>
                  <input
                    value={axfrView}
                    onChange={(e) => setAxfrView(e.target.value)}
                    placeholder="internal"
                    className="w-full px-3 py-2 rounded-xl bg-[#080612] border border-[#2a1f42] text-[#f0eeff] text-sm focus:outline-none focus:border-violet-500 transition-colors placeholder-[#6b5f8a]"
                  />
                </div>
                <div className="flex gap-3 pt-1">
                  <button
                    onClick={() => setImportOpen(false)}
                    disabled={importing}
                    className="flex-1 px-4 py-2 rounded-xl border border-[#2a1f42] text-[#9a8cbf] text-sm hover:text-[#f0eeff] disabled:opacity-50 transition-colors"
                  >
                    Abbrechen
                  </button>
                  <MovingBorderButton onClick={handleImportAXFR} disabled={importing || !axfrServer.trim() || !axfrDomain.trim()} className="flex-1">
                    {importing
                      ? <span className="flex items-center justify-center gap-2"><span className="inline-block w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" /> Überträgt …</span>
                      : 'AXFR starten'}
                  </MovingBorderButton>
                </div>
              </>
            )}
          </div>
        </AnimatedModal>

        {/* Add Zone Modal */}
        <AnimatedModal
          isOpen={addZoneOpen}
          onClose={() => setAddZoneOpen(false)}
          title="Zone hinzufügen"
        >
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-[#9a8cbf] uppercase tracking-wider mb-2">
                Domain *
              </label>
              <input
                value={zoneDomain}
                onChange={(e) => setZoneDomain(e.target.value)}
                placeholder="example.com"
                autoFocus
                className="w-full px-3 py-2 rounded-xl bg-[#080612] border border-[#2a1f42] text-[#f0eeff] text-sm focus:outline-none focus:border-violet-500 transition-colors"
              />
              <p className="text-xs text-[#6b5f8a] mt-1">z.B. example.com oder intern.home.lab</p>
            </div>
            <div>
              <label className="block text-xs font-semibold text-[#9a8cbf] uppercase tracking-wider mb-2">
                View (optional)
              </label>
              <input
                value={zoneView}
                onChange={(e) => setZoneView(e.target.value)}
                placeholder="internal"
                className="w-full px-3 py-2 rounded-xl bg-[#080612] border border-[#2a1f42] text-[#f0eeff] text-sm focus:outline-none focus:border-violet-500 transition-colors"
              />
              <p className="text-xs text-[#6b5f8a] mt-1">
                Split-Horizon: View-Name z.B. &quot;internal&quot;. Leer = global sichtbar.
              </p>
            </div>
            <div>
              <label className="block text-xs font-semibold text-[#9a8cbf] uppercase tracking-wider mb-2">
                Standard-TTL (Sekunden)
              </label>
              <input
                type="number"
                value={zoneTtl}
                onChange={(e) => setZoneTtl(parseInt(e.target.value) || 3600)}
                min={60}
                className="w-full px-3 py-2 rounded-xl bg-[#080612] border border-[#2a1f42] text-[#f0eeff] text-sm focus:outline-none focus:border-violet-500 transition-colors"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-[#9a8cbf] uppercase tracking-wider mb-2">
                TTL-Override (optional, Sekunden)
              </label>
              <input
                type="number"
                value={zoneTtlOverride || ''}
                onChange={(e) => setZoneTtlOverride(parseInt(e.target.value) || 0)}
                min={60}
                placeholder="Leer = kein Override"
                className="w-full px-3 py-2 rounded-xl bg-[#080612] border border-[#2a1f42] text-[#f0eeff] text-sm focus:outline-none focus:border-violet-500 transition-colors placeholder-[#6b5f8a]"
              />
              <p className="text-xs text-[#6b5f8a] mt-1">
                Normalisiert TTL aller Antworten dieser Zone. Nützlich für Clients mit TTL-Problemen.
              </p>
            </div>
            <div className="flex gap-3 pt-2">
              <button
                onClick={() => setAddZoneOpen(false)}
                disabled={addingZone}
                className="flex-1 px-4 py-2 rounded-xl border border-[#2a1f42] text-[#9a8cbf] text-sm hover:text-[#f0eeff] disabled:opacity-50 transition-colors"
              >
                Abbrechen
              </button>
              <MovingBorderButton onClick={handleAddZone} disabled={addingZone} className="flex-1">
                {addingZone
                  ? <span className="flex items-center justify-center gap-2"><span className="inline-block w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" /> Erstellt …</span>
                  : 'Zone erstellen'}
              </MovingBorderButton>
            </div>
          </div>
        </AnimatedModal>
      </div>
    </>
  )
}

export default function ZonesPage() {
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center h-64">
        <div className="w-6 h-6 border-2 border-violet-500 border-t-transparent rounded-full animate-spin" />
      </div>
    }>
      <ZonesContent />
    </Suspense>
  )
}
