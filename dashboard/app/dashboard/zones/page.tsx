'use client'

import { useEffect, useState, useCallback, Suspense } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { Topbar } from '@/components/layout/Topbar'
import { AnimatedModal } from '@/components/ui/animated-modal'
import { MovingBorderButton } from '@/components/ui/moving-border'
import { useToast } from '@/components/shared/Toast'
import { zones as zonesApi, records as recordsApi, type Zone, type DnsRecord, type ImportResult, type SOA, type CreateRecordResponse } from '@/lib/api'
import { formatRecordValue, RECORD_TYPE_COLORS } from '@/lib/utils'
import { useZones } from '@/lib/hooks/useZones'

const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'PTR', 'CAA', 'FWD']

function nextSerial(current: number): number {
  const today = new Date()
  const base = parseInt(
    `${today.getFullYear()}${String(today.getMonth() + 1).padStart(2, '0')}${String(today.getDate()).padStart(2, '0')}00`
  )
  return Math.max(current + 1, base)
}

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

  const zonesState = useZones()
  const zoneList = zonesState.data ?? []
  const loading = zonesState.loading
  const [selectedZone, setSelectedZone] = useState<Zone | null>(null)

  // Loading states for actions
  const [addingZone, setAddingZone] = useState(false)
  const [deletingZone, setDeletingZone] = useState<string | null>(null)
  const [savingRecord, setSavingRecord] = useState(false)
  const [deletingRecord, setDeletingRecord] = useState<number | null>(null)
  const [exportingZone, setExportingZone] = useState(false)
  const [importing, setImporting] = useState(false)
  const [savingSOA, setSavingSOA] = useState(false)

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

  // SOA Modal
  const [soaModalOpen, setSOAModalOpen] = useState(false)
  const [soaForm, setSOAForm] = useState<SOA>({
    mname: '',
    rname: '',
    serial: 0,
    refresh: 3600,
    retry: 1800,
    expire: 604800,
    minimum: 300,
  })

  // Record Modal
  const [recordModalOpen, setRecordModalOpen] = useState(false)
  const [editingRecord, setEditingRecord] = useState<DnsRecord | null>(null)
  const [recordDomain, setRecordDomain] = useState('')
  const [autoPtr, setAutoPtr] = useState(true)
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

  const loadZones = zonesState.refetch

  const loadZoneDetail = useCallback(
    async (domain: string, view?: string) => {
      try {
        const res = view
          ? await zonesApi.getView(domain, view)
          : await zonesApi.get(domain)
        setSelectedZone(res.data)
      } catch {
        showToast('Zone nicht gefunden', 'error')
      }
    },
    [showToast]
  )

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
    setAutoPtr(true)
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
        const useAutoPtr = autoPtr && (rForm.type === 'A' || rForm.type === 'AAAA')
        const res = await recordsApi.create(recordDomain, payload, useAutoPtr || undefined)
        const data = (res as { data: CreateRecordResponse | DnsRecord }).data
        if (useAutoPtr && data && 'ptr' in data && data.ptr) {
          if (data.ptr.created) {
            const zoneMsg = data.ptr.zone_created ? ` (Zone ${data.ptr.reverse_zone} erstellt)` : ''
            showToast(`Record + PTR hinzugefügt${zoneMsg}`)
          } else {
            showToast(`Record hinzugefügt, PTR fehlgeschlagen: ${data.ptr.error ?? 'Unbekannt'}`, 'error')
          }
        } else {
          showToast('Record hinzugefügt')
        }
      }
      setRecordModalOpen(false)
      await loadZoneDetail(recordDomain, selectedZone?.view)
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
      await loadZoneDetail(domain, selectedZone?.view)
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler', 'error')
    } finally {
      setDeletingRecord(null)
    }
  }

  const openSOAModal = () => {
    if (!selectedZone?.soa) return
    setSOAForm({ ...selectedZone.soa })
    setSOAModalOpen(true)
  }

  const handleSaveSOA = async () => {
    if (savingSOA || !selectedZone) return
    setSavingSOA(true)
    try {
      const serial = nextSerial(selectedZone.soa?.serial ?? 0)
      await zonesApi.update(selectedZone.domain, {
        ...selectedZone,
        soa: { ...soaForm, serial },
      }, selectedZone.view)
      showToast('SOA gespeichert')
      setSOAModalOpen(false)
      await loadZoneDetail(selectedZone.domain, selectedZone.view)
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler beim Speichern', 'error')
    } finally {
      setSavingSOA(false)
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
        <div className="w-6 h-6 border-2 border-amber-500 border-t-transparent rounded-full animate-spin" />
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
            className="text-sm text-amber-400 hover:text-amber-400 flex items-center gap-1"
          >
            ← Zurück zu Zonen
          </button>

          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold text-[var(--text)]">{selectedZone.domain}</h2>
              <p className="text-xs text-[var(--muted)]">
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
                className="text-xs text-[var(--muted-2)] hover:text-[var(--text)] disabled:opacity-50 px-3 py-1.5 rounded-lg border border-[var(--border)] hover:border-[var(--muted)] transition-colors"
              >
                {exportingZone ? '…' : '↓ Export .zone'}
              </button>
              <MovingBorderButton onClick={() => openRecordModal(selectedZone.domain)}>
                + Record
              </MovingBorderButton>
            </div>
          </div>

          <div className="bg-[var(--surface-2)] neon-card rounded-2xl overflow-hidden">
            {(selectedZone.records ?? []).length > 0 || selectedZone.soa ? (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[var(--border)]">
                      {['Name', 'Typ', 'TTL', 'Wert', 'Aktionen'].map((h) => (
                        <th key={h} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-[var(--muted-2)]">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--surface)]">
                    {selectedZone.soa && (
                      <tr className="bg-amber-500/5 hover:bg-amber-500/10 transition-colors">
                        <td className="px-4 py-3 font-mono text-xs text-[var(--text)]">@</td>
                        <td className="px-4 py-3">
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-bold bg-amber-500/20 text-amber-400">
                            SOA
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs text-[var(--muted)]">{selectedZone.soa.minimum}s</td>
                        <td className="px-4 py-3 font-mono text-xs text-[var(--muted)] max-w-xs truncate">
                          {selectedZone.soa.mname} {selectedZone.soa.rname}{' '}
                          <span className="text-[var(--muted-2)]">(Serial: {selectedZone.soa.serial})</span>
                        </td>
                        <td className="px-4 py-3">
                          <button
                            onClick={openSOAModal}
                            className="text-xs text-[var(--muted-2)] hover:text-[var(--text)] px-2 py-1 rounded border border-[var(--border)] hover:border-[var(--muted)] transition-colors"
                          >
                            Bearbeiten
                          </button>
                        </td>
                      </tr>
                    )}
                    {(selectedZone.records ?? []).map((r) => {
                      const isDeletingThis = deletingRecord === r.id
                      return (
                      <tr key={r.id} className="hover:bg-[var(--surface-3)] transition-colors">
                        <td className="px-4 py-3 font-mono text-xs text-[var(--text)]">{r.name ?? '@'}</td>
                        <td className="px-4 py-3">
                          <span
                            className="inline-flex items-center px-2 py-0.5 rounded text-xs font-bold"
                            style={{
                              background: (RECORD_TYPE_COLORS[r.type] ?? '#5a5a72') + '25',
                              color: RECORD_TYPE_COLORS[r.type] ?? '#9A9AAE',
                            }}
                          >
                            {r.type}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs text-[var(--muted)]">{r.ttl}s</td>
                        <td className="px-4 py-3 font-mono text-xs text-[var(--text)] max-w-xs truncate">
                          {formatRecordValue(r)}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => openRecordModal(selectedZone.domain, r)}
                              disabled={isDeletingThis}
                              className="text-xs text-[var(--muted-2)] hover:text-[var(--text)] disabled:opacity-50 px-2 py-1 rounded border border-[var(--border)] hover:border-[var(--muted)] transition-colors"
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
                <div className="text-sm font-medium text-[var(--text)]">Keine Records</div>
                <div className="text-xs text-[var(--muted)]">Füge den ersten DNS-Record hinzu.</div>
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
              <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">
                Name (@ = Zone-Apex)
              </label>
              <input
                value={rForm.name}
                onChange={(e) => setRForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="@ oder www"
                readOnly={rForm.type === 'FWD'}
                className="w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors read-only:opacity-60 read-only:cursor-not-allowed"
              />
              <p className="text-xs text-[var(--muted)] mt-1">@ = Zone selbst, sonst Subdomain</p>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">Typ</label>
                <select
                  value={rForm.type}
                  onChange={(e) => setRForm((f) => ({ ...f, type: e.target.value }))}
                  className="w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors"
                >
                  {RECORD_TYPES.map((t) => (
                    <option key={t} value={t}>{t}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">TTL (s)</label>
                <input
                  type="number"
                  value={rForm.ttl}
                  onChange={(e) => setRForm((f) => ({ ...f, ttl: parseInt(e.target.value) || 3600 }))}
                  min={60}
                  className="w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">
                Wert
              </label>
              <input
                value={rForm.value}
                onChange={(e) => setRForm((f) => ({ ...f, value: e.target.value }))}
                placeholder={TYPE_HINTS[rForm.type] ?? 'Wert'}
                className="w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors"
              />
              <p className="text-xs text-[var(--muted)] mt-1">{TYPE_HINTS[rForm.type] ?? ''}</p>
            </div>

            {rForm.type === 'MX' && (
              <div>
                <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">Priorität</label>
                <input
                  type="number"
                  value={rForm.priority}
                  onChange={(e) => setRForm((f) => ({ ...f, priority: parseInt(e.target.value) || 10 }))}
                  min={0} max={65535}
                  className="w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors"
                />
              </div>
            )}

            {rForm.type === 'SRV' && (
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">Prio</label>
                  <input type="number" value={rForm.priority} onChange={(e) => setRForm((f) => ({ ...f, priority: parseInt(e.target.value) || 0 }))} className="w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors" />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">Gewicht</label>
                  <input type="number" value={rForm.weight} onChange={(e) => setRForm((f) => ({ ...f, weight: parseInt(e.target.value) || 10 }))} className="w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors" />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">Port</label>
                  <input type="number" value={rForm.port} onChange={(e) => setRForm((f) => ({ ...f, port: parseInt(e.target.value) || 443 }))} className="w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors" />
                </div>
              </div>
            )}

            {rForm.type === 'CAA' && (
              <div>
                <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">Tag</label>
                <select value={rForm.tag} onChange={(e) => setRForm((f) => ({ ...f, tag: e.target.value }))} className="w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors">
                  <option value="issue">issue</option>
                  <option value="issuewild">issuewild</option>
                  <option value="iodef">iodef</option>
                </select>
              </div>
            )}

            {!editingRecord && (rForm.type === 'A' || rForm.type === 'AAAA') && (
              <div className="flex items-center justify-between gap-4 py-2 border-t border-[var(--border)]">
                <div>
                  <div className="text-sm font-medium text-[var(--text)]">PTR automatisch erstellen</div>
                  <div className="text-xs text-[var(--muted)]">Erstellt Reverse-DNS-Eintrag (ggf. inkl. Reverse-Zone)</div>
                </div>
                <button
                  type="button"
                  onClick={() => setAutoPtr((v) => !v)}
                  disabled={savingRecord}
                  className={`relative inline-flex h-6 w-10 shrink-0 items-center rounded-full transition-colors disabled:opacity-50 ${autoPtr ? 'bg-amber-500' : 'bg-[var(--border)]'}`}
                >
                  <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${autoPtr ? 'translate-x-5' : 'translate-x-1'}`} />
                </button>
              </div>
            )}

            <div className="flex gap-3 pt-2">
              <button
                onClick={() => setRecordModalOpen(false)}
                disabled={savingRecord}
                className="flex-1 px-4 py-2 rounded-xl border border-[var(--border)] text-[var(--muted-2)] text-sm hover:text-[var(--text)] hover:border-[var(--muted)] disabled:opacity-50 transition-colors"
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

        {/* SOA Modal */}
        <AnimatedModal
          isOpen={soaModalOpen}
          onClose={() => setSOAModalOpen(false)}
          title={`SOA bearbeiten — ${selectedZone?.domain ?? ''}`}
        >
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="col-span-2">
                <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">
                  Primary Nameserver (MName)
                </label>
                <input
                  value={soaForm.mname}
                  onChange={(e) => setSOAForm((f) => ({ ...f, mname: e.target.value }))}
                  placeholder="ns1.example.com"
                  className="w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors"
                />
              </div>
              <div className="col-span-2">
                <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">
                  Responsible Mailbox (RName)
                </label>
                <input
                  value={soaForm.rname}
                  onChange={(e) => setSOAForm((f) => ({ ...f, rname: e.target.value }))}
                  placeholder="hostmaster.example.com"
                  className="w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">
                  Refresh (s)
                </label>
                <input
                  type="number"
                  value={soaForm.refresh}
                  onChange={(e) => setSOAForm((f) => ({ ...f, refresh: parseInt(e.target.value) || 3600 }))}
                  min={60}
                  className="w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">
                  Retry (s)
                </label>
                <input
                  type="number"
                  value={soaForm.retry}
                  onChange={(e) => setSOAForm((f) => ({ ...f, retry: parseInt(e.target.value) || 1800 }))}
                  min={60}
                  className="w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">
                  Expire (s)
                </label>
                <input
                  type="number"
                  value={soaForm.expire}
                  onChange={(e) => setSOAForm((f) => ({ ...f, expire: parseInt(e.target.value) || 604800 }))}
                  min={3600}
                  className="w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors"
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">
                  Minimum TTL (s)
                </label>
                <input
                  type="number"
                  value={soaForm.minimum}
                  onChange={(e) => setSOAForm((f) => ({ ...f, minimum: parseInt(e.target.value) || 300 }))}
                  min={0}
                  className="w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors"
                />
              </div>
            </div>

            <div className="rounded-xl bg-[var(--surface)] border border-[var(--border)] px-3 py-2 flex items-center justify-between">
              <span className="text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider">
                Serial (nach Speichern)
              </span>
              <span className="font-mono text-sm text-amber-400">
                {selectedZone?.soa ? nextSerial(selectedZone.soa.serial) : '—'}
              </span>
            </div>

            <div className="flex gap-3 pt-2">
              <button
                onClick={() => setSOAModalOpen(false)}
                disabled={savingSOA}
                className="flex-1 px-4 py-2 rounded-xl border border-[var(--border)] text-[var(--muted-2)] text-sm hover:text-[var(--text)] hover:border-[var(--muted)] disabled:opacity-50 transition-colors"
              >
                Abbrechen
              </button>
              <MovingBorderButton
                onClick={handleSaveSOA}
                disabled={savingSOA || !soaForm.mname.trim() || !soaForm.rname.trim()}
                className="flex-1"
              >
                {savingSOA
                  ? <span className="flex items-center justify-center gap-2"><span className="inline-block w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" /> Speichert …</span>
                  : 'Speichern'}
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
            <h2 className="text-base font-semibold text-[var(--text)]">Zonen</h2>
            <p className="text-xs text-[var(--muted)]">
              {zoneList.length} autoritative DNS-Zone{zoneList.length !== 1 ? 'n' : ''}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setImportOpen(true)}
              className="text-xs text-[var(--muted-2)] hover:text-[var(--text)] px-3 py-1.5 rounded-lg border border-[var(--border)] hover:border-[var(--muted)] transition-colors"
            >
              ↑ Importieren
            </button>
            <MovingBorderButton onClick={() => setAddZoneOpen(true)}>+ Zone hinzufügen</MovingBorderButton>
          </div>
        </div>

        <div className="bg-[var(--surface-2)] neon-card rounded-2xl overflow-hidden">
          {zoneList.length > 0 ? (
            <div className="divide-y divide-[var(--surface)]">
              {zoneList.map((z) => {
                const isDeletingThis = deletingZone === z.domain
                return (
                <div
                  key={z.domain}
                  className="flex items-center justify-between px-5 py-4 hover:bg-[var(--surface-3)] transition-colors"
                >
                  <div
                    className="flex-1 cursor-pointer"
                    onClick={() => openZoneDetail(z.domain)}
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-amber-400">{z.domain}</span>
                      {z.view && (
                        <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
                          {z.view}
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-[var(--muted)] mt-0.5">
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
                              color: RECORD_TYPE_COLORS[r.type] ?? '#9A9AAE',
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
                      className="text-xs text-[var(--muted-2)] hover:text-[var(--text)] disabled:opacity-50 px-2 py-1 rounded border border-[var(--border)] hover:border-[var(--muted)] transition-colors"
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
              <div className="text-sm font-medium text-[var(--text)]">Noch keine Zonen</div>
              <div className="text-xs text-[var(--muted)]">
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
            <div className="flex gap-1 bg-[var(--surface)] rounded-xl p-1">
              {(['file', 'axfr'] as const).map((tab) => (
                <button
                  key={tab}
                  onClick={() => setImportTab(tab)}
                  className={`flex-1 py-1.5 text-xs font-semibold rounded-lg transition-colors ${
                    importTab === tab
                      ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                      : 'text-[var(--muted)] hover:text-[var(--muted-2)]'
                  }`}
                >
                  {tab === 'file' ? 'Zone File' : 'AXFR Transfer'}
                </button>
              ))}
            </div>

            {importTab === 'file' ? (
              <>
                <div>
                  <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">
                    Zone-Datei *
                  </label>
                  <input
                    type="file"
                    accept=".zone,.txt,text/plain"
                    onChange={(e) => setImportFile(e.target.files?.[0] ?? null)}
                    className="w-full text-sm text-[var(--muted-2)] file:mr-3 file:px-3 file:py-1 file:rounded-lg file:border file:border-[var(--border)] file:bg-[var(--surface-2)] file:text-[var(--muted-2)] file:text-xs file:cursor-pointer hover:file:text-[var(--text)] transition-colors cursor-pointer"
                  />
                  <p className="text-xs text-[var(--muted)] mt-1">RFC 1035 Zonendatei (BIND-Format, z.B. example.zone)</p>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">
                    Domain (optional)
                  </label>
                  <input
                    value={importDomain}
                    onChange={(e) => setImportDomain(e.target.value)}
                    placeholder="example.com — wird aus SOA ermittelt"
                    className="w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors placeholder-[#5A5A6E]"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">
                    View (optional)
                  </label>
                  <input
                    value={importView}
                    onChange={(e) => setImportView(e.target.value)}
                    placeholder="internal"
                    className="w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors placeholder-[#5A5A6E]"
                  />
                </div>
                <div className="flex gap-3 pt-1">
                  <button
                    onClick={() => { setImportOpen(false); setImportFile(null) }}
                    disabled={importing}
                    className="flex-1 px-4 py-2 rounded-xl border border-[var(--border)] text-[var(--muted-2)] text-sm hover:text-[var(--text)] disabled:opacity-50 transition-colors"
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
                  <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">
                    DNS-Server *
                  </label>
                  <input
                    value={axfrServer}
                    onChange={(e) => setAxfrServer(e.target.value)}
                    placeholder="192.168.1.1 oder 192.168.1.1:53"
                    className="w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors placeholder-[#5A5A6E]"
                  />
                  <p className="text-xs text-[var(--muted)] mt-1">IP oder Hostname des Quell-DNS-Servers (Standard: Port 53)</p>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">
                    Domain *
                  </label>
                  <input
                    value={axfrDomain}
                    onChange={(e) => setAxfrDomain(e.target.value)}
                    placeholder="example.com"
                    className="w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors placeholder-[#5A5A6E]"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">
                    View (optional)
                  </label>
                  <input
                    value={axfrView}
                    onChange={(e) => setAxfrView(e.target.value)}
                    placeholder="internal"
                    className="w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors placeholder-[#5A5A6E]"
                  />
                </div>
                <div className="flex gap-3 pt-1">
                  <button
                    onClick={() => setImportOpen(false)}
                    disabled={importing}
                    className="flex-1 px-4 py-2 rounded-xl border border-[var(--border)] text-[var(--muted-2)] text-sm hover:text-[var(--text)] disabled:opacity-50 transition-colors"
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
              <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">
                Domain *
              </label>
              <input
                value={zoneDomain}
                onChange={(e) => setZoneDomain(e.target.value)}
                placeholder="example.com"
                autoFocus
                className="w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors"
              />
              <p className="text-xs text-[var(--muted)] mt-1">z.B. example.com oder intern.home.lab</p>
            </div>
            <div>
              <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">
                View (optional)
              </label>
              <input
                value={zoneView}
                onChange={(e) => setZoneView(e.target.value)}
                placeholder="internal"
                className="w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors"
              />
              <p className="text-xs text-[var(--muted)] mt-1">
                Split-Horizon: View-Name z.B. &quot;internal&quot;. Leer = global sichtbar.
              </p>
            </div>
            <div>
              <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">
                Standard-TTL (Sekunden)
              </label>
              <input
                type="number"
                value={zoneTtl}
                onChange={(e) => setZoneTtl(parseInt(e.target.value) || 3600)}
                min={60}
                className="w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">
                TTL-Override (optional, Sekunden)
              </label>
              <input
                type="number"
                value={zoneTtlOverride || ''}
                onChange={(e) => setZoneTtlOverride(parseInt(e.target.value) || 0)}
                min={60}
                placeholder="Leer = kein Override"
                className="w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors placeholder-[#5A5A6E]"
              />
              <p className="text-xs text-[var(--muted)] mt-1">
                Normalisiert TTL aller Antworten dieser Zone. Nützlich für Clients mit TTL-Problemen.
              </p>
            </div>
            <div className="flex gap-3 pt-2">
              <button
                onClick={() => setAddZoneOpen(false)}
                disabled={addingZone}
                className="flex-1 px-4 py-2 rounded-xl border border-[var(--border)] text-[var(--muted-2)] text-sm hover:text-[var(--text)] disabled:opacity-50 transition-colors"
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
        <div className="w-6 h-6 border-2 border-amber-500 border-t-transparent rounded-full animate-spin" />
      </div>
    }>
      <ZonesContent />
    </Suspense>
  )
}
