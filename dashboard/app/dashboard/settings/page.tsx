'use client'

import { useEffect, useState, useCallback, FormEvent } from 'react'
import { Topbar } from '@/components/layout/Topbar'
import { AnimatedModal } from '@/components/ui/animated-modal'
import { MovingBorderButton } from '@/components/ui/moving-border'
import { useToast } from '@/components/shared/Toast'
import { InfoTooltip } from '@/components/shared/InfoTooltip'
import { cn, fmtDate, BLOCKLIST_SUGGESTIONS } from '@/lib/utils'
import {
  config as configApi,
  auth as authApi,
  setApiKey,
  splitHorizon as splitHorizonApi,
  blocklist as blocklistApi,
  ddns as ddnsApi,
  listNamedAPIKeys,
  createNamedAPIKey,
  deleteNamedAPIKey,
  type Config,
  type SplitHorizonConfig,
  type AXFRConfig,
  type BlocklistUrl,
  type BlocklistPattern,
  type TSIGKey,
  type TSIGKeyCreateResponse,
  type NamedAPIKey,
  type CreateNamedAPIKeyResponse,
} from '@/lib/api'

// ─── Types ────────────────────────────────────────────────────────────────────

type MainTab = 'dns' | 'blocklist' | 'ddns' | 'split-horizon' | 'zone-transfer' | 'dhcp' | 'system' | 'security'
type BlocklistSubTab = 'urls' | 'blocked' | 'allowed' | 'whitelist-ips' | 'patterns'

const MAIN_TABS: { key: MainTab; label: string }[] = [
  { key: 'dns',           label: 'DNS Server' },
  { key: 'blocklist',     label: 'Blocklist' },
  { key: 'ddns',          label: 'DDNS' },
  { key: 'split-horizon', label: 'Split-Horizon' },
  { key: 'zone-transfer', label: 'Zone Transfer' },
  { key: 'dhcp',          label: 'DHCP Sync' },
  { key: 'system',        label: 'System' },
  { key: 'security',      label: 'Sicherheit' },
]

const BLOCKLIST_SUB_TABS: { key: BlocklistSubTab; label: string; info: string }[] = [
  { key: 'urls',          label: 'Quellen',          info: 'Abonnierte Blocklist-Quellen (EasyList, etc.). Werden automatisch aktualisiert.' },
  { key: 'blocked',       label: 'Blockiert',         info: 'Manuell gesperrte Domains, unabhängig von Blocklist-URLs.' },
  { key: 'allowed',       label: 'Whitelist',         info: 'Diese Domains werden nie blockiert, auch wenn sie in einer Blocklist stehen.' },
  { key: 'whitelist-ips', label: 'IP-Whitelist',      info: 'Client-IPs/Netze, für die die Blocklist komplett übersprungen wird.' },
  { key: 'patterns',      label: 'Muster',            info: 'Wildcard- und RegEx-Patterns blockieren ganze Domain-Gruppen.' },
]

// ─── Shared helper functions ─────────────────────────────────────────────────

const inputCls = 'w-full px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors'
const labelCls = 'flex items-center gap-1.5 text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2'

function Spinner() {
  return <span className="inline-block w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin" />
}

function Card({ title, subtitle, children, headerRight }: {
  title?: string; subtitle?: string; children: React.ReactNode; headerRight?: React.ReactNode
}) {
  return (
    <div className="bg-[var(--surface-2)] neon-card rounded-2xl overflow-hidden">
      {title && (
        <div className="flex items-start justify-between px-5 py-4 border-b border-[var(--border)]">
          <div>
            <h3 className="text-sm font-semibold text-[var(--text)]">{title}</h3>
            {subtitle && <p className="text-xs text-[var(--muted)] mt-0.5">{subtitle}</p>}
          </div>
          {headerRight}
        </div>
      )}
      <div className="p-5 space-y-4">{children}</div>
    </div>
  )
}

function ToggleSwitch({ checked, onChange, disabled }: {
  checked: boolean; onChange: (v: boolean) => void; disabled?: boolean
}) {
  return (
    <button
      type="button"
      onClick={() => onChange(!checked)}
      disabled={disabled}
      className={`relative inline-flex h-6 w-10 shrink-0 items-center rounded-full transition-colors disabled:opacity-50 ${checked ? 'bg-amber-500' : 'bg-[var(--border)]'}`}
    >
      <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${checked ? 'translate-x-5' : 'translate-x-1'}`} />
    </button>
  )
}

function FormToggle({ name, defaultChecked }: { name: string; defaultChecked?: boolean }) {
  return (
    <label className="relative inline-flex items-center cursor-pointer shrink-0">
      <input name={name} type="checkbox" defaultChecked={defaultChecked} className="sr-only peer" />
      <div className="w-10 h-6 bg-[var(--border)] rounded-full peer peer-checked:bg-amber-500 transition-colors after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:after:translate-x-4" />
    </label>
  )
}

function ToggleRow({ label, hint, tooltip, children }: {
  label: string; hint?: string; tooltip?: string; children: React.ReactNode
}) {
  return (
    <div className="flex items-center justify-between gap-4 py-3 border-t border-[var(--border)]">
      <div className="min-w-0">
        <div className="flex items-center gap-1.5 text-sm font-medium text-[var(--text)]">
          <span>{label}</span>
          {tooltip && <InfoTooltip text={tooltip} />}
        </div>
        {hint && <div className="text-xs text-[var(--muted)]">{hint}</div>}
      </div>
      {children}
    </div>
  )
}

// ─── DNS Server Tab ──────────────────────────────────────────────────────────

function DNSTab({ cfg, onSaved }: { cfg: Config; onSaved: () => void }) {
  const { showToast } = useToast()
  const [saving, setSaving] = useState(false)
  const dns = cfg.dnsserver ?? cfg.coredns ?? {}
  const cache = dns.cache ?? {}
  const doh = dns.doh ?? {}
  const dot = dns.dot ?? {}
  const cacheMax = ('max_entries' in cache ? cache.max_entries : undefined) ?? 10000
  const cacheTtl = ('default_ttl' in cache ? cache.default_ttl : undefined) ?? 3600

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    setSaving(true)
    const f = e.currentTarget
    const fd = new FormData(f)
    try {
      await configApi.patch({
        dnsserver: {
          listen: fd.get('dns_listen') as string,
          upstream: (fd.get('dns_upstream') as string).split(/[,\s]+/).filter(Boolean),
          cache: {
            enabled: (f.querySelector('[name=cache_enabled]') as HTMLInputElement)?.checked,
            max_entries: parseInt(fd.get('cache_max') as string) || undefined,
            default_ttl: parseInt(fd.get('cache_ttl') as string) || undefined,
          },
          doh: {
            enabled: (f.querySelector('[name=doh_enabled]') as HTMLInputElement)?.checked,
            path: (fd.get('doh_path') as string) || undefined,
          },
          dot: {
            enabled: (f.querySelector('[name=dot_enabled]') as HTMLInputElement)?.checked,
            listen: (fd.get('dot_listen') as string) || undefined,
            cert_file: (fd.get('dot_cert_file') as string) || undefined,
            key_file: (fd.get('dot_key_file') as string) || undefined,
          },
        },
      })
      showToast('DNS-Einstellungen gespeichert')
      onSaved()
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler', 'error')
    } finally {
      setSaving(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4 max-w-2xl">
      <Card title="Verbindung">
        <div>
          <label className={labelCls}>
            <span>Listen-Adresse</span>
            <InfoTooltip text="Netzwerk-Adresse und Port, auf dem der DNS-Server lauscht. [::]:53 = IPv4+IPv6." />
          </label>
          <input name="dns_listen" defaultValue={dns.listen ?? '[::]:53'} className={inputCls} />
          <p className="text-xs text-[var(--muted)] mt-1">[::]:53 für IPv4+IPv6 Dual-Stack</p>
        </div>
        <div>
          <label className={labelCls}>
            <span>Upstream-Resolver (kommagetrennt)</span>
            <InfoTooltip text="Externe DNS-Server für unbekannte Domains. Werden im Round-Robin rotiert." />
          </label>
          <input name="dns_upstream" defaultValue={(dns.upstream ?? []).join(', ') || '1.1.1.1, 8.8.8.8'} className={inputCls} />
          <p className="text-xs text-[var(--muted)] mt-1">Cloudflare: 1.1.1.1 · Google: 8.8.8.8 · Quad9: 9.9.9.9</p>
        </div>
      </Card>

      <Card title="Cache">
        <ToggleRow label="DNS Cache aktivieren" hint="LRU-Cache im RAM — reduziert Upstream-Anfragen drastisch" tooltip="Speichert Antworten im RAM für schnellere Auflösung.">
          <FormToggle name="cache_enabled" defaultChecked={!!cache.enabled} />
        </ToggleRow>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className={labelCls}>
              <span>Max. Einträge</span>
              <InfoTooltip text="~500 Bytes pro Eintrag (10k ≈ 5 MB RAM)." />
            </label>
            <input name="cache_max" type="number" defaultValue={cacheMax} min={100} className={inputCls} />
          </div>
          <div>
            <label className={labelCls}>
              <span>Standard-TTL (Sekunden)</span>
              <InfoTooltip text="Wie lange Antworten gecacht werden, falls kein TTL in der DNS-Antwort steht." />
            </label>
            <input name="cache_ttl" type="number" defaultValue={cacheTtl} min={60} className={inputCls} />
          </div>
        </div>
      </Card>

      <Card title="DNS over HTTPS (DoH) — RFC 8484">
        <ToggleRow label="DoH aktivieren" hint="DNS-Anfragen über HTTPS — Pfad ist öffentlich ohne Auth" tooltip="RFC 8484 DoH-Endpunkt.">
          <FormToggle name="doh_enabled" defaultChecked={!!doh.enabled} />
        </ToggleRow>
        <div>
          <label className={labelCls}><span>DoH-Pfad</span></label>
          <input name="doh_path" defaultValue={doh.path ?? '/dns-query'} className={inputCls} placeholder="/dns-query" />
          <p className="text-xs text-[var(--muted)] mt-1">Standard: /dns-query · Neustart erforderlich</p>
        </div>
      </Card>

      <Card title="DNS over TLS (DoT) — RFC 7858">
        <ToggleRow label="DoT aktivieren" hint="DNS-Anfragen über TLS auf Port 853 — TLS-Zertifikat erforderlich" tooltip="Verschlüsselt DNS-Anfragen über TLS.">
          <FormToggle name="dot_enabled" defaultChecked={!!dot.enabled} />
        </ToggleRow>
        <div>
          <label className={labelCls}><span>DoT-Listen-Adresse</span></label>
          <input name="dot_listen" defaultValue={dot.listen ?? '[::]:853'} className={inputCls} placeholder="[::]:853" />
          <p className="text-xs text-[var(--muted)] mt-1">Neustart erforderlich</p>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className={labelCls}>
              <span>TLS-Zertifikat (cert_file)</span>
              <InfoTooltip text="Pfad zum TLS-Zertifikat für DoT." />
            </label>
            <input name="dot_cert_file" defaultValue={dot.cert_file ?? ''} className={inputCls} placeholder="/etc/domudns/certs/dns.crt" />
          </div>
          <div>
            <label className={labelCls}>
              <span>TLS-Schlüssel (key_file)</span>
              <InfoTooltip text="Pfad zum TLS-Schlüssel für DoT." />
            </label>
            <input name="dot_key_file" defaultValue={dot.key_file ?? ''} className={inputCls} placeholder="/etc/domudns/certs/dns.key" />
          </div>
        </div>
      </Card>

      <MovingBorderButton type="submit" disabled={saving} className="px-6 py-2.5">
        {saving ? 'Speichern …' : 'DNS-Einstellungen speichern'}
      </MovingBorderButton>
    </form>
  )
}

// ─── Blocklist Tab ───────────────────────────────────────────────────────────

function BlocklistTab({ cfg, onSaved }: { cfg: Config; onSaved: () => void }) {
  const { showToast } = useToast()
  const [subTab, setSubTab] = useState<BlocklistSubTab>('urls')
  const [saving, setSaving] = useState(false)
  const bl = cfg.blocklist ?? {}

  const handleSaveConfig = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    setSaving(true)
    const f = e.currentTarget
    const fd = new FormData(f)
    try {
      await configApi.patch({
        blocklist: {
          enabled: (f.querySelector('[name=bl_enabled]') as HTMLInputElement)?.checked,
          fetch_interval: (fd.get('bl_interval') as string) || undefined,
          block_mode: (fd.get('bl_block_mode') as string) || undefined,
        },
      })
      showToast('Blocklist-Einstellungen gespeichert')
      onSaved()
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler', 'error')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-4 max-w-4xl">
      {/* Configuration */}
      <form onSubmit={handleSaveConfig}>
        <Card title="Konfiguration" subtitle="Globale Blocklist-Einstellungen">
          <ToggleRow label="Blocklist aktivieren" hint="Blockiert Werbung, Tracking und Malware-Domains" tooltip="Aktiviert/deaktiviert die Domain-Blocklist für alle DNS-Anfragen.">
            <FormToggle name="bl_enabled" defaultChecked={!!bl.enabled} />
          </ToggleRow>
          <div className="grid grid-cols-2 gap-4 pt-1">
            <div>
              <label className={labelCls}>
                <span>Abruf-Intervall</span>
                <InfoTooltip text="Wie oft Blocklist-Quellen neu heruntergeladen werden." />
              </label>
              <input name="bl_interval" defaultValue={bl.fetch_interval ?? '24h'} className={inputCls} />
              <p className="text-xs text-[var(--muted)] mt-1">z.B. 24h, 12h, 6h</p>
            </div>
            <div>
              <label className={labelCls}>
                <span>Block-Antwort</span>
                <InfoTooltip text="zero_ip gibt 0.0.0.0/:: zurück. nxdomain bricht Browser sofort ab — kein TLS-Timeout." />
              </label>
              <select name="bl_block_mode" defaultValue={bl.block_mode ?? 'zero_ip'} className={inputCls}>
                <option value="zero_ip">zero_ip — 0.0.0.0 / :: zurückgeben</option>
                <option value="nxdomain">nxdomain — Domain existiert nicht</option>
              </select>
              <p className="text-xs text-[var(--muted)] mt-1">Live-Reload — kein Neustart nötig</p>
            </div>
          </div>
          <div className="pt-1">
            <MovingBorderButton type="submit" disabled={saving} className="px-5 py-2">
              {saving ? 'Speichern …' : 'Einstellungen speichern'}
            </MovingBorderButton>
          </div>
        </Card>
      </form>

      {/* Management Sub-Tabs */}
      <div>
        <div className="flex items-center gap-3 mb-3">
          <h3 className="text-sm font-semibold text-[var(--text)]">Verwaltung</h3>
        </div>
        <div className="overflow-x-auto pb-1">
          <div className="flex gap-1 bg-[var(--surface-2)] neon-card rounded-xl p-1 w-max">
            {BLOCKLIST_SUB_TABS.map((t) => (
              <button
                key={t.key}
                onClick={() => setSubTab(t.key)}
                className={cn(
                  'flex items-center gap-1.5 whitespace-nowrap px-3 py-1.5 rounded-lg text-sm font-medium transition-all',
                  subTab === t.key ? 'bg-amber-500/10 text-amber-400' : 'text-[var(--muted-2)] hover:text-[var(--text)]'
                )}
              >
                <span>{t.label}</span>
                <InfoTooltip text={t.info} />
              </button>
            ))}
          </div>
        </div>

        <div className="mt-4">
          {subTab === 'urls'          && <URLsTab />}
          {subTab === 'blocked'       && <DomainsTab mode="blocked" />}
          {subTab === 'allowed'       && <DomainsTab mode="allowed" />}
          {subTab === 'whitelist-ips' && <IPWhitelistTab />}
          {subTab === 'patterns'      && <PatternsTab />}
        </div>
      </div>
    </div>
  )
}

// ─── Blocklist Sub-Tabs ───────────────────────────────────────────────────────

function URLsTab() {
  const { showToast } = useToast()
  const [urls, setUrls] = useState<BlocklistUrl[]>([])
  const [loading, setLoading] = useState(true)
  const [addOpen, setAddOpen] = useState(false)
  const [newUrl, setNewUrl] = useState('')
  const [newEnabled, setNewEnabled] = useState(true)
  const [fetchingId, setFetchingId] = useState<number | null>(null)
  const [togglingId, setTogglingId] = useState<number | null>(null)
  const [deletingId, setDeletingId] = useState<number | null>(null)
  const [activatingUrl, setActivatingUrl] = useState<string | null>(null)
  const [adding, setAdding] = useState(false)

  const load = useCallback(async () => {
    try {
      const res = await blocklistApi.listUrls()
      setUrls(res.data ?? [])
    } catch { showToast('Fehler beim Laden', 'error') }
    finally { setLoading(false) }
  }, [showToast])

  useEffect(() => { load() }, [load])

  const handleAdd = async () => {
    if (adding) return
    setAdding(true)
    try {
      const res = await blocklistApi.addUrl({ url: newUrl.trim(), enabled: newEnabled })
      showToast('URL hinzugefügt')
      setAddOpen(false); setNewUrl('')
      if (newEnabled && res.data?.id) {
        showToast('Abruf läuft im Hintergrund …')
        try { await blocklistApi.fetchUrl(res.data.id) } catch {}
        showToast('Blocklist abgerufen')
      }
      await load()
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler', 'error')
    } finally { setAdding(false) }
  }

  const handleToggle = async (id: number, enabled: boolean) => {
    if (togglingId !== null) return
    setTogglingId(id)
    try {
      await blocklistApi.updateUrl(id, { enabled: !enabled })
      showToast(enabled ? 'Deaktiviert' : 'Aktiviert')
      await load()
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler', 'error')
    } finally { setTogglingId(null) }
  }

  const handleFetch = async (id: number) => {
    if (fetchingId !== null) return
    setFetchingId(id)
    showToast('Abruf läuft im Hintergrund …')
    try {
      await blocklistApi.fetchUrl(id)
      showToast('Blocklist abgerufen')
      await load()
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler', 'error')
    } finally { setFetchingId(null) }
  }

  const handleDelete = async (id: number) => {
    if (!confirm('URL löschen?')) return
    if (deletingId !== null) return
    setDeletingId(id)
    try {
      await blocklistApi.deleteUrl(id)
      showToast('URL gelöscht')
      await load()
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler', 'error')
    } finally { setDeletingId(null) }
  }

  const handleActivateSuggestion = async (s: typeof BLOCKLIST_SUGGESTIONS[0]) => {
    if (activatingUrl !== null) return
    setActivatingUrl(s.url)
    try {
      const existing = urls.find((u) => u.url === s.url)
      if (!existing) {
        const res = await blocklistApi.addUrl({ url: s.url, enabled: true })
        showToast('Blocklist hinzugefügt — Abruf läuft …')
        if (res.data?.id) { try { await blocklistApi.fetchUrl(res.data.id) } catch {} }
      } else if (!existing.enabled) {
        await blocklistApi.updateUrl(existing.id, { enabled: true })
      }
      showToast('Blocklist aktiviert')
      await load()
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler', 'error')
    } finally { setActivatingUrl(null) }
  }

  if (loading) return <div className="flex items-center justify-center h-32"><div className="w-6 h-6 border-2 border-amber-500 border-t-transparent rounded-full animate-spin" /></div>

  return (
    <div className="space-y-4">
      <div className="bg-[var(--surface-2)] neon-card rounded-2xl overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-[var(--border)]">
          <h3 className="text-sm font-semibold text-[var(--text)]">Beliebte Blocklisten</h3>
          <MovingBorderButton onClick={() => setAddOpen(true)}>+ URL hinzufügen</MovingBorderButton>
        </div>
        <div className="p-4 space-y-3">
          {BLOCKLIST_SUGGESTIONS.map((s) => {
            const ex = urls.find((u) => u.url === s.url)
            const isActive = ex?.enabled
            const isActivating = activatingUrl === s.url
            return (
              <div key={s.url} className="flex items-center justify-between gap-4 p-3 rounded-xl bg-[var(--surface)] border border-[var(--border)]">
                <div>
                  <div className="text-sm font-medium text-[var(--text)]">{s.name}</div>
                  <div className="text-xs text-[var(--muted)] mt-0.5">{s.desc}</div>
                </div>
                <button
                  onClick={() => !isActive && !isActivating && handleActivateSuggestion(s)}
                  disabled={!!isActive || isActivating}
                  className={cn('shrink-0 min-w-[90px] flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors',
                    isActive ? 'bg-green-500/15 text-green-400 cursor-default'
                    : isActivating ? 'bg-amber-500/10 text-amber-400 cursor-wait'
                    : 'bg-amber-500/10 text-amber-400 hover:bg-amber-500/10'
                  )}
                >
                  {isActivating ? <><Spinner /> Lädt …</> : isActive ? '✓ Aktiv' : 'Aktivieren'}
                </button>
              </div>
            )
          })}
        </div>
      </div>

      {urls.length > 0 && (
        <div className="bg-[var(--surface-2)] neon-card rounded-2xl overflow-hidden">
          <div className="px-5 py-4 border-b border-[var(--border)]">
            <h3 className="text-sm font-semibold text-[var(--text)]">{urls.length} konfigurierte URLs</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)]">
                  {['URL', 'Status', 'Letzter Abruf', 'Fehler', ''].map((h) => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-[var(--muted-2)]">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--surface)]">
                {urls.map((u) => {
                  const isFetching = fetchingId === u.id
                  const isToggling = togglingId === u.id
                  const isDeleting = deletingId === u.id
                  return (
                    <tr key={u.id} className="hover:bg-[var(--surface-3)] transition-colors">
                      <td className="px-4 py-3 max-w-xs">
                        <a href={u.url} target="_blank" rel="noopener noreferrer" className="text-amber-400 hover:text-amber-400 text-xs truncate block">{u.url}</a>
                      </td>
                      <td className="px-4 py-3">
                        <span className={cn('inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium', u.enabled ? 'bg-green-500/15 text-green-400' : 'bg-slate-500/15 text-slate-400')}>
                          {u.enabled ? 'Aktiv' : 'Inaktiv'}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-[var(--muted)]">
                        {isFetching ? <span className="flex items-center gap-1.5 text-amber-400"><Spinner /> Läuft …</span> : fmtDate(u.last_fetched_at)}
                      </td>
                      <td className="px-4 py-3 text-xs text-red-400 max-w-[120px] truncate">{u.last_error ?? ''}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5">
                          <button onClick={() => handleToggle(u.id, u.enabled)} disabled={isToggling || isFetching} className="min-w-[72px] flex items-center justify-center gap-1 text-xs text-[var(--muted-2)] hover:text-[var(--text)] disabled:opacity-50 px-2 py-1 rounded border border-[var(--border)] transition-colors">
                            {isToggling ? <><Spinner /> …</> : u.enabled ? 'Deakt.' : 'Aktivieren'}
                          </button>
                          <button onClick={() => handleFetch(u.id)} disabled={isFetching || isToggling} className="min-w-[72px] flex items-center justify-center gap-1 text-xs text-[var(--muted-2)] hover:text-[var(--text)] disabled:opacity-50 px-2 py-1 rounded border border-[var(--border)] transition-colors">
                            {isFetching ? <><Spinner /> Läuft …</> : 'Abrufen'}
                          </button>
                          <button onClick={() => handleDelete(u.id)} disabled={isDeleting || isFetching} className="min-w-[60px] flex items-center justify-center gap-1 text-xs text-red-400 hover:text-red-300 disabled:opacity-50 px-2 py-1 rounded border border-red-500/30 transition-colors">
                            {isDeleting ? <><Spinner /> …</> : 'Löschen'}
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <AnimatedModal isOpen={addOpen} onClose={() => setAddOpen(false)} title="Externe Blocklist hinzufügen">
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">URL</label>
            <input type="url" value={newUrl} onChange={(e) => setNewUrl(e.target.value)} placeholder="https://…" autoFocus className={inputCls} />
          </div>
          <label className="flex items-center gap-3 cursor-pointer">
            <input type="checkbox" checked={newEnabled} onChange={(e) => setNewEnabled(e.target.checked)} className="w-4 h-4" />
            <span className="text-sm text-[var(--muted-2)]">Sofort aktivieren &amp; abrufen</span>
          </label>
          <div className="flex gap-3 pt-2">
            <button onClick={() => setAddOpen(false)} disabled={adding} className="flex-1 px-4 py-2 rounded-xl border border-[var(--border)] text-[var(--muted-2)] text-sm hover:text-[var(--text)] disabled:opacity-50 transition-colors">Abbrechen</button>
            <MovingBorderButton onClick={handleAdd} disabled={adding} className="flex-1">
              {adding ? <span className="flex items-center justify-center gap-2"><Spinner /> Lädt …</span> : 'Hinzufügen'}
            </MovingBorderButton>
          </div>
        </div>
      </AnimatedModal>
    </div>
  )
}

function DomainsTab({ mode }: { mode: 'blocked' | 'allowed' }) {
  const { showToast } = useToast()
  const [domains, setDomains] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [addOpen, setAddOpen] = useState(false)
  const [newDomain, setNewDomain] = useState('')
  const [adding, setAdding] = useState(false)
  const [deletingDomain, setDeletingDomain] = useState<string | null>(null)
  const addLabel = mode === 'blocked' ? 'Domain blockieren' : 'Domain erlauben'
  const countLabel = mode === 'blocked' ? 'Blockierte' : 'Erlaubte'

  const load = useCallback(async () => {
    try {
      const res = mode === 'blocked' ? await blocklistApi.listDomains() : await blocklistApi.listAllowed()
      setDomains(res.data ?? [])
    } catch { showToast('Fehler beim Laden', 'error') }
    finally { setLoading(false) }
  }, [mode, showToast])

  useEffect(() => { load() }, [load])

  const handleAdd = async () => {
    if (adding) return
    setAdding(true)
    try {
      if (mode === 'blocked') await blocklistApi.addDomain(newDomain.trim())
      else await blocklistApi.addAllowed(newDomain.trim())
      showToast('Gespeichert')
      setAddOpen(false); setNewDomain('')
      await load()
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler', 'error')
    } finally { setAdding(false) }
  }

  const handleDelete = async (domain: string) => {
    if (!confirm(`Domain ${domain} entfernen?`)) return
    if (deletingDomain !== null) return
    setDeletingDomain(domain)
    try {
      if (mode === 'blocked') await blocklistApi.deleteDomain(domain)
      else await blocklistApi.deleteAllowed(domain)
      showToast('Entfernt')
      await load()
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler', 'error')
    } finally { setDeletingDomain(null) }
  }

  if (loading) return <div className="flex items-center justify-center h-32"><div className="w-6 h-6 border-2 border-amber-500 border-t-transparent rounded-full animate-spin" /></div>

  return (
    <div className="bg-[var(--surface-2)] neon-card rounded-2xl overflow-hidden">
      <div className="flex items-center justify-between px-5 py-4 border-b border-[var(--border)]">
        <h3 className="text-sm font-semibold text-[var(--text)]">{domains.length} {countLabel} Domains</h3>
        <MovingBorderButton onClick={() => setAddOpen(true)}>+ {addLabel}</MovingBorderButton>
      </div>
      {domains.length > 0 ? (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--border)]">
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-[var(--muted-2)]">Domain</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--surface)]">
              {domains.map((d) => (
                <tr key={d} className="hover:bg-[var(--surface-3)] transition-colors">
                  <td className="px-4 py-3 font-mono text-xs text-[var(--text)]">{d}</td>
                  <td className="px-4 py-3 text-right">
                    <button onClick={() => handleDelete(d)} disabled={deletingDomain === d} className="min-w-[80px] flex items-center justify-center gap-1 ml-auto text-xs text-red-400 hover:text-red-300 disabled:opacity-50 px-2 py-1 rounded border border-red-500/30 transition-colors">
                      {deletingDomain === d ? <><Spinner /> …</> : 'Entfernen'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="flex flex-col items-center justify-center py-12 gap-3">
          <div className="text-sm font-medium text-[var(--text)]">Keine Einträge</div>
          <MovingBorderButton onClick={() => setAddOpen(true)}>+ {addLabel}</MovingBorderButton>
        </div>
      )}
      <AnimatedModal isOpen={addOpen} onClose={() => setAddOpen(false)} title={addLabel}>
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">Domain</label>
            <input value={newDomain} onChange={(e) => setNewDomain(e.target.value)} placeholder="ads.example.com" autoFocus className={inputCls} />
          </div>
          <div className="flex gap-3 pt-2">
            <button onClick={() => setAddOpen(false)} disabled={adding} className="flex-1 px-4 py-2 rounded-xl border border-[var(--border)] text-[var(--muted-2)] text-sm hover:text-[var(--text)] disabled:opacity-50 transition-colors">Abbrechen</button>
            <MovingBorderButton onClick={handleAdd} disabled={adding} className="flex-1">
              {adding ? <span className="flex items-center justify-center gap-2"><Spinner /> Speichert …</span> : addLabel}
            </MovingBorderButton>
          </div>
        </div>
      </AnimatedModal>
    </div>
  )
}

function IPWhitelistTab() {
  const { showToast } = useToast()
  const [ips, setIps] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [addOpen, setAddOpen] = useState(false)
  const [newIP, setNewIP] = useState('')
  const [adding, setAdding] = useState(false)
  const [deletingIP, setDeletingIP] = useState<string | null>(null)

  const load = useCallback(async () => {
    try { const res = await blocklistApi.listWhitelistIPs(); setIps(res.data ?? []) }
    catch { showToast('Fehler beim Laden', 'error') }
    finally { setLoading(false) }
  }, [showToast])

  useEffect(() => { load() }, [load])

  const handleAdd = async () => {
    if (adding) return
    setAdding(true)
    try {
      await blocklistApi.addWhitelistIP(newIP.trim())
      showToast('IP hinzugefügt')
      setAddOpen(false); setNewIP('')
      await load()
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler', 'error')
    } finally { setAdding(false) }
  }

  const handleDelete = async (ip: string) => {
    if (!confirm(`IP ${ip} entfernen?`)) return
    if (deletingIP !== null) return
    setDeletingIP(ip)
    try {
      await blocklistApi.deleteWhitelistIP(ip)
      showToast('Entfernt')
      await load()
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler', 'error')
    } finally { setDeletingIP(null) }
  }

  if (loading) return <div className="flex items-center justify-center h-32"><div className="w-6 h-6 border-2 border-amber-500 border-t-transparent rounded-full animate-spin" /></div>

  return (
    <div className="bg-[var(--surface-2)] neon-card rounded-2xl overflow-hidden">
      <div className="flex items-center justify-between px-5 py-4 border-b border-[var(--border)]">
        <h3 className="text-sm font-semibold text-[var(--text)]">{ips.length} IP-Whitelist Einträge</h3>
        <MovingBorderButton onClick={() => setAddOpen(true)}>+ IP/CIDR hinzufügen</MovingBorderButton>
      </div>
      {ips.length > 0 ? (
        <div className="p-4 space-y-2">
          {ips.map((ip) => (
            <div key={ip} className="flex items-center justify-between px-4 py-3 bg-[var(--surface)] rounded-xl border border-[var(--border)]">
              <span className="font-mono text-sm text-[var(--text)]">{ip}</span>
              <button onClick={() => handleDelete(ip)} disabled={deletingIP === ip} className="min-w-[80px] flex items-center justify-center gap-1 text-xs text-red-400 hover:text-red-300 disabled:opacity-50 px-2 py-1 rounded border border-red-500/30 transition-colors">
                {deletingIP === ip ? <><Spinner /> …</> : 'Entfernen'}
              </button>
            </div>
          ))}
        </div>
      ) : (
        <div className="flex flex-col items-center justify-center py-12 gap-3 px-5">
          <div className="text-sm font-medium text-[var(--text)]">Keine IP-Whitelist</div>
          <div className="text-xs text-[var(--muted)] text-center">IPs in dieser Liste umgehen die Blocklist komplett.<br />Tipp: &bdquo;localhost&ldquo; fügt 127.0.0.1 und ::1 hinzu.</div>
          <MovingBorderButton onClick={() => setAddOpen(true)} className="mt-1">+ IP/CIDR hinzufügen</MovingBorderButton>
        </div>
      )}
      <AnimatedModal isOpen={addOpen} onClose={() => setAddOpen(false)} title="IP oder CIDR hinzufügen">
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">IP oder CIDR</label>
            <input value={newIP} onChange={(e) => setNewIP(e.target.value)} placeholder="localhost, 192.168.0.0/24, ::1" autoFocus className={inputCls} />
            <p className="text-xs text-[var(--muted)] mt-1">&bdquo;localhost&ldquo; → fügt 127.0.0.1 und ::1 hinzu</p>
          </div>
          <div className="flex gap-3 pt-2">
            <button onClick={() => setAddOpen(false)} disabled={adding} className="flex-1 px-4 py-2 rounded-xl border border-[var(--border)] text-[var(--muted-2)] text-sm hover:text-[var(--text)] disabled:opacity-50 transition-colors">Abbrechen</button>
            <MovingBorderButton onClick={handleAdd} disabled={adding} className="flex-1">
              {adding ? <span className="flex items-center justify-center gap-2"><Spinner /> Speichert …</span> : 'Hinzufügen'}
            </MovingBorderButton>
          </div>
        </div>
      </AnimatedModal>
    </div>
  )
}

function PatternsTab() {
  const { showToast } = useToast()
  const [patterns, setPatterns] = useState<BlocklistPattern[]>([])
  const [loading, setLoading] = useState(true)
  const [addOpen, setAddOpen] = useState(false)
  const [newPattern, setNewPattern] = useState('')
  const [newType, setNewType] = useState<'wildcard' | 'regex'>('wildcard')
  const [adding, setAdding] = useState(false)
  const [deletingId, setDeletingId] = useState<number | null>(null)

  const load = useCallback(async () => {
    try { const res = await blocklistApi.listPatterns(); setPatterns(res.data ?? []) }
    catch { showToast('Fehler beim Laden', 'error') }
    finally { setLoading(false) }
  }, [showToast])

  useEffect(() => { load() }, [load])

  const handleAdd = async () => {
    if (adding) return
    const val = newPattern.trim()
    if (!val) return
    if (newType === 'wildcard' && !val.startsWith('*.')) { showToast('Wildcard-Pattern muss mit "*." beginnen', 'error'); return }
    setAdding(true)
    try {
      await blocklistApi.addPattern({ pattern: val, type: newType })
      showToast('Pattern gespeichert')
      setAddOpen(false); setNewPattern(''); setNewType('wildcard')
      await load()
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler', 'error')
    } finally { setAdding(false) }
  }

  const handleDelete = async (id: number, pattern: string) => {
    if (!confirm(`Pattern "${pattern}" löschen?`)) return
    if (deletingId !== null) return
    setDeletingId(id)
    try {
      await blocklistApi.deletePattern(id)
      showToast('Pattern gelöscht')
      await load()
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler', 'error')
    } finally { setDeletingId(null) }
  }

  if (loading) return <div className="flex items-center justify-center h-32"><div className="w-6 h-6 border-2 border-amber-500 border-t-transparent rounded-full animate-spin" /></div>

  const wildcards = patterns.filter((p) => p.type === 'wildcard')
  const regexps   = patterns.filter((p) => p.type === 'regex')

  return (
    <div className="space-y-4">
      <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl px-4 py-3 text-xs text-amber-300 space-y-1">
        <div className="font-semibold text-amber-200">Muster-Blocking</div>
        <div><span className="font-mono text-amber-100">*.example.com</span> — blockiert alle Subdomains und die Domain selbst (Wildcard)</div>
        <div><span className="font-mono text-amber-100">/^ads[0-9]+\.com$/</span> — blockiert per regulärem Ausdruck (Go regexp, optional mit <span className="font-mono">/…/</span> Begrenzer)</div>
      </div>

      <div className="bg-[var(--surface-2)] neon-card rounded-2xl overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-[var(--border)]">
          <h3 className="text-sm font-semibold text-[var(--text)]">{patterns.length} Muster</h3>
          <MovingBorderButton onClick={() => setAddOpen(true)}>+ Muster hinzufügen</MovingBorderButton>
        </div>
        {patterns.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 gap-3">
            <div className="text-sm font-medium text-[var(--text)]">Keine Muster konfiguriert</div>
            <MovingBorderButton onClick={() => setAddOpen(true)} className="mt-1">+ Muster hinzufügen</MovingBorderButton>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)]">
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-[var(--muted-2)]">Muster</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-[var(--muted-2)]">Typ</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-[var(--muted-2)]">Erstellt</th>
                  <th className="px-4 py-3" />
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--surface)]">
                {patterns.map((p) => (
                  <tr key={p.id} className="hover:bg-[var(--surface-3)] transition-colors">
                    <td className="px-4 py-3 font-mono text-xs text-[var(--text)]">{p.pattern}</td>
                    <td className="px-4 py-3">
                      <span className={cn('inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium', p.type === 'wildcard' ? 'bg-amber-500/15 text-amber-300' : 'bg-orange-500/15 text-orange-300')}>
                        {p.type === 'wildcard' ? '✱ Wildcard' : '∕∕ Regex'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-[var(--muted)]">{new Date(p.created_at).toLocaleDateString('de-DE')}</td>
                    <td className="px-4 py-3 text-right">
                      <button onClick={() => handleDelete(p.id, p.pattern)} disabled={deletingId === p.id} className="min-w-[80px] flex items-center justify-center gap-1 ml-auto text-xs text-red-400 hover:text-red-300 disabled:opacity-50 px-2 py-1 rounded border border-red-500/30 transition-colors">
                        {deletingId === p.id ? <><Spinner /> …</> : 'Löschen'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {patterns.length > 0 && (
        <div className="grid grid-cols-2 gap-4 text-xs">
          <div className="bg-[var(--surface-2)] neon-card rounded-xl px-4 py-3">
            <div className="text-[var(--muted-2)] mb-1">Wildcard-Muster</div>
            <div className="text-2xl font-bold text-amber-400">{wildcards.length}</div>
          </div>
          <div className="bg-[var(--surface-2)] neon-card rounded-xl px-4 py-3">
            <div className="text-[var(--muted-2)] mb-1">RegEx-Muster</div>
            <div className="text-2xl font-bold text-orange-300">{regexps.length}</div>
          </div>
        </div>
      )}

      <AnimatedModal isOpen={addOpen} onClose={() => setAddOpen(false)} title="Muster hinzufügen">
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">Typ</label>
            <div className="flex gap-2">
              {(['wildcard', 'regex'] as const).map((t) => (
                <button key={t} onClick={() => { setNewType(t); setNewPattern(t === 'wildcard' ? '*.' : '/') }} className={cn('flex-1 py-2 rounded-xl text-sm font-medium border transition-colors', newType === t ? (t === 'wildcard' ? 'bg-amber-500/20 border-amber-500/50 text-amber-300' : 'bg-orange-500/20 border-orange-500/50 text-orange-300') : 'bg-[var(--surface)] border-[var(--border)] text-[var(--muted-2)] hover:text-[var(--text)]')}>
                  {t === 'wildcard' ? '✱ Wildcard' : '∕∕ Regex'}
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">Muster</label>
            <input value={newPattern} onChange={(e) => setNewPattern(e.target.value)} placeholder={newType === 'wildcard' ? '*.example.com' : '/^ads[0-9]+\\.com$/'} autoFocus className={cn(inputCls, 'font-mono')} />
            <p className="text-xs text-[var(--muted)] mt-1.5">
              {newType === 'wildcard' ? 'Beispiel: *.doubleclick.net blockiert foo.doubleclick.net und doubleclick.net' : 'Beispiel: /^ads[0-9]+\\.example\\.com$/ — Go regexp, / Begrenzer optional'}
            </p>
          </div>
          <div className="flex gap-3 pt-2">
            <button onClick={() => setAddOpen(false)} disabled={adding} className="flex-1 px-4 py-2 rounded-xl border border-[var(--border)] text-[var(--muted-2)] text-sm hover:text-[var(--text)] disabled:opacity-50 transition-colors">Abbrechen</button>
            <MovingBorderButton onClick={handleAdd} disabled={adding || !newPattern.trim()} className="flex-1">
              {adding ? <span className="flex items-center justify-center gap-2"><Spinner /> Speichert …</span> : 'Hinzufügen'}
            </MovingBorderButton>
          </div>
        </div>
      </AnimatedModal>
    </div>
  )
}

// ─── DDNS Tab ─────────────────────────────────────────────────────────────────

function DDNSTab() {
  const { showToast } = useToast()
  const [keys, setKeys] = useState<TSIGKey[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [newKey, setNewKey] = useState<TSIGKeyCreateResponse | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null)
  const [createName, setCreateName] = useState('')
  const [createAlgorithm, setCreateAlgorithm] = useState('hmac-sha256')
  const [creating, setCreating] = useState(false)
  const [createError, setCreateError] = useState('')
  const [copied, setCopied] = useState(false)

  const loadKeys = useCallback(async () => {
    try { const resp = await ddnsApi.listKeys(); setKeys(resp.data ?? []) }
    catch { showToast('Schlüssel konnten nicht geladen werden.', 'error') }
    finally { setLoading(false) }
  }, [showToast])

  useEffect(() => { loadKeys() }, [loadKeys])

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    setCreateError('')
    const trimmed = createName.trim()
    if (!trimmed) { setCreateError('Name ist erforderlich.'); return }
    setCreating(true)
    try {
      const resp = await ddnsApi.createKey({ name: trimmed, algorithm: createAlgorithm })
      setShowCreate(false)
      setCreateName('')
      setNewKey(resp.data)
      loadKeys()
    } catch (err: unknown) {
      setCreateError(err instanceof Error ? err.message : 'Fehler beim Erstellen.')
    } finally { setCreating(false) }
  }

  const handleDeleteConfirm = async () => {
    if (!deleteTarget) return
    try {
      await ddnsApi.deleteKey(deleteTarget)
      showToast(`Schlüssel "${deleteTarget}" gelöscht.`)
      setDeleteTarget(null)
      loadKeys()
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler beim Löschen.', 'error')
      setDeleteTarget(null)
    }
  }

  const handleCopySecret = () => {
    if (!newKey) return
    navigator.clipboard.writeText(newKey.secret).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  const fmtKeyDate = (iso: string) =>
    new Date(iso).toLocaleDateString('de-DE', { dateStyle: 'medium' }) + ' ' +
    new Date(iso).toLocaleTimeString('de-DE', { timeStyle: 'short' })

  return (
    <div className="space-y-4 max-w-4xl">
      {/* Key table */}
      <div className="bg-[var(--surface-2)] neon-card rounded-2xl overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-[var(--border)]">
          <div>
            <h3 className="text-sm font-semibold text-[var(--text)]">TSIG-Schlüssel</h3>
            <p className="text-xs text-[var(--muted)] mt-0.5">RFC 2136 — für ISC dhcpd und andere Dynamic-DNS-Clients</p>
          </div>
          <button onClick={() => setShowCreate(true)} className="flex items-center gap-2 px-4 py-2 rounded-xl bg-amber-500 hover:bg-amber-500 text-white text-sm font-medium transition-colors">
            <span>+</span> Neuer Schlüssel
          </button>
        </div>
        {loading ? (
          <div className="px-5 py-10 text-center text-[var(--muted)] text-sm">Lade …</div>
        ) : keys.length === 0 ? (
          <div className="px-5 py-10 text-center">
            <div className="text-3xl mb-3">⟳</div>
            <p className="text-[var(--muted)] text-sm">Keine Schlüssel vorhanden.</p>
            <p className="text-[var(--muted)] text-xs mt-1">Erstelle einen Schlüssel und trage ihn in die dhcpd.conf ein.</p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-[var(--muted-2)] uppercase border-b border-[var(--border)]">
                <th className="px-5 py-3 text-left font-medium">Name</th>
                <th className="px-5 py-3 text-left font-medium">Algorithmus</th>
                <th className="px-5 py-3 text-left font-medium">Erstellt</th>
                <th className="px-5 py-3 text-right font-medium" />
              </tr>
            </thead>
            <tbody>
              {keys.map((k) => (
                <tr key={k.name} className="border-b border-[var(--border)]/50 last:border-0 hover:bg-white/5 transition-colors">
                  <td className="px-5 py-3.5 font-mono text-[var(--text)]">{k.name}</td>
                  <td className="px-5 py-3.5 text-[var(--muted-2)]">{k.algorithm}</td>
                  <td className="px-5 py-3.5 text-[var(--muted)]">{fmtKeyDate(k.created_at)}</td>
                  <td className="px-5 py-3.5 text-right">
                    <button onClick={() => setDeleteTarget(k.name)} className="text-xs text-red-400 hover:text-red-300 hover:bg-red-900/20 px-2 py-1 rounded-lg transition-colors">Löschen</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* dhcpd example */}
      <div className="bg-[var(--surface-2)] neon-card rounded-2xl overflow-hidden">
        <div className="px-5 py-4 border-b border-[var(--border)]">
          <h3 className="text-sm font-semibold text-[var(--text)]">ISC dhcpd Konfigurationsbeispiel</h3>
          <p className="text-xs text-[var(--muted)] mt-0.5">Füge diese Konfiguration in <code className="text-amber-400">/etc/dhcp/dhcpd.conf</code> ein.</p>
        </div>
        <div className="px-5 py-4">
          <pre className="bg-[var(--surface)] text-[var(--muted-2)] rounded-xl px-4 py-4 text-xs font-mono border border-[var(--border)] overflow-x-auto leading-relaxed">{`# DDNS-Konfiguration aktivieren
ddns-updates on;
ddns-update-style interim;
update-static-leases on;
ignore client-updates;

# TSIG-Schlüssel (aus dem Dashboard)
key <name-aus-dashboard> {
  algorithm hmac-sha256;
  secret "<secret-aus-dashboard>";
}

# Zonen registrieren
zone home. {
  primary 192.0.2.1;   # IP dieses DNS-Servers
  key <name-aus-dashboard>;
}

# PTR-Records (Reverse-Zone)
zone 100.168.192.in-addr.arpa. {
  primary 192.0.2.1;
  key <name-aus-dashboard>;
}`}</pre>
        </div>
      </div>

      <div className="bg-blue-900/20 border border-blue-800/30 rounded-xl px-4 py-3 text-xs text-blue-300 leading-relaxed">
        <strong>Hinweis:</strong> Nach dem Erstellen wird das Secret nur einmalig angezeigt. DDNS-Updates werden ausschließlich mit gültigem TSIG-Schlüssel akzeptiert.
      </div>

      {/* Create modal */}
      <AnimatedModal isOpen={showCreate} onClose={() => { setShowCreate(false); setCreateError(''); setCreateName('') }} title="Neuen TSIG-Schlüssel erstellen">
        <form onSubmit={handleCreate} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">Name</label>
            <input type="text" value={createName} onChange={(e) => setCreateName(e.target.value)} placeholder="z.B. dhcp-dns" autoFocus className={inputCls} />
            <p className="text-xs text-[var(--muted)] mt-1">Muss mit dem Schlüsselnamen in der dhcpd.conf übereinstimmen.</p>
          </div>
          <div>
            <label className="block text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider mb-2">Algorithmus</label>
            <select value={createAlgorithm} onChange={(e) => setCreateAlgorithm(e.target.value)} className={inputCls}>
              <option value="hmac-sha256">HMAC-SHA256 (empfohlen)</option>
              <option value="hmac-sha512">HMAC-SHA512</option>
              <option value="hmac-sha1">HMAC-SHA1 (veraltet)</option>
            </select>
          </div>
          {createError && <p className="text-sm text-red-400 bg-red-900/20 border border-red-800/30 rounded-lg px-3 py-2">{createError}</p>}
          <div className="flex gap-3 pt-2">
            <button type="button" onClick={() => { setShowCreate(false); setCreateError(''); setCreateName('') }} className="flex-1 px-4 py-2 rounded-xl border border-[var(--border)] text-[var(--muted-2)] text-sm hover:text-[var(--text)] transition-colors">Abbrechen</button>
            <MovingBorderButton type="submit" disabled={creating} className="flex-1">
              {creating ? 'Erstellen …' : 'Erstellen'}
            </MovingBorderButton>
          </div>
        </form>
      </AnimatedModal>

      {/* Secret display */}
      {newKey && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="bg-[var(--surface-2)] neon-card rounded-2xl w-full max-w-xl shadow-2xl">
            <div className="px-6 py-5 border-b border-[var(--border)]">
              <h2 className="text-lg font-semibold text-[var(--text)]">TSIG-Schlüssel erstellt</h2>
              <p className="text-sm text-amber-400 mt-1 flex items-center gap-2"><span>⚠</span> Dieser Secret wird nur einmalig angezeigt — bitte jetzt sichern!</p>
            </div>
            <div className="px-6 py-5 space-y-4">
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div><div className="text-[var(--muted)] mb-1">Name</div><div className="text-[var(--text)] font-mono">{newKey.name}</div></div>
                <div><div className="text-[var(--muted)] mb-1">Algorithmus</div><div className="text-[var(--text)] font-mono">{newKey.algorithm}</div></div>
              </div>
              <div>
                <div className="text-[var(--muted)] text-sm mb-1">Secret (Base64)</div>
                <div className="flex items-center gap-2">
                  <code className="flex-1 bg-[var(--surface)] text-green-400 rounded-lg px-3 py-2 text-xs font-mono break-all border border-[var(--border)]">{newKey.secret}</code>
                  <button onClick={handleCopySecret} className="shrink-0 px-3 py-2 rounded-lg bg-[var(--border)] hover:bg-[#5A5A6E] text-[var(--muted-2)] text-xs transition-colors">
                    {copied ? '✓' : 'Kopieren'}
                  </button>
                </div>
              </div>
              <div>
                <div className="text-[var(--muted)] text-sm mb-1">ISC dhcpd Konfiguration</div>
                <pre className="bg-[var(--surface)] text-[var(--muted-2)] rounded-lg px-3 py-3 text-xs font-mono border border-[var(--border)] overflow-x-auto whitespace-pre-wrap">{`key ${newKey.name} {\n  algorithm ${newKey.algorithm};\n  secret "${newKey.secret}";\n}\n\nzone home. {\n  primary 192.0.2.1;\n  key ${newKey.name};\n}`}</pre>
              </div>
            </div>
            <div className="px-6 pb-5">
              <button onClick={() => setNewKey(null)} className="w-full px-4 py-2.5 rounded-xl bg-amber-500 hover:bg-amber-500 text-white text-sm font-medium transition-colors">Verstanden, Secret gesichert</button>
            </div>
          </div>
        </div>
      )}

      {/* Delete confirmation */}
      <AnimatedModal isOpen={!!deleteTarget} onClose={() => setDeleteTarget(null)} title="Schlüssel löschen?">
        <div className="space-y-4">
          <p className="text-sm text-[var(--muted-2)]">
            Der TSIG-Schlüssel <span className="font-mono text-[var(--text)]">&quot;{deleteTarget}&quot;</span> wird dauerhaft gelöscht. Clients, die diesen Schlüssel verwenden, können keine DNS-Updates mehr senden.
          </p>
          <div className="flex gap-3 pt-2">
            <button onClick={() => setDeleteTarget(null)} className="flex-1 px-4 py-2 rounded-xl border border-[var(--border)] text-[var(--muted-2)] text-sm hover:text-[var(--text)] transition-colors">Abbrechen</button>
            <button onClick={handleDeleteConfirm} className="flex-1 px-4 py-2.5 rounded-xl bg-red-700 hover:bg-red-600 text-white text-sm font-medium transition-colors">Löschen</button>
          </div>
        </div>
      </AnimatedModal>
    </div>
  )
}

// ─── Split-Horizon Tab ────────────────────────────────────────────────────────

function SplitHorizonTab() {
  const { showToast } = useToast()
  const [shConfig, setShConfig] = useState<SplitHorizonConfig>({ enabled: false, views: [] })
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [newName, setNewName] = useState('')
  const [newSubnets, setNewSubnets] = useState('')

  const load = useCallback(async () => {
    try {
      const res = await splitHorizonApi.get()
      setShConfig({ enabled: res.data?.enabled ?? false, views: res.data?.views ?? [] })
    } catch {} finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  const save = async (updated: SplitHorizonConfig) => {
    setSaving(true)
    try {
      await splitHorizonApi.update(updated)
      setShConfig(updated)
      showToast('Split-Horizon gespeichert')
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler', 'error')
    } finally { setSaving(false) }
  }

  const addView = () => {
    const name = newName.trim()
    if (!name) return
    const subnets = newSubnets.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean)
    save({ ...shConfig, views: [...(shConfig.views ?? []), { name, subnets }] })
    setNewName(''); setNewSubnets('')
  }

  const removeView = (idx: number) => {
    save({ ...shConfig, views: (shConfig.views ?? []).filter((_, i) => i !== idx) })
  }

  if (loading) return <div className="flex items-center justify-center h-32"><div className="w-6 h-6 border-2 border-amber-500 border-t-transparent rounded-full animate-spin" /></div>

  return (
    <div className="space-y-4 max-w-2xl">
      <Card
        title="Split-Horizon DNS"
        subtitle="Verschiedene Antworten je nach Client-IP (z.B. intern vs. extern)"
        headerRight={
          <ToggleSwitch checked={shConfig.enabled} onChange={(v) => save({ ...shConfig, enabled: v })} disabled={saving} />
        }
      >
        {(shConfig.views ?? []).length > 0 && (
          <div className="space-y-2">
            {(shConfig.views ?? []).map((view, idx) => (
              <div key={idx} className="flex items-start justify-between gap-3 p-3 rounded-xl bg-[var(--surface)] border border-[var(--border)]">
                <div>
                  <div className="text-sm font-medium text-amber-400">{view.name}</div>
                  <div className="text-xs text-[var(--muted)] mt-0.5">{view.subnets.length > 0 ? view.subnets.join(', ') : 'catch-all (alle anderen)'}</div>
                </div>
                <button onClick={() => removeView(idx)} disabled={saving} className="text-xs text-red-400 hover:text-red-300 disabled:opacity-50 px-2 py-1 rounded border border-red-500/30 hover:border-red-400/50 transition-colors shrink-0">Entfernen</button>
              </div>
            ))}
          </div>
        )}
        <div className="space-y-3 pt-1 border-t border-[var(--border)]">
          <p className="text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider pt-1">View hinzufügen</p>
          <input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="Name (z.B. internal)" className={inputCls} />
          <input value={newSubnets} onChange={(e) => setNewSubnets(e.target.value)} placeholder="Subnetze, kommagetrennt (leer = catch-all)" className={inputCls} />
          <p className="text-xs text-[var(--muted)]">z.B. 192.168.0.0/16, 10.0.0.0/8 — leer für catch-all</p>
          <MovingBorderButton onClick={addView} disabled={saving || !newName.trim()} className="w-full">View hinzufügen</MovingBorderButton>
        </div>
      </Card>
    </div>
  )
}

// ─── Zone Transfer Tab ────────────────────────────────────────────────────────

function ZoneTransferTab({ cfg, onSaved }: { cfg: Config; onSaved: () => void }) {
  const { showToast } = useToast()
  const [axfrConfig, setAxfrConfig] = useState<AXFRConfig>({ enabled: false, allowed_ips: [] })
  const [saving, setSaving] = useState(false)
  const [newIP, setNewIP] = useState('')

  useEffect(() => {
    const axfr = cfg.dnsserver?.axfr
    if (axfr) setAxfrConfig({ enabled: axfr.enabled ?? false, allowed_ips: axfr.allowed_ips ?? [] })
  }, [cfg])

  const save = async (updated: AXFRConfig) => {
    setSaving(true)
    try {
      await configApi.patch({ dnsserver: { axfr: updated } })
      setAxfrConfig(updated)
      showToast('Zone Transfer gespeichert')
      onSaved()
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler', 'error')
    } finally { setSaving(false) }
  }

  const addIP = () => {
    const ip = newIP.trim()
    if (!ip) return
    save({ ...axfrConfig, allowed_ips: [...(axfrConfig.allowed_ips ?? []), ip] })
    setNewIP('')
  }

  const removeIP = (idx: number) => {
    save({ ...axfrConfig, allowed_ips: (axfrConfig.allowed_ips ?? []).filter((_, i) => i !== idx) })
  }

  return (
    <div className="space-y-4 max-w-2xl">
      <Card
        title="Zone Transfer (AXFR/IXFR)"
        subtitle="Erlaubt externen Secondary-DNS-Servern, Zonen per Standard-DNS-Protokoll abzurufen"
        headerRight={
          <ToggleSwitch checked={axfrConfig.enabled} onChange={(v) => save({ ...axfrConfig, enabled: v })} disabled={saving} />
        }
      >
        <p className="text-xs text-[var(--muted)]">
          Erlaubte Client-IPs/CIDRs für DNS Zone Transfer. Leer = alle Anfragen ablehnen. Nur über TCP.
        </p>

        {(axfrConfig.allowed_ips ?? []).length > 0 && (
          <div className="space-y-2">
            {(axfrConfig.allowed_ips ?? []).map((ip, idx) => (
              <div key={idx} className="flex items-center justify-between gap-3 p-3 rounded-xl bg-[var(--surface)] border border-[var(--border)]">
                <span className="text-sm font-mono text-amber-400">{ip}</span>
                <button onClick={() => removeIP(idx)} disabled={saving} className="text-xs text-red-400 hover:text-red-300 disabled:opacity-50 px-2 py-1 rounded border border-red-500/30 hover:border-red-400/50 transition-colors shrink-0">Entfernen</button>
              </div>
            ))}
          </div>
        )}

        <div className="space-y-2 border-t border-[var(--border)] pt-3">
          <p className="text-xs font-semibold text-[var(--muted-2)] uppercase tracking-wider">IP/CIDR hinzufügen</p>
          <div className="flex gap-2">
            <input
              value={newIP}
              onChange={(e) => setNewIP(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addIP())}
              placeholder="z.B. 192.168.0.0/16 oder 10.0.0.1"
              className="flex-1 px-3 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-[var(--text)] text-sm focus:outline-none focus:border-amber-500 transition-colors"
            />
            <button onClick={addIP} disabled={saving || !newIP.trim()} className="px-4 py-2 rounded-xl bg-amber-500 hover:bg-amber-500 disabled:opacity-50 text-sm text-white transition-colors">Hinzufügen</button>
          </div>
          <p className="text-xs text-[var(--muted)]">CIDR-Notation empfohlen: 192.168.0.0/16, 127.0.0.1/32</p>
        </div>
      </Card>
    </div>
  )
}

// ─── System Tab ───────────────────────────────────────────────────────────────

function SystemTab({ cfg, onSaved }: { cfg: Config; onSaved: () => void }) {
  const { showToast } = useToast()
  const [saving, setSaving] = useState(false)
  const system = cfg.system ?? {}
  const rateLimit = system.rate_limit ?? {}

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    setSaving(true)
    const f = e.currentTarget
    const fd = new FormData(f)
    try {
      await configApi.patch({
        system: {
          log_level: (fd.get('log_level') as string) || undefined,
          rate_limit: {
            enabled: (f.querySelector('[name=rl_enabled]') as HTMLInputElement)?.checked,
            api_requests: parseInt(fd.get('rl_api') as string) || undefined,
          },
        },
      })
      showToast('System-Einstellungen gespeichert')
      onSaved()
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler', 'error')
    } finally { setSaving(false) }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4 max-w-2xl">
      <Card title="Logging">
        <div>
          <label className={labelCls}>
            <span>Log-Level</span>
            <InfoTooltip text="debug = alle Details, info = Standard, warn/error = nur Probleme." />
          </label>
          <select name="log_level" defaultValue={system.log_level ?? 'info'} className={inputCls}>
            {['debug', 'info', 'warn', 'error'].map((l) => <option key={l} value={l}>{l}</option>)}
          </select>
        </div>
      </Card>

      <Card title="Rate-Limiting">
        <ToggleRow label="Rate-Limit aktivieren" hint="Begrenzt API-Anfragen pro Minute pro IP — schützt vor Überlastung" tooltip="Begrenzt API-Anfragen pro Minute pro IP.">
          <FormToggle name="rl_enabled" defaultChecked={!!rateLimit.enabled} />
        </ToggleRow>
        <div>
          <label className={labelCls}>
            <span>Max. API-Anfragen / Minute</span>
            <InfoTooltip text="Maximale API-Requests pro IP-Adresse innerhalb einer Minute." />
          </label>
          <input name="rl_api" type="number" defaultValue={rateLimit.api_requests ?? 100} min={10} className={inputCls} />
        </div>
      </Card>

      <MovingBorderButton type="submit" disabled={saving} className="px-6 py-2.5">
        {saving ? 'Speichern …' : 'System-Einstellungen speichern'}
      </MovingBorderButton>
    </form>
  )
}

// ─── DHCP Sync Tab ───────────────────────────────────────────────────────────

function DHCPSyncTab({ cfg }: { cfg: Config }) {
  const dhcp = (cfg as Record<string, unknown>).dhcp_lease_sync as {
    enabled?: boolean; source?: string; source_path?: string;
    zone?: string; reverse_zone?: string; ttl?: number;
    poll_interval?: string; auto_create_zone?: boolean;
    fritzbox_url?: string; fritzbox_user?: string;
  } | undefined

  const sourceLabels: Record<string, string> = {
    dnsmasq: 'dnsmasq',
    dhcpd: 'ISC dhcpd',
    fritzbox: 'FritzBox (TR-064)',
  }

  return (
    <div className="space-y-4">
      <Card title="DHCP-Lease-Sync" subtitle="Automatische A- und PTR-Records aus DHCP-Leases (nur lesend, Konfiguration via config.yaml)">
        {!dhcp || !dhcp.enabled ? (
          <div className="text-[var(--muted)] text-sm py-4">
            DHCP-Lease-Sync ist nicht aktiviert. Aktiviere das Feature in der <code className="bg-[var(--surface)] px-1.5 py-0.5 rounded text-amber-400">config.yaml</code> unter <code className="bg-[var(--surface)] px-1.5 py-0.5 rounded text-amber-400">dhcp_lease_sync.enabled: true</code>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className={labelCls}>Quelle</label>
              <div className="text-[var(--text)] text-sm">{sourceLabels[dhcp.source ?? ''] ?? dhcp.source ?? '—'}</div>
            </div>
            {dhcp.source !== 'fritzbox' && (
              <div>
                <label className={labelCls}>Quelldatei</label>
                <div className="text-[var(--text)] text-sm font-mono">{dhcp.source_path ?? '—'}</div>
              </div>
            )}
            {dhcp.source === 'fritzbox' && (
              <>
                <div>
                  <label className={labelCls}>FritzBox URL</label>
                  <div className="text-[var(--text)] text-sm font-mono">{dhcp.fritzbox_url ?? '—'}</div>
                </div>
                <div>
                  <label className={labelCls}>FritzBox Benutzer</label>
                  <div className="text-[var(--text)] text-sm">{dhcp.fritzbox_user ?? '—'}</div>
                </div>
              </>
            )}
            <div>
              <label className={labelCls}>Forward-Zone</label>
              <div className="text-[var(--text)] text-sm">{dhcp.zone ?? '—'}</div>
            </div>
            <div>
              <label className={labelCls}>Reverse-Zone</label>
              <div className="text-[var(--text)] text-sm">{dhcp.reverse_zone || 'Automatisch'}</div>
            </div>
            <div>
              <label className={labelCls}>TTL</label>
              <div className="text-[var(--text)] text-sm">{dhcp.ttl ?? 60}s</div>
            </div>
            <div>
              <label className={labelCls}>Abfrage-Intervall</label>
              <div className="text-[var(--text)] text-sm">{dhcp.poll_interval ?? '30s'}</div>
            </div>
            <div>
              <label className={labelCls}>Zonen automatisch erstellen</label>
              <div className="text-[var(--text)] text-sm">{dhcp.auto_create_zone ? 'Ja' : 'Nein'}</div>
            </div>
          </div>
        )}
      </Card>
    </div>
  )
}

// ─── Security Tab ───────────────────────────────────────────────────────────

function SecurityTab() {
  const { showToast } = useToast()
  const [pwOpen, setPwOpen] = useState(false)
  const [curPw, setCurPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [changingPassword, setChangingPassword] = useState(false)
  const [keyOpen, setKeyOpen] = useState(false)
  const [newKey, setNewKey] = useState('')
  const [generatingKey, setGeneratingKey] = useState(false)

  // Named API Keys
  const [namedKeys, setNamedKeys] = useState<NamedAPIKey[]>([])
  const [namedKeysLoading, setNamedKeysLoading] = useState(true)
  const [newNamedKeyOpen, setNewNamedKeyOpen] = useState(false)
  const [newNamedKeyName, setNewNamedKeyName] = useState('')
  const [newNamedKeyDesc, setNewNamedKeyDesc] = useState('')
  const [creatingNamedKey, setCreatingNamedKey] = useState(false)
  const [createdKey, setCreatedKey] = useState<CreateNamedAPIKeyResponse | null>(null)
  const [copied, setCopied] = useState(false)

  const loadNamedKeys = useCallback(async () => {
    try {
      const keys = await listNamedAPIKeys()
      setNamedKeys(keys)
    } catch {
      // ignore — keys may not be available yet
    } finally {
      setNamedKeysLoading(false)
    }
  }, [])

  useEffect(() => { loadNamedKeys() }, [loadNamedKeys])

  const handleChangePassword = async () => {
    if (newPw.length < 8) { showToast('Passwort muss mindestens 8 Zeichen lang sein', 'error'); return }
    if (changingPassword) return
    setChangingPassword(true)
    try {
      await authApi.changePassword(curPw, newPw)
      showToast('Passwort erfolgreich geändert')
      setPwOpen(false); setCurPw(''); setNewPw('')
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler', 'error')
    } finally { setChangingPassword(false) }
  }

  const handleRegenKey = async () => {
    if (generatingKey) return
    setGeneratingKey(true)
    try {
      const resp = await authApi.regenerateApiKey()
      const key = resp.data?.api_key ?? resp.api_key ?? ''
      setNewKey(key)
      if (key) setApiKey(key)
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler', 'error')
    } finally { setGeneratingKey(false) }
  }

  const handleCreateNamedKey = async () => {
    if (!newNamedKeyName.trim() || creatingNamedKey) return
    setCreatingNamedKey(true)
    try {
      const key = await createNamedAPIKey(newNamedKeyName.trim(), newNamedKeyDesc.trim() || undefined)
      setCreatedKey(key)
      setNewNamedKeyOpen(false)
      setNewNamedKeyName('')
      setNewNamedKeyDesc('')
      await loadNamedKeys()
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler beim Erstellen', 'error')
    } finally { setCreatingNamedKey(false) }
  }

  const handleDeleteNamedKey = async (id: string, name: string) => {
    try {
      await deleteNamedAPIKey(id)
      showToast(`API-Schlüssel "${name}" gelöscht`)
      await loadNamedKeys()
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Fehler beim Löschen', 'error')
    }
  }

  const handleCopyKey = () => {
    if (!createdKey) return
    navigator.clipboard.writeText(createdKey.key).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <div className="space-y-4 max-w-2xl">
      <Card title="Zugangsdaten">
        <div>
          <div className="text-sm font-medium text-[var(--text)] mb-1">Passwort ändern</div>
          <div className="text-xs text-[var(--muted)] mb-3">Neues Login-Passwort für das Web-Interface</div>
          <button onClick={() => setPwOpen(true)} className="px-4 py-2 rounded-xl bg-[var(--surface)] border border-[var(--border)] text-sm text-[var(--muted-2)] hover:text-[var(--text)] hover:border-[var(--muted)] transition-colors">
            Passwort ändern …
          </button>
        </div>
        <div className="border-t border-[var(--border)] pt-4">
          <div className="text-sm font-medium text-[var(--text)] mb-1">Root-API-Key</div>
          <div className="text-xs text-[var(--muted)] mb-3">Haupt-Key für programmatischen Zugriff via Bearer Token (curl, Scripts)</div>
          <button onClick={() => setKeyOpen(true)} className="px-4 py-2 rounded-xl bg-gradient-to-r from-amber-500/20 to-red-500/20 border border-amber-500/30 text-sm text-amber-400 hover:text-amber-300 transition-colors">
            Neuen Root-Key generieren …
          </button>
        </div>
      </Card>

      {/* Named API Keys */}
      <Card title="API-Schlüssel">
        <div className="text-xs text-[var(--muted)] mb-4">
          Dedizierte Keys für externe Tools (Traefik, Certbot, acme.sh, Proxmox). Jeder Key kann einzeln widerrufen werden.
        </div>
        {namedKeysLoading ? (
          <div className="flex items-center gap-2 text-xs text-[var(--muted)]"><Spinner /> Laden …</div>
        ) : namedKeys.length === 0 ? (
          <div className="text-xs text-[var(--muted)] italic mb-3">Noch keine API-Schlüssel erstellt.</div>
        ) : (
          <div className="space-y-2 mb-4">
            {namedKeys.map((k) => (
              <div key={k.id} className="flex items-center gap-3 p-3 rounded-xl bg-[var(--surface)] border border-[var(--border)]">
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-[var(--text)] truncate">{k.name}</div>
                  {k.description && <div className="text-xs text-[var(--muted)] truncate">{k.description}</div>}
                  <div className="text-xs text-[#5A5A6E] mt-0.5">Erstellt: {new Date(k.created_at).toLocaleDateString('de-DE', { dateStyle: 'medium' })}</div>
                </div>
                <button
                  onClick={() => handleDeleteNamedKey(k.id, k.name)}
                  className="shrink-0 p-1.5 rounded-lg text-red-400 hover:text-red-300 hover:bg-red-900/20 transition-colors"
                  title="Schlüssel löschen"
                >
                  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
                </button>
              </div>
            ))}
          </div>
        )}
        <button
          onClick={() => setNewNamedKeyOpen(true)}
          className="px-4 py-2 rounded-xl bg-amber-500/10 border border-amber-500/30 text-sm text-amber-400 hover:text-amber-400 hover:border-amber-500/30 transition-colors"
        >
          + Neuer API-Schlüssel
        </button>
      </Card>

      <AnimatedModal isOpen={pwOpen} onClose={() => setPwOpen(false)} title="Passwort ändern">
        <div className="space-y-4">
          <div>
            <label className={labelCls}>Aktuelles Passwort</label>
            <input type="password" value={curPw} onChange={(e) => setCurPw(e.target.value)} className={inputCls} />
          </div>
          <div>
            <label className={labelCls}>Neues Passwort (mind. 8 Zeichen)</label>
            <input type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)} className={inputCls} />
          </div>
          <div className="flex gap-3 pt-2">
            <button onClick={() => setPwOpen(false)} disabled={changingPassword} className="flex-1 px-4 py-2 rounded-xl border border-[var(--border)] text-[var(--muted-2)] text-sm hover:text-[var(--text)] disabled:opacity-50 transition-colors">Abbrechen</button>
            <MovingBorderButton onClick={handleChangePassword} disabled={changingPassword} className="flex-1">
              {changingPassword ? <span className="flex items-center justify-center gap-2"><Spinner /> Speichert …</span> : 'Passwort ändern'}
            </MovingBorderButton>
          </div>
        </div>
      </AnimatedModal>

      <AnimatedModal isOpen={keyOpen && !newKey} onClose={() => setKeyOpen(false)} title="Root-API-Key regenerieren">
        <div className="space-y-4">
          <p className="text-sm text-[var(--muted-2)]">Der aktuelle Root-Key wird sofort ungültig. Alle Scripts/Tools müssen den neuen Key verwenden.</p>
          <p className="text-sm font-semibold text-amber-400">Der neue Key wird nur einmalig angezeigt!</p>
          <div className="flex gap-3 pt-2">
            <button onClick={() => setKeyOpen(false)} disabled={generatingKey} className="flex-1 px-4 py-2 rounded-xl border border-[var(--border)] text-[var(--muted-2)] text-sm hover:text-[var(--text)] disabled:opacity-50 transition-colors">Abbrechen</button>
            <button onClick={handleRegenKey} disabled={generatingKey} className="flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-amber-500 to-red-500 text-white text-sm font-semibold hover:opacity-90 disabled:opacity-60 transition-opacity">
              {generatingKey ? <><Spinner /> Generiert …</> : 'Neuen Key generieren'}
            </button>
          </div>
        </div>
      </AnimatedModal>

      <AnimatedModal isOpen={!!newKey} onClose={() => { setNewKey(''); setKeyOpen(false) }} title="">
        <div className="space-y-4">
          <h3 className="text-lg font-bold text-green-400">✓ Neuer Root-API-Key generiert</h3>
          <p className="text-sm text-[var(--muted-2)]">Bitte jetzt kopieren – wird nicht erneut angezeigt:</p>
          <div className="bg-[var(--surface)] neon-card rounded-xl p-4 font-mono text-sm text-amber-400 break-all">{newKey}</div>
          <div className="flex items-center gap-2 px-4 py-3 rounded-xl border border-amber-500/30 bg-amber-500/10 text-amber-300 text-xs">
            <span>⚠</span> Dieser Key wird nicht erneut angezeigt. Jetzt kopieren!
          </div>
          <MovingBorderButton onClick={() => { setNewKey(''); setKeyOpen(false) }} className="w-full">Schließen</MovingBorderButton>
        </div>
      </AnimatedModal>

      {/* Neuer benannter API-Schlüssel */}
      <AnimatedModal isOpen={newNamedKeyOpen} onClose={() => { setNewNamedKeyOpen(false); setNewNamedKeyName(''); setNewNamedKeyDesc('') }} title="Neuer API-Schlüssel">
        <div className="space-y-4">
          <div>
            <label className={labelCls}>Name <span className="text-red-400">*</span></label>
            <input
              type="text"
              value={newNamedKeyName}
              onChange={(e) => setNewNamedKeyName(e.target.value)}
              placeholder="z.B. Traefik ACME"
              className={inputCls}
              maxLength={100}
            />
          </div>
          <div>
            <label className={labelCls}>Beschreibung (optional)</label>
            <input
              type="text"
              value={newNamedKeyDesc}
              onChange={(e) => setNewNamedKeyDesc(e.target.value)}
              placeholder="z.B. Let's Encrypt via Traefik"
              className={inputCls}
              maxLength={500}
            />
          </div>
          <div className="flex gap-3 pt-2">
            <button
              onClick={() => { setNewNamedKeyOpen(false); setNewNamedKeyName(''); setNewNamedKeyDesc('') }}
              disabled={creatingNamedKey}
              className="flex-1 px-4 py-2 rounded-xl border border-[var(--border)] text-[var(--muted-2)] text-sm hover:text-[var(--text)] disabled:opacity-50 transition-colors"
            >
              Abbrechen
            </button>
            <MovingBorderButton onClick={handleCreateNamedKey} disabled={!newNamedKeyName.trim() || creatingNamedKey} className="flex-1">
              {creatingNamedKey ? <span className="flex items-center justify-center gap-2"><Spinner /> Erstellt …</span> : 'Schlüssel erstellen'}
            </MovingBorderButton>
          </div>
        </div>
      </AnimatedModal>

      {/* Erstellter Key anzeigen (einmalig) */}
      <AnimatedModal isOpen={!!createdKey} onClose={() => { setCreatedKey(null); setCopied(false) }} title="">
        <div className="space-y-4">
          <h3 className="text-lg font-bold text-green-400">✓ API-Schlüssel erstellt</h3>
          <div>
            <div className="text-sm font-medium text-[var(--text)] mb-1">{createdKey?.name}</div>
            {createdKey?.description && <div className="text-xs text-[var(--muted)]">{createdKey.description}</div>}
          </div>
          <p className="text-sm text-[var(--muted-2)]">Bitte jetzt kopieren – wird nicht erneut angezeigt:</p>
          <div className="bg-[var(--surface)] neon-card rounded-xl p-4 font-mono text-sm text-amber-400 break-all">
            {createdKey?.key}
          </div>
          <button
            onClick={handleCopyKey}
            className="w-full py-2 rounded-xl bg-amber-500/10 border border-amber-500/30 text-sm text-amber-400 hover:text-amber-400 transition-colors"
          >
            {copied ? '✓ Kopiert!' : 'Key kopieren'}
          </button>
          <div className="flex items-center gap-2 px-4 py-3 rounded-xl border border-amber-500/30 bg-amber-500/10 text-amber-300 text-xs">
            <span>⚠</span> Dieser Key wird nicht erneut angezeigt. Jetzt kopieren!
          </div>
          <MovingBorderButton onClick={() => { setCreatedKey(null); setCopied(false) }} className="w-full">Schließen</MovingBorderButton>
        </div>
      </AnimatedModal>
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function SettingsPage() {
  const { showToast } = useToast()
  const [activeTab, setActiveTab] = useState<MainTab>('dns')
  const [cfg, setCfg] = useState<Config | null>(null)
  const [loading, setLoading] = useState(true)

  const loadConfig = useCallback(async () => {
    try {
      const res = await configApi.get()
      setCfg(res.data)
    } catch {
      showToast('Fehler beim Laden der Konfiguration', 'error')
    } finally {
      setLoading(false)
    }
  }, [showToast])

  useEffect(() => { loadConfig() }, [loadConfig])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-6 h-6 border-2 border-amber-500 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  return (
    <>
      <Topbar title="Einstellungen" />
      <div className="p-4 lg:p-6 space-y-5">

        {/* Tab bar */}
        <div className="overflow-x-auto pb-1 -mx-4 px-4 lg:mx-0 lg:px-0">
          <div className="flex gap-1 bg-[var(--surface-2)] neon-card rounded-xl p-1 w-max min-w-full lg:w-auto lg:min-w-0">
            {MAIN_TABS.map((t) => (
              <button
                key={t.key}
                onClick={() => setActiveTab(t.key)}
                className={cn(
                  'whitespace-nowrap px-3 py-2 rounded-lg text-sm font-medium transition-all',
                  activeTab === t.key
                    ? 'bg-amber-500/10 text-amber-400'
                    : 'text-[var(--muted-2)] hover:text-[var(--text)]'
                )}
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>

        {/* Tab content */}
        {cfg && (
          <>
            {activeTab === 'dns'           && <DNSTab cfg={cfg} onSaved={loadConfig} />}
            {activeTab === 'blocklist'     && <BlocklistTab cfg={cfg} onSaved={loadConfig} />}
            {activeTab === 'ddns'          && <DDNSTab />}
            {activeTab === 'split-horizon' && <SplitHorizonTab />}
            {activeTab === 'zone-transfer' && <ZoneTransferTab cfg={cfg} onSaved={loadConfig} />}
            {activeTab === 'dhcp'          && <DHCPSyncTab cfg={cfg} />}
            {activeTab === 'system'        && <SystemTab cfg={cfg} onSaved={loadConfig} />}
            {activeTab === 'security'      && <SecurityTab />}
          </>
        )}
      </div>
    </>
  )
}
