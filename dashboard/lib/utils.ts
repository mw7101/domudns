import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function fmtNum(n: number | null | undefined): string {
  if (n == null) return '–'
  if (n >= 1e9) return (n / 1e9).toFixed(1) + 'G'
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M'
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K'
  return n.toLocaleString('de-DE')
}

export function fmtDate(s: string | null | undefined): string {
  if (!s) return '–'
  try {
    return new Date(s).toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' })
  } catch {
    return s
  }
}

export function timeSince(ts: number): string {
  const diff = Math.floor((Date.now() - ts) / 1000)
  if (diff < 60) return `vor ${diff}s`
  if (diff < 3600) return `vor ${Math.floor(diff / 60)}min`
  return `vor ${Math.floor(diff / 3600)}h`
}

export function formatRecordValue(r: {
  type: string
  value?: string
  priority?: number
  weight?: number
  port?: number
  tag?: string
}): string {
  if (r.type === 'MX' && r.priority != null) return `${r.priority} ${r.value}`
  if (r.type === 'SRV') return `${r.priority ?? 0} ${r.weight ?? 0} ${r.port ?? 0} ${r.value}`
  if (r.type === 'CAA') return `${r.tag ?? 'issue'} ${r.value}`
  return r.value ?? ''
}

export const RECORD_TYPE_COLORS: Record<string, string> = {
  A: '#0ea5e9',
  AAAA: '#0284c7',
  MX: '#06b6d4',
  CNAME: '#f59e0b',
  TXT: '#22c55e',
  NS: '#ef4444',
  SRV: '#6b7280',
  PTR: '#f97316',
  CAA: '#ec4899',
}


export const BLOCKLIST_SUGGESTIONS = [
  {
    name: 'StevenBlack Hosts',
    url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    desc: 'Werbung, Tracking, Malware – sehr verbreitet',
  },
  {
    name: 'AdGuard Spyware',
    url: 'https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt',
    desc: 'Spyware & Tracking-Filter von AdGuard',
  },
  {
    name: 'Phishing Army',
    url: 'https://phishing.army/download/phishing_army_blocklist.txt',
    desc: 'Phishing-Domains',
  },
]

// Compiled once at module load — avoids per-line regex compilation in parsePrometheus.
const PROMETHEUS_LINE_RE = /^([a-zA-Z_:][a-zA-Z0-9_:]*)\{?([^}]*)\}?\s+([\d.e+\-]+)/

// Prometheus text format parser
export function parsePrometheus(text: string): Record<string, { total: number; samples: { labels: string; value: number }[] }> {
  const result: Record<string, { total: number; samples: { labels: string; value: number }[] }> = {}
  if (!text) return result
  for (const line of text.split('\n')) {
    if (line.startsWith('#') || !line.trim()) continue
    const match = line.match(PROMETHEUS_LINE_RE)
    if (!match) continue
    const [, name, labelsStr, valStr] = match
    const value = parseFloat(valStr)
    if (isNaN(value)) continue
    if (!result[name]) result[name] = { total: 0, samples: [] }
    result[name].total += value
    if (labelsStr.trim()) result[name].samples.push({ labels: labelsStr, value })
  }
  return result
}

export function getMetric(
  metrics: Record<string, { total: number; samples: { labels: string; value: number }[] }>,
  name: string
): number | null {
  return metrics[name]?.total ?? null
}
