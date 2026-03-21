const API_BASE = '/api'
const KEY_STORAGE = 'dns-stack-api-key'

export function getApiKey(): string {
  if (typeof window === 'undefined') return ''
  return localStorage.getItem(KEY_STORAGE) ?? ''
}

export function setApiKey(key: string): void {
  localStorage.setItem(KEY_STORAGE, key)
}

function authHeaders(): Record<string, string> {
  const key = getApiKey()
  return key ? { Authorization: `Bearer ${key}` } : {}
}

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

const REQUEST_TIMEOUT_MS = 30_000

async function request<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
  try {
    const res = await fetch(API_BASE + path, {
      ...opts,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...authHeaders(),
        ...(opts.headers as Record<string, string> | undefined),
      },
    })
    const data = await res.json().catch(() => ({}))
    if (res.status === 401) {
      if (typeof window !== 'undefined') {
        window.location.href = '/login/?redirect=' + encodeURIComponent(window.location.pathname)
      }
      throw new ApiError('Nicht angemeldet', 401)
    }
    if (!res.ok) {
      const msg = (data as { error?: { message?: string } })?.error?.message ?? res.statusText
      throw new ApiError(msg, res.status)
    }
    return data as T
  } finally {
    clearTimeout(timeoutId)
  }
}

async function requestText(path: string): Promise<string> {
  const res = await fetch(API_BASE + path, { headers: authHeaders() })
  if (res.status === 401) throw new ApiError('Nicht angemeldet', 401)
  if (!res.ok) throw new ApiError(res.statusText, res.status)
  return res.text()
}

// ─── Types ───────────────────────────────────────────────────────────────────

export interface HealthResponse {
  data?: {
    status: string
    version?: string
    uptime?: number
  }
}

export interface Zone {
  domain: string
  view?: string         // "" or absent = default zone; set = view zone
  ttl: number
  ttl_override?: number // 0 or absent = no override; >0 = all response TTLs for this zone are normalized
  records: DnsRecord[]
}

export interface SplitHorizonView {
  name: string
  subnets: string[]  // CIDR strings, empty = catch-all
}

export interface SplitHorizonConfig {
  enabled: boolean
  views: SplitHorizonView[]
}

export interface AXFRConfig {
  enabled: boolean
  allowed_ips: string[]
}

export interface DnsRecord {
  id: number
  name: string
  type: string
  ttl: number
  value: string
  priority?: number
  weight?: number
  port?: number
  tag?: string
}

export interface BlocklistUrl {
  id: number
  url: string
  enabled: boolean
  last_fetched_at?: string
  last_error?: string
}

export interface BlocklistPattern {
  id: number
  pattern: string
  type: 'wildcard' | 'regex'
  created_at: string
}

export interface DnsServerConfig {
  listen?: string
  upstream?: string[]
  cache?: {
    enabled?: boolean
    // PostgreSQL/Custom DNS server
    max_entries?: number
    default_ttl?: number
    negative_ttl?: number
    // CoreDNS (legacy)
    size?: number
    ttl?: number
  }
  doh?: {
    enabled?: boolean
    path?: string
  }
  dot?: {
    enabled?: boolean
    listen?: string
    cert_file?: string
    key_file?: string
  }
  axfr?: AXFRConfig
}

export interface Config {
  dnsserver?: DnsServerConfig
  coredns?: DnsServerConfig
  blocklist?: {
    enabled?: boolean
    fetch_interval?: string
    block_mode?: string // "zero_ip" | "nxdomain"
  }
  system?: {
    log_level?: string
    metrics?: { enabled?: boolean }
    rate_limit?: {
      enabled?: boolean
      api_requests?: number
    }
  }
  caddy?: Record<string, unknown>
}

// ─── Health ──────────────────────────────────────────────────────────────────

export const health = {
  get: () => request<HealthResponse>('/health'),
}

// ─── Zones ───────────────────────────────────────────────────────────────────

export interface ImportResult {
  zone: string
  imported: number
  merged: number
}

export const zones = {
  list: () => request<{ data: Zone[] }>('/zones'),
  get: (domain: string) => request<{ data: Zone }>('/zones/' + encodeURIComponent(domain)),
  getView: (domain: string, view: string) =>
    request<{ data: Zone }>('/zones/' + encodeURIComponent(domain) + '?view=' + encodeURIComponent(view)),
  create: (payload: { domain: string; view?: string; ttl: number; ttl_override?: number; records: DnsRecord[] }) =>
    request<{ data: Zone }>('/zones', { method: 'POST', body: JSON.stringify(payload) }),
  delete: (domain: string) =>
    request<void>('/zones/' + encodeURIComponent(domain), { method: 'DELETE' }),
  deleteView: (domain: string, view: string) =>
    request<void>('/zones/' + encodeURIComponent(domain) + '?view=' + encodeURIComponent(view), {
      method: 'DELETE',
    }),

  /** Export a zone as an RFC 1035 zone file. Returns the file content as text. */
  export: async (domain: string, view?: string): Promise<string> => {
    const qs = view ? '?view=' + encodeURIComponent(view) : ''
    const res = await fetch(API_BASE + '/zones/' + encodeURIComponent(domain) + '/export' + qs, {
      headers: authHeaders(),
    })
    if (res.status === 401) throw new ApiError('Nicht angemeldet', 401)
    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      const msg = (data as { error?: { message?: string } })?.error?.message ?? res.statusText
      throw new ApiError(msg, res.status)
    }
    return res.text()
  },

  /** Import a zone from an RFC 1035 zone file. */
  importFile: async (file: File, domain?: string, view?: string): Promise<{ data: ImportResult }> => {
    const form = new FormData()
    form.append('file', file)
    if (domain) form.append('domain', domain)
    if (view) form.append('view', view)
    const res = await fetch(API_BASE + '/zones/import', {
      method: 'POST',
      headers: authHeaders(), // no Content-Type: browser sets multipart boundary automatically
      body: form,
    })
    if (res.status === 401) throw new ApiError('Nicht angemeldet', 401)
    const data = await res.json().catch(() => ({}))
    if (!res.ok) {
      const msg = (data as { error?: { message?: string } })?.error?.message ?? res.statusText
      throw new ApiError(msg, res.status)
    }
    return data as { data: ImportResult }
  },

  /** Import a zone via AXFR transfer from a remote DNS server. */
  importAXFR: (server: string, domain: string, view?: string): Promise<{ data: ImportResult }> =>
    request<{ data: ImportResult }>('/zones/import/axfr', {
      method: 'POST',
      body: JSON.stringify({ server, domain, view: view ?? '' }),
    }),
}

// ─── Records ─────────────────────────────────────────────────────────────────

export const records = {
  create: (domain: string, payload: Omit<DnsRecord, 'id'>) =>
    request<{ data: DnsRecord }>('/zones/' + encodeURIComponent(domain) + '/records', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  update: (domain: string, id: number, payload: Partial<DnsRecord>) =>
    request<{ data: DnsRecord }>(
      '/zones/' + encodeURIComponent(domain) + '/records/' + id,
      { method: 'PUT', body: JSON.stringify(payload) }
    ),
  delete: (domain: string, id: number) =>
    request<void>('/zones/' + encodeURIComponent(domain) + '/records/' + id, {
      method: 'DELETE',
    }),
}

// ─── Blocklist ────────────────────────────────────────────────────────────────

export const blocklist = {
  listUrls: () => request<{ data: BlocklistUrl[] }>('/blocklist/urls'),
  addUrl: (payload: { url: string; enabled: boolean }) =>
    request<{ data: BlocklistUrl }>('/blocklist/urls', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  updateUrl: (id: number, payload: { enabled: boolean }) =>
    request<void>('/blocklist/urls/' + id, { method: 'PATCH', body: JSON.stringify(payload) }),
  deleteUrl: (id: number) =>
    request<void>('/blocklist/urls/' + id, { method: 'DELETE' }),
  fetchUrl: (id: number) =>
    request<void>('/blocklist/urls/' + id + '/fetch', { method: 'POST' }),

  listDomains: () => request<{ data: string[] }>('/blocklist/domains'),
  addDomain: (domain: string) =>
    request<void>('/blocklist/domains', { method: 'POST', body: JSON.stringify({ domain }) }),
  deleteDomain: (domain: string) =>
    request<void>('/blocklist/domains/' + encodeURIComponent(domain), { method: 'DELETE' }),

  listAllowed: () => request<{ data: string[] }>('/blocklist/allowed'),
  addAllowed: (domain: string) =>
    request<void>('/blocklist/allowed', { method: 'POST', body: JSON.stringify({ domain }) }),
  deleteAllowed: (domain: string) =>
    request<void>('/blocklist/allowed/' + encodeURIComponent(domain), { method: 'DELETE' }),

  listWhitelistIPs: () => request<{ data: string[] }>('/blocklist/whitelist-ips'),
  addWhitelistIP: (ip_cidr: string) =>
    request<void>('/blocklist/whitelist-ips', {
      method: 'POST',
      body: JSON.stringify({ ip_cidr }),
    }),
  deleteWhitelistIP: (ip: string) =>
    request<void>('/blocklist/whitelist-ips/' + encodeURIComponent(ip), { method: 'DELETE' }),

  listPatterns: () => request<{ data: BlocklistPattern[] }>('/blocklist/patterns'),
  addPattern: (payload: { pattern: string; type: 'wildcard' | 'regex' }) =>
    request<{ data: BlocklistPattern }>('/blocklist/patterns', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  deletePattern: (id: number) =>
    request<void>('/blocklist/patterns/' + id, { method: 'DELETE' }),
}

// ─── Config ───────────────────────────────────────────────────────────────────

export const config = {
  get: () => request<{ data: Config }>('/config'),
  patch: (overrides: Partial<Config>) =>
    request<void>('/config', { method: 'PATCH', body: JSON.stringify(overrides) }),
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

export const auth = {
  login: (username: string, password: string) =>
    request<void>('/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
      headers: { 'Content-Type': 'application/json' },
    }),
  logout: () => fetch('/api/logout', { method: 'POST', headers: authHeaders() }),
  changePassword: (current_password: string, new_password: string) =>
    request<void>('/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ current_password, new_password }),
    }),
  regenerateApiKey: () =>
    request<{ data?: { api_key: string }; api_key?: string }>('/auth/regenerate-api-key', {
      method: 'POST',
    }),
}

// ─── Setup ────────────────────────────────────────────────────────────────────

export const setup = {
  status: () => request<{ setup_completed: boolean }>('/setup/status'),
  complete: (payload: { username: string; password: string; generate_api_key: boolean }) =>
    request<{ message: string; api_key?: string }>('/setup/complete', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
}

// ─── Query-Log ───────────────────────────────────────────────────────────────

export interface QueryLogEntry {
  ts: string
  node: string
  client: string
  domain: string
  qtype: string
  result: string
  latency_us: number
  upstream: string
  blocked: boolean
  cached: boolean
  rcode: number
}

export interface QueryLogPage {
  entries: QueryLogEntry[]
  total: number
  has_more: boolean
}

export interface QueryLogStats {
  total_queries: number
  block_rate: number
  top_clients: { client: string; count: number }[]
  top_domains: { domain: string; count: number }[]
  top_blocked: { domain: string; count: number }[]
  queries_per_hour: { hour: string; count: number }[]
}

interface QueryLogFilter {
  client?: string
  domain?: string
  result?: string
  qtype?: string
  node?: string
  since?: string
  until?: string
  limit?: number
  offset?: number
}

export const queryLog = {
  list: (f: QueryLogFilter = {}) => {
    const params = new URLSearchParams()
    if (f.client)  params.set('client',  f.client)
    if (f.domain)  params.set('domain',  f.domain)
    if (f.result)  params.set('result',  f.result)
    if (f.qtype)   params.set('qtype',   f.qtype)
    if (f.node)    params.set('node',    f.node)
    if (f.since)   params.set('since',   f.since)
    if (f.until)   params.set('until',   f.until)
    if (f.limit)   params.set('limit',   String(f.limit))
    if (f.offset)  params.set('offset',  String(f.offset))
    const qs = params.toString()
    return request<{ data?: QueryLogPage }>(`/query-log${qs ? '?' + qs : ''}`)
  },
  stats: () => request<{ data?: QueryLogStats }>('/query-log/stats'),
}

// ─── Metrics ─────────────────────────────────────────────────────────────────

export interface MetricsSnapshot {
  ts: number
  queries: number
  blocked: number
  cached: number
  forwarded: number
  errors: number
}

export const metrics = {
  get: () => requestText('/metrics'),
  history: (range?: '1h' | '24h' | '7d' | '30d') =>
    request<{ data: { samples: MetricsSnapshot[] } }>(
      '/metrics/history' + (range && range !== '24h' ? '?range=' + range : '')
    ),
}

// ─── DDNS ────────────────────────────────────────────────────────────────────

export interface TSIGKey {
  name: string
  algorithm: string
  created_at: string
}

export interface TSIGKeyCreateResponse extends TSIGKey {
  secret: string // only returned on creation
}

export interface DDNSStatus {
  key_count: number
  total_updates: number
  last_update_at: string      // RFC3339 oder "" wenn noch kein Update
  total_failed: number
  last_error: string          // "" wenn kein Fehler
  last_error_at: string       // RFC3339 oder "" wenn noch kein Fehler
  last_rejected_reason: string // z.B. "NOTZONE: example.local" oder ""
  last_rejected_at: string    // RFC3339 oder ""
}

export const ddns = {
  listKeys: () => request<{ data: TSIGKey[] }>('/ddns/keys'),
  createKey: (payload: { name: string; algorithm?: string }) =>
    request<{ data: TSIGKeyCreateResponse }>('/ddns/keys', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  deleteKey: (name: string) =>
    fetch(API_BASE + '/ddns/keys/' + encodeURIComponent(name), {
      method: 'DELETE',
      headers: authHeaders(),
    }).then(async (res) => {
      if (res.status === 401) throw new ApiError('Nicht angemeldet', 401)
      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        const msg = (data as { error?: { message?: string } })?.error?.message ?? res.statusText
        throw new ApiError(msg, res.status)
      }
    }),
  getStatus: () => request<{ data: DDNSStatus }>('/ddns/status'),
}

// ─── Cluster ─────────────────────────────────────────────────────────────────

export interface ClusterNode {
  label: string
  url: string
  ip: string
  role: string
}

export interface ClusterInfo {
  role: string
  remote_nodes: ClusterNode[]
}

export const cluster = {
  info: () => request<{ data?: ClusterInfo }>('/cluster'),
}

// ─── Split-Horizon ───────────────────────────────────────────────────────────

export const splitHorizon = {
  get: () => request<{ data: SplitHorizonConfig }>('/split-horizon'),
  update: (payload: SplitHorizonConfig) =>
    request<void>('/split-horizon', { method: 'PUT', body: JSON.stringify(payload) }),
}

// ─── DHCP-Lease-Sync ────────────────────────────────────────────────────────

export interface DHCPLease {
  hostname: string
  ip: string
  mac: string
  a_record_id: number
  ptr_record_id: number
  updated_at: string
}

export interface DHCPSyncStatus {
  enabled: boolean
  source: string
  last_sync: string
  last_error?: string
  lease_count: number
  record_count: number
  next_sync: string
}

export const dhcpLeaseSync = {
  getLeases: () => request<{ data: DHCPLease[] }>('/dhcp/leases'),
  getStatus: () => request<{ data: DHCPSyncStatus }>('/dhcp/status'),
}

/** Checks the reachability of a remote node by its full URL (e.g. http://192.0.2.2:80). */
// ─── Named API Keys ───────────────────────────────────────────────────────────

export interface NamedAPIKey {
  id: string
  name: string
  description?: string
  created_at: string
}

export interface CreateNamedAPIKeyResponse extends NamedAPIKey {
  key: string // only set on creation, never returned again
}

export async function listNamedAPIKeys(): Promise<NamedAPIKey[]> {
  const res = await request<{ success: boolean; data: NamedAPIKey[] }>('/auth/api-keys')
  return res.data ?? []
}

export async function createNamedAPIKey(
  name: string,
  description?: string
): Promise<CreateNamedAPIKeyResponse> {
  const res = await request<{ success: boolean; data: CreateNamedAPIKeyResponse }>(
    '/auth/api-keys',
    {
      method: 'POST',
      body: JSON.stringify({ name, description: description ?? '' }),
    }
  )
  return res.data
}

export async function deleteNamedAPIKey(id: string): Promise<void> {
  await fetch(API_BASE + `/auth/api-keys/${id}`, {
    method: 'DELETE',
    headers: authHeaders(),
  })
}

export async function checkNodeHealth(nodeUrl: string): Promise<{ online: boolean; status: string }> {
  try {
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), 3000)
    const res = await fetch(`${nodeUrl}/api/health`, {
      signal: ctrl.signal,
      mode: 'cors',
    })
    clearTimeout(timer)
    if (res.ok) {
      const j = await res.json().catch(() => ({}))
      return { online: true, status: j.data?.status ?? 'ok' }
    }
    return { online: false, status: 'error' }
  } catch {
    return { online: false, status: 'offline' }
  }
}
