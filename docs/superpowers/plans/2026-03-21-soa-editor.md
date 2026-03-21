# SOA Editor — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the SOA record of a DNS zone editable in the dashboard — as a pinned first row in the record table, with a dedicated modal.

**Architecture:** Dashboard-only change. Add `SOA` type + `zones.update()` to `lib/api.ts`, extend `loadZoneDetail` to be view-aware, add SOA state + handlers + pinned table row + modal to `zones/page.tsx`. The backend `PUT /api/zones/{domain}` already accepts a `soa` field — no backend changes needed.

**Tech Stack:** Next.js 15 (App Router), TypeScript strict, Tailwind CSS, existing `AnimatedModal` component

**Spec:** `docs/superpowers/specs/2026-03-21-soa-editor-design.md`

---

## File Map

| File | Change |
|---|---|
| `dashboard/lib/api.ts` | Add `SOA` interface, add `soa?: SOA` to `Zone`, add `zones.update()` |
| `dashboard/app/dashboard/zones/page.tsx` | Extend `loadZoneDetail(view?)`, add SOA state/handlers, add SOA row in table, add SOA modal, fix empty-state condition |

---

## Task 1: Add SOA type and `zones.update()` to `api.ts`

**Files:**
- Modify: `dashboard/lib/api.ts:77-83` (Zone interface)
- Modify: `dashboard/lib/api.ts:186-241` (zones object)

- [ ] **Step 1: Add `SOA` interface and `soa?` field to `Zone`**

  In `dashboard/lib/api.ts`, after line 83 (closing brace of `Zone` interface), add the `SOA` interface. Also add `soa?: SOA` as the last field of the `Zone` interface.

  The `Zone` interface (lines 77–83) becomes:
  ```typescript
  export interface Zone {
    domain: string
    view?: string
    ttl: number
    ttl_override?: number
    records: DnsRecord[]
    soa?: SOA
  }
  ```

  Add the `SOA` interface directly after `Zone` (before `SplitHorizonView`):
  ```typescript
  export interface SOA {
    mname: string
    rname: string
    serial: number
    refresh: number
    retry: number
    expire: number
    minimum: number
  }
  ```

- [ ] **Step 2: Add `zones.update()` to the `zones` object**

  In `dashboard/lib/api.ts`, add `update` as the last method of the `zones` object (before the closing `}`), after `importAXFR`:
  ```typescript
  update: (domain: string, zone: Zone, view?: string): Promise<{ data: Zone }> => {
    const url = view
      ? '/zones/' + encodeURIComponent(domain) + '?view=' + encodeURIComponent(view)
      : '/zones/' + encodeURIComponent(domain)
    return request<{ data: Zone }>(url, { method: 'PUT', body: JSON.stringify(zone) })
  },
  ```

- [ ] **Step 3: Verify TypeScript compiles**

  ```bash
  cd dashboard && npm run build 2>&1 | head -40
  ```
  Expected: build succeeds (or only pre-existing errors unrelated to this change).

- [ ] **Step 4: Commit**

  ```bash
  git add dashboard/lib/api.ts
  git commit -m "feat(dashboard): add SOA type and zones.update() to api.ts"
  ```

---

## Task 2: Add SOA state, `nextSerial()`, and handlers to `page.tsx`

**Files:**
- Modify: `dashboard/app/dashboard/zones/page.tsx:9` (import line)
- Modify: `dashboard/app/dashboard/zones/page.tsx:40-44` (loading states)
- Modify: `dashboard/app/dashboard/zones/page.tsx:62-75` (state declarations)
- Modify: `dashboard/app/dashboard/zones/page.tsx:88-98` (`loadZoneDetail`)

- [ ] **Step 1: Update the import line**

  Line 9 currently imports:
  ```typescript
  import { zones as zonesApi, records as recordsApi, type Zone, type DnsRecord, type ImportResult } from '@/lib/api'
  ```

  Change to also import `SOA`:
  ```typescript
  import { zones as zonesApi, records as recordsApi, type Zone, type DnsRecord, type ImportResult, type SOA } from '@/lib/api'
  ```

- [ ] **Step 2: Add SOA state declarations**

  After the existing loading states block (around line 40–44), add:
  ```typescript
  const [savingSOA, setSavingSOA] = useState(false)
  ```

  After the Record Modal state block (around line 62–75), add:
  ```typescript
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
  ```

- [ ] **Step 3: Add `nextSerial()` helper**

  Add this pure function directly above the `ZonesContent` function (before line 27):
  ```typescript
  function nextSerial(current: number): number {
    const today = new Date()
    const base = parseInt(
      `${today.getFullYear()}${String(today.getMonth() + 1).padStart(2, '0')}${String(today.getDate()).padStart(2, '0')}00`
    )
    return Math.max(current + 1, base)
  }
  ```

- [ ] **Step 4: Extend `loadZoneDetail` with optional `view` parameter**

  Replace the existing `loadZoneDetail` (lines 88–98):
  ```typescript
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
  ```

  The existing call sites `loadZoneDetail(domainParam)` and `loadZoneDetail(recordDomain)` remain compatible — the new `view?` parameter is optional.

- [ ] **Step 5: Add `openSOAModal` and `handleSaveSOA` handlers**

  **Also update the existing `handleSaveRecord` and `handleDeleteRecord` calls** to pass `selectedZone?.view` for correct view-zone reload. In `handleSaveRecord` (around line 203), change:
  ```typescript
  await loadZoneDetail(recordDomain)
  ```
  to:
  ```typescript
  await loadZoneDetail(recordDomain, selectedZone?.view)
  ```
  In `handleDeleteRecord` (around line 218), change:
  ```typescript
  await loadZoneDetail(domain)
  ```
  to:
  ```typescript
  await loadZoneDetail(domain, selectedZone?.view)
  ```

  Then add the two new SOA functions after `handleDeleteRecord`:

  ```typescript
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
  ```

- [ ] **Step 6: Verify TypeScript compiles**

  ```bash
  cd dashboard && npm run build 2>&1 | head -40
  ```
  Expected: no new type errors.

- [ ] **Step 7: Commit**

  ```bash
  git add dashboard/app/dashboard/zones/page.tsx
  git commit -m "feat(dashboard): add SOA state, nextSerial, and handlers to zones page"
  ```

---

## Task 3: Add SOA pinned row to the record table

**Files:**
- Modify: `dashboard/app/dashboard/zones/page.tsx:346-414` (zone detail table section)

The table is currently inside the condition `(selectedZone.records ?? []).length > 0`. A zone with 0 records but a SOA (always the case) would show the empty state — wrong. The condition must be broadened.

- [ ] **Step 1: Fix the empty-state condition**

  Change line 346 from:
  ```typescript
  {(selectedZone.records ?? []).length > 0 ? (
  ```
  To:
  ```typescript
  {(selectedZone.records ?? []).length > 0 || selectedZone.soa ? (
  ```

- [ ] **Step 2: Add SOA pinned row before the records `.map()`**

  The `<tbody>` currently starts with the `.map()` over records (line 358). Add the SOA row as the first element inside `<tbody>`, before the `.map()`:

  ```tsx
  <tbody className="divide-y divide-[var(--surface)]">
    {/* SOA pinned row */}
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
    {/* Regular records */}
    {(selectedZone.records ?? []).map((r) => {
      // ... existing record rows unchanged
    })}
  </tbody>
  ```

- [ ] **Step 3: Verify TypeScript compiles**

  ```bash
  cd dashboard && npm run build 2>&1 | head -40
  ```

- [ ] **Step 4: Commit**

  ```bash
  git add dashboard/app/dashboard/zones/page.tsx
  git commit -m "feat(dashboard): add SOA pinned row to zone record table"
  ```

---

## Task 4: Add SOA edit modal

**Files:**
- Modify: `dashboard/app/dashboard/zones/page.tsx:418-533` (after the Record Modal)

The SOA modal goes between the closing `</AnimatedModal>` of the Record Modal (line 533) and the `</>` closing the Fragment (line 534). Both modals must remain inside the Fragment.

- [ ] **Step 1: Add SOA modal JSX**

  After the existing Record Modal `</AnimatedModal>` (line 533), add:

  ```tsx
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

      {/* Serial read-only info */}
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
            ? <span className="flex items-center justify-center gap-2">
                <span className="inline-block w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" />
                Speichert …
              </span>
            : 'Speichern'}
        </MovingBorderButton>
      </div>
    </div>
  </AnimatedModal>
  ```

- [ ] **Step 2: Verify TypeScript compiles**

  ```bash
  cd dashboard && npm run build 2>&1 | head -40
  ```
  Expected: clean build (0 type errors from this change).

- [ ] **Step 3: Build dashboard and copy to embed dir**

  ```bash
  make build-dashboard
  ```
  Expected: build succeeds, files copied to `internal/caddy/web/`.

- [ ] **Step 4: Run Go tests**

  ```bash
  make test
  ```
  Expected: all tests pass (no Go code changed, tests should be green).

- [ ] **Step 5: Commit**

  ```bash
  git add dashboard/app/dashboard/zones/page.tsx internal/caddy/web/
  git commit -m "feat(dashboard): add SOA edit modal to zone detail view"
  ```

---

## Task 5: Changelog entry

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Add entry under `## [Unreleased]` → `Added`**

  ```markdown
  ### Added
  - Dashboard: SOA records are now editable in the zone detail view — pinned as the first row in the record table with a dedicated edit modal (MName, RName, Refresh, Retry, Expire, Minimum TTL; Serial auto-incremented)
  ```

- [ ] **Step 2: Commit**

  ```bash
  git add CHANGELOG.md
  git commit -m "docs: add changelog entry for SOA editor"
  ```

---

## Done

After Task 5, the feature is complete. Verify by:
1. Opening the dashboard → Zonen → any zone detail
2. Confirming the SOA row appears as the first row with amber badge
3. Clicking "Bearbeiten" → modal opens with current values + read-only serial preview
4. Changing MName → saving → SOA row updates, serial incremented
5. Testing with a view zone (Split-Horizon): save → zone reloads with correct view data
