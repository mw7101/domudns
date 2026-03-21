# SOA Editor im Dashboard

**Date:** 2026-03-21
**Status:** Approved
**Scope:** Dashboard-only (kein Backend-Änderungsbedarf)

---

## Problem

Der SOA-Record einer Zone (Primary Nameserver, Responsible Mailbox, Refresh/Retry/Expire/Minimum-Zeiten, Serial) ist im Dashboard nicht editierbar. Er wird beim Anlegen einer Zone automatisch generiert und kann danach nur über Import/Export oder direkte API-Aufrufe geändert werden.

---

## Ziel

SOA-Records sollen direkt im Dashboard bearbeitbar sein — ohne neue API-Endpoints.

---

## Architektur

### Backend (keine Änderungen)

Der bestehende `PUT /api/zones/{domain}` akzeptiert bereits ein `soa`-Objekt im Zone-Payload:

```go
type Zone struct {
    Domain      string   `json:"domain"`
    SOA         *SOA     `json:"soa,omitempty"`
    Records     []Record `json:"records"`
    // ...
}

type SOA struct {
    MName   string `json:"mname"`
    RName   string `json:"rname"`
    Serial  uint32 `json:"serial"`   // unsigned 32-bit, max 4294967295
    Refresh int    `json:"refresh"`
    Retry   int    `json:"retry"`
    Expire  int    `json:"expire"`
    Minimum int    `json:"minimum"`
}
```

**Wichtig:** `EnsureSOA()` im Backend füllt nur dann ein fehlendes SOA auf — wenn das Frontend ein SOA-Objekt mitschickt (auch mit `serial: 0`), wird es unverändert gespeichert. Das Frontend muss daher alle SOA-Felder vollständig befüllen, bevor es den PUT-Request abschickt.

### API Types (`dashboard/lib/api.ts`)

Drei Ergänzungen:

```typescript
// 1. Neues Interface
export interface SOA {
  mname: string
  rname: string
  serial: number       // uint32 auf Backend-Seite (0–4294967295); nextSerial() bleibt sicher im YYYYMMDDnn-Bereich
  refresh: number
  retry: number
  expire: number
  minimum: number
}

// 2. Zone-Interface erweitern
export interface Zone {
  domain: string
  view?: string
  ttl: number
  ttl_override?: number
  records: DnsRecord[]
  soa?: SOA          // neu
}

// 3. Neue Update-Funktion im zones-Objekt
export const zones = {
  // ... bestehende Funktionen ...
  update: (domain: string, zone: Zone, view?: string): Promise<{ data: Zone }> => {
    const url = view
      ? `/api/zones/${encodeURIComponent(domain)}?view=${encodeURIComponent(view)}`
      : `/api/zones/${encodeURIComponent(domain)}`
    return request<{ data: Zone }>(url, { method: 'PUT', body: JSON.stringify(zone) })
  },
}
```

### Dashboard UI (`dashboard/app/dashboard/zones/page.tsx`)

#### 1. SOA-Zeile in der Record-Tabelle

Die SOA-Daten werden als **erste, gepinnte Zeile** in der Record-Tabelle angezeigt:

- **Name:** `@`
- **Typ:** amber/gelber Badge `SOA` (statt blauem Badge wie reguläre Record-Typen)
- **TTL:** `zone.soa.minimum` (Minimum TTL — der für negative Caching relevante Wert, semantisch korrekt für SOA)
- **Wert:** kompakt — `{mname} {rname} (Serial: {serial})`
- **Aktionen:** nur ✏ Edit-Button, kein Delete-Icon
- **Bedingung:** Zeile erscheint nur wenn `zone.soa` vorhanden ist

#### 2. SOA-Modal

State: `soaModalOpen: boolean` + `soaForm: SOA` (vollständig typisiert, kein `Partial<SOA>`)

Initialisierung beim Öffnen: `soaForm = { ...zone.soa! }` — alle Felder vollständig aus der aktuell geladenen Zone übernommen. Der Edit-Button wird nur gerendert wenn `zone.soa` vorhanden ist (SOA-Zeile-Bedingung), daher ist der Non-null-Assert (`!`) zur Laufzeit sicher; TypeScript strict mode erfordert ihn trotzdem am Aufruf-Ort.

Felder im Modal (2-Spalten-Grid):

| Feld | Label | Typ | Verhalten |
|---|---|---|---|
| `mname` | Primary Nameserver (MName) | Text-Input | editierbar, Pflichtfeld |
| `rname` | Responsible Mailbox (RName) | Text-Input | editierbar, Pflichtfeld |
| `refresh` | Refresh (s) | Number-Input | editierbar |
| `retry` | Retry (s) | Number-Input | editierbar |
| `expire` | Expire (s) | Number-Input | editierbar |
| `minimum` | Minimum TTL (s) | Number-Input | editierbar |
| `serial` | Serial (nach Speichern) | Read-only Text | vorberechneter Wert via `nextSerial()` |

**Serial-Berechnung (Frontend):**

```typescript
function nextSerial(current: number): number {
  const today = new Date()
  const base = parseInt(
    `${today.getFullYear()}${String(today.getMonth() + 1).padStart(2, '0')}${String(today.getDate()).padStart(2, '0')}00`
  )
  return Math.max(current + 1, base)
}
```

Der resultierende Wert liegt immer im `uint32`-sicheren Bereich (YYYYMMDDnn ≤ 10 Stellen, max ~2099123199 < 4294967295).

---

## Datenfluss

```
User klickt ✏ (SOA-Zeile)
  → soaModalOpen = true
  → soaForm = { ...zone.soa }   // vollständig, nicht Partial

User bearbeitet Felder → lokaler soaForm-State

User klickt Speichern
  → Client-seitige Validierung: mname + rname nicht leer → Submit-Button disabled wenn ungültig
  → serial = nextSerial(zone.soa.serial)
  → zones.update(zone.domain, { ...zone, soa: { ...soaForm, serial } }, zone.view)
  → bei Erfolg: loadZoneDetail(zone.domain, zone.view) aufrufen, Modal schließen
  → bei Fehler: Fehlermeldung im Modal, Modal bleibt offen

View-aware Reload nach Speichern:
  `loadZoneDetail` wird um einen optionalen `view`-Parameter erweitert:
  ```typescript
  async function loadZoneDetail(domain: string, view?: string) {
    const result = view
      ? await zonesApi.getView(domain, view)
      : await zonesApi.get(domain)
    setSelectedZone(result.data)
  }
  ```
  Alle bestehenden Aufrufe von `loadZoneDetail(domain)` bleiben unverändert kompatibel.
```

---

## Fehlerbehandlung

- Leere Pflichtfelder (mname, rname) → Submit-Button disabled, kein API-Call
- API-Fehler → Fehlermeldung unterhalb der Felder im Modal anzeigen, Modal bleibt offen
- Zone ohne SOA → SOA-Zeile nicht rendern (defensiver Fallback für evtl. ältere Datensätze)
- Race condition (server-seitiger Serial-Update zwischen Laden und Speichern): akzeptiertes Risiko; `nextSerial()` erhöht immer relativ zum zuletzt geladenen Wert — kein Mechanismus zur Erkennung nötig

---

## Nicht im Scope

- Serial manuell überschreiben (wird automatisch via `nextSerial()` erhöht)
- SOA beim Anlegen einer Zone konfigurieren (weiterhin auto-generiert)
- Backend-Änderungen
- RFC-Validierung der SOA-Werte (z. B. Refresh > Retry)

---

## Betroffene Dateien

| Datei | Art der Änderung |
|---|---|
| `dashboard/lib/api.ts` | `SOA`-Interface + `soa?`-Feld in `Zone` + `zones.update()` Funktion |
| `dashboard/app/dashboard/zones/page.tsx` | SOA-Zeile in Tabelle + Modal + State (`soaModalOpen`, `soaForm: SOA`) |
