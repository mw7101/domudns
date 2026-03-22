package dnsserver

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/mw7101/domudns/internal/dns"
	"github.com/mw7101/domudns/internal/store"
	miekgdns "github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// DDNSStats enthält laufende Statistiken des DDNS-Handlers.
type DDNSStats struct {
	TotalUpdates int64
	LastUpdateAt time.Time
	TotalFailed  int64
	LastError    string
	LastErrorAt  time.Time
	// LastRejectedReason gibt den Grund der letzten Ablehnung an (z.B. "NOTZONE: example.local", "NOTAUTH").
	LastRejectedReason string
	LastRejectedAt     time.Time
}

// DDNSHandler processes RFC 2136 UPDATE messages (Opcode=5).
// TSIG verification is done via miekg/dns ResponseWriter.TsigStatus() interface:
// The DNS server must be configured with TsigSecret — the handler only implements
// the status check and business logic.
type DDNSHandler struct {
	store        DDNSStoreProvider
	mu           sync.RWMutex
	secrets      map[string]string // keyname → base64 secret
	algorithms   map[string]string // keyname → algorithm URI
	zoneReloader func()
	// keyUpdater is called when keys change so the DNS server can update TsigSecret.
	keyUpdater func(map[string]string)

	statsMu sync.Mutex
	stats   DDNSStats
}

// NewDDNSHandler creates a new DDNSHandler.
// keyUpdater is set via SetDDNSHandler on the DNS server.
func NewDDNSHandler(store DDNSStoreProvider, zoneReloader func()) *DDNSHandler {
	h := &DDNSHandler{
		store:        store,
		secrets:      map[string]string{},
		algorithms:   map[string]string{},
		zoneReloader: zoneReloader,
	}
	return h
}

// SetZoneReloader sets the zone reload callback (can be set after initialization).
func (h *DDNSHandler) SetZoneReloader(fn func()) {
	h.mu.Lock()
	h.zoneReloader = fn
	h.mu.Unlock()
}

// UpdateKeys updates the TSIG keys (live-reload, no restart needed).
func (h *DDNSHandler) UpdateKeys(keys []store.TSIGKey) {
	secrets := make(map[string]string, len(keys))
	algorithms := make(map[string]string, len(keys))
	// miekg/dns looks up key names with trailing dot (FQDN) in TsigSecret.
	// dhcpd sends TSIG with key name "dhcp-dns." — without the trailing dot
	// the map lookup fails and TsigStatus() returns an error → NOTAUTH.
	tsigSecrets := make(map[string]string, len(keys))
	for _, k := range keys {
		secrets[k.Name] = k.Secret
		algorithms[k.Name] = tsigAlgorithmURI(k.Algorithm)
		fqdn := k.Name
		if !strings.HasSuffix(fqdn, ".") {
			fqdn += "."
		}
		tsigSecrets[fqdn] = k.Secret
	}

	h.mu.Lock()
	h.secrets = secrets
	h.algorithms = algorithms
	h.mu.Unlock()

	// Update DNS server TsigSecret (with trailing dots for miekg lookup)
	if h.keyUpdater != nil {
		h.keyUpdater(tsigSecrets)
	}

	log.Info().Int("count", len(keys)).Msg("ddns: TSIG keys updated")
}

// GetStats gibt eine Snapshot-Kopie der aktuellen DDNS-Statistiken zurück.
func (h *DDNSHandler) GetStats() DDNSStats {
	h.statsMu.Lock()
	defer h.statsMu.Unlock()
	return h.stats
}

// recordRejection zählt eine abgelehnte UPDATE-Anfrage mit Grund.
func (h *DDNSHandler) recordRejection(reason string) {
	h.statsMu.Lock()
	h.stats.TotalFailed++
	h.stats.LastRejectedReason = reason
	h.stats.LastRejectedAt = time.Now().UTC()
	h.statsMu.Unlock()
}

// GetSecrets returns a copy of the secrets map with trailing dots (for miekg TsigSecret).
func (h *DDNSHandler) GetSecrets() map[string]string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	cp := make(map[string]string, len(h.secrets))
	for k, v := range h.secrets {
		fqdn := k
		if !strings.HasSuffix(fqdn, ".") {
			fqdn += "."
		}
		cp[fqdn] = v
	}
	return cp
}

// Handle verarbeitet eine RFC 2136 UPDATE-Nachricht.
func (h *DDNSHandler) Handle(w miekgdns.ResponseWriter, r *miekgdns.Msg) {
	log.Info().
		Str("remote", w.RemoteAddr().String()).
		Msg("ddns: RFC 2136 UPDATE empfangen")

	h.mu.RLock()
	hasKeys := len(h.secrets) > 0
	h.mu.RUnlock()

	// No keys configured → reject all UPDATEs
	if !hasKeys {
		log.Warn().
			Str("remote", w.RemoteAddr().String()).
			Msg("ddns: UPDATE abgelehnt — keine TSIG-Keys konfiguriert")
		h.respond(w, r, miekgdns.RcodeRefused)
		return
	}

	// Check TSIG status (already verified by miekg DNS server)
	if w.TsigStatus() != nil {
		log.Warn().
			Err(w.TsigStatus()).
			Str("remote", w.RemoteAddr().String()).
			Msg("ddns: TSIG-Verifikation fehlgeschlagen")
		h.recordRejection("NOTAUTH: TSIG-Verifikation fehlgeschlagen")
		h.respond(w, r, miekgdns.RcodeNotAuth)
		return
	}

	// No TSIG in message but keys configured → NOTAUTH
	if r.IsTsig() == nil {
		log.Warn().
			Str("remote", w.RemoteAddr().String()).
			Msg("ddns: UPDATE ohne TSIG abgelehnt (Keys konfiguriert)")
		h.recordRejection("NOTAUTH: UPDATE ohne TSIG")
		h.respond(w, r, miekgdns.RcodeNotAuth)
		return
	}

	h.processUpdate(w, r)
}

// processUpdate processes the actual UPDATE logic after TSIG validation.
func (h *DDNSHandler) processUpdate(w miekgdns.ResponseWriter, r *miekgdns.Msg) {
	if len(r.Question) == 0 {
		h.respond(w, r, miekgdns.RcodeFormatError)
		return
	}

	zoneName := r.Question[0].Name // FQDN with trailing dot
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Check zone existence
	zoneDomain := strings.TrimSuffix(zoneName, ".")
	zone, err := h.store.GetZone(ctx, zoneDomain)
	if err != nil || zone == nil {
		log.Warn().
			Str("zone", zoneDomain).
			Msg("ddns: Zone nicht gefunden — Zone muss in DomU DNS angelegt sein")
		h.recordRejection("NOTZONE: " + zoneDomain)
		h.respond(w, r, miekgdns.RcodeNotZone)
		return
	}

	// Process UPDATE records (Ns section = Update section per RFC 2136)
	for _, rr := range r.Ns {
		if err := h.applyUpdate(ctx, zone, rr); err != nil {
			log.Error().
				Err(err).
				Str("zone", zoneDomain).
				Str("rr", rr.String()).
				Msg("ddns: Update-Record fehlgeschlagen")
			h.statsMu.Lock()
			h.stats.TotalFailed++
			h.stats.LastError = err.Error()
			h.stats.LastErrorAt = time.Now().UTC()
			h.stats.LastRejectedReason = "SERVFAIL: " + err.Error()
			h.stats.LastRejectedAt = time.Now().UTC()
			h.statsMu.Unlock()
			h.respond(w, r, miekgdns.RcodeServerFailure)
			return
		}
	}

	// Zone reload after successful changes
	h.mu.RLock()
	zr := h.zoneReloader
	h.mu.RUnlock()
	if zr != nil {
		go zr()
	}

	log.Info().
		Str("zone", zoneDomain).
		Int("updates", len(r.Ns)).
		Str("remote", w.RemoteAddr().String()).
		Msg("ddns: UPDATE erfolgreich")

	h.statsMu.Lock()
	h.stats.TotalUpdates++
	h.stats.LastUpdateAt = time.Now().UTC()
	h.statsMu.Unlock()

	h.respond(w, r, miekgdns.RcodeSuccess)
}

// applyUpdate applies a single update record to the zone.
func (h *DDNSHandler) applyUpdate(ctx context.Context, zone *dns.Zone, rr miekgdns.RR) error {
	hdr := rr.Header()

	switch hdr.Class {
	case miekgdns.ClassINET:
		// Add or update record (Upsert-Semantik)
		record, err := rrToRecord(rr, zone.Domain)
		if err != nil {
			return err
		}
		if record == nil {
			log.Debug().Str("type", miekgdns.TypeToString[hdr.Rrtype]).Msg("ddns: RR-Typ nicht unterstützt, ignoriert")
			return nil
		}
		// Upsert: existierende Records gleichen Namens+Typs zuerst löschen,
		// damit dhcpd-Retries und IP-Wechsel keine Duplikate erzeugen.
		existing, listErr := h.store.GetRecords(ctx, zone.Domain)
		if listErr == nil {
			for _, ex := range existing {
				if ex.Name == record.Name && string(ex.Type) == string(record.Type) {
					if err := h.store.DeleteRecord(ctx, zone.Domain, ex.ID); err != nil {
						log.Warn().Err(err).Int("id", ex.ID).Msg("ddns: Upsert — alter Record konnte nicht gelöscht werden")
					}
				}
			}
		}
		return h.store.PutRecord(ctx, zone.Domain, record)

	case miekgdns.ClassNONE:
		// Delete specific record (name + type + value match)
		return h.deleteMatchingRecord(ctx, zone, rr)

	case miekgdns.ClassANY:
		// Delete all records with this name (and optionally type)
		return h.deleteRecordsByName(ctx, zone, rr)

	default:
		log.Debug().Uint16("class", hdr.Class).Msg("ddns: unbekannte CLASS im UPDATE, ignoriert")
		return nil
	}
}

// deleteMatchingRecord deletes a specific record by name+type+value.
func (h *DDNSHandler) deleteMatchingRecord(ctx context.Context, zone *dns.Zone, rr miekgdns.RR) error {
	hdr := rr.Header()
	targetName := normalizeRRName(hdr.Name, zone.Domain)

	records, err := h.store.GetRecords(ctx, zone.Domain)
	if err != nil {
		return err
	}

	targetType := miekgdns.TypeToString[hdr.Rrtype]
	targetValue := rrValue(rr)

	for _, rec := range records {
		recName := rec.Name
		if recName == "@" {
			recName = ""
		}
		if recName == targetName &&
			string(rec.Type) == targetType &&
			(targetValue == "" || rec.Value == targetValue) {
			if err := h.store.DeleteRecord(ctx, zone.Domain, rec.ID); err != nil {
				log.Warn().Err(err).Int("id", rec.ID).Msg("ddns: Record löschen fehlgeschlagen")
			}
		}
	}
	return nil
}

// deleteRecordsByName deletes all records of a name (ClassANY).
func (h *DDNSHandler) deleteRecordsByName(ctx context.Context, zone *dns.Zone, rr miekgdns.RR) error {
	hdr := rr.Header()
	targetName := normalizeRRName(hdr.Name, zone.Domain)

	records, err := h.store.GetRecords(ctx, zone.Domain)
	if err != nil {
		return err
	}

	// If Qtype ANY: all records of this name; otherwise only records with matching type
	filterType := ""
	if hdr.Rrtype != miekgdns.TypeANY {
		filterType = miekgdns.TypeToString[hdr.Rrtype]
	}

	for _, rec := range records {
		recName := rec.Name
		if recName == "@" {
			recName = ""
		}
		if recName != targetName {
			continue
		}
		if filterType != "" && string(rec.Type) != filterType {
			continue
		}
		if err := h.store.DeleteRecord(ctx, zone.Domain, rec.ID); err != nil {
			log.Warn().Err(err).Int("id", rec.ID).Msg("ddns: Record löschen fehlgeschlagen")
		}
	}
	return nil
}

// respond sends a TSIG-signed response.
// miekg signs the response only when the response message itself contains a TSIG RR —
// it does NOT add TSIG automatically. We call SetTsig() so WriteMsg() can compute the MAC.
func (h *DDNSHandler) respond(w miekgdns.ResponseWriter, r *miekgdns.Msg, rcode int) {
	resp := new(miekgdns.Msg)
	resp.SetRcode(r, rcode)
	if t := r.IsTsig(); t != nil {
		resp.SetTsig(t.Hdr.Name, t.Algorithm, 300, time.Now().Unix())
	}
	if err := w.WriteMsg(resp); err != nil {
		log.Error().Err(err).Msg("ddns: response write failed")
	}
}

// rrToRecord converts a miekg/dns RR to a dns.Record.
// Returns (nil, nil) if the type is not supported.
func rrToRecord(rr miekgdns.RR, zoneDomain string) (*dns.Record, error) {
	hdr := rr.Header()
	name := normalizeRRName(hdr.Name, zoneDomain)
	if name == "" {
		name = "@"
	}

	ttl := int(hdr.Ttl)
	if ttl == 0 {
		ttl = 60
	}

	switch v := rr.(type) {
	case *miekgdns.A:
		return &dns.Record{
			Name:  name,
			Type:  dns.TypeA,
			TTL:   ttl,
			Value: v.A.String(),
		}, nil

	case *miekgdns.AAAA:
		return &dns.Record{
			Name:  name,
			Type:  dns.TypeAAAA,
			TTL:   ttl,
			Value: v.AAAA.String(),
		}, nil

	case *miekgdns.CNAME:
		return &dns.Record{
			Name:  name,
			Type:  dns.TypeCNAME,
			TTL:   ttl,
			Value: strings.TrimSuffix(v.Target, "."),
		}, nil

	case *miekgdns.TXT:
		return &dns.Record{
			Name:  name,
			Type:  dns.TypeTXT,
			TTL:   ttl,
			Value: strings.Join(v.Txt, " "),
		}, nil

	case *miekgdns.PTR:
		return &dns.Record{
			Name:  name,
			Type:  dns.TypePTR,
			TTL:   ttl,
			Value: strings.TrimSuffix(v.Ptr, "."),
		}, nil

	default:
		return nil, nil // unbekannte Typen ignorieren
	}
}

// rrValue extracts the data value of an RR as string (for comparison when deleting).
func rrValue(rr miekgdns.RR) string {
	switch v := rr.(type) {
	case *miekgdns.A:
		return v.A.String()
	case *miekgdns.AAAA:
		return v.AAAA.String()
	case *miekgdns.CNAME:
		return strings.TrimSuffix(v.Target, ".")
	case *miekgdns.TXT:
		return strings.Join(v.Txt, " ")
	case *miekgdns.PTR:
		return strings.TrimSuffix(v.Ptr, ".")
	}
	return ""
}

// normalizeRRName extracts the subdomain label from an FQDN relative to the zone.
// Returns "" if the name equals the zone apex.
func normalizeRRName(fqdn, zoneDomain string) string {
	fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))
	zone := strings.ToLower(strings.TrimSuffix(zoneDomain, "."))
	if fqdn == zone {
		return "" // Apex
	}
	suffix := "." + zone
	if strings.HasSuffix(fqdn, suffix) {
		return strings.TrimSuffix(fqdn, suffix)
	}
	return fqdn
}

// tsigAlgorithmURI konvertiert einen lesbaren Algorithmus-Namen in die miekg/dns URI.
func tsigAlgorithmURI(algorithm string) string {
	switch strings.ToLower(algorithm) {
	case "hmac-sha256", "hmac_sha256":
		return miekgdns.HmacSHA256
	case "hmac-sha512", "hmac_sha512":
		return miekgdns.HmacSHA512
	case "hmac-sha1", "hmac_sha1":
		return miekgdns.HmacSHA1
	default:
		return miekgdns.HmacSHA256
	}
}
