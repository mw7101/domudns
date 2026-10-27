package api

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/mw7101/domudns/internal/dns"
	mdns "github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// maxZoneFileSize is the maximum accepted zone file size (10 MB).
const maxZoneFileSize = 10 * 1024 * 1024

// axfrDialTimeout is the TCP dial timeout for AXFR transfers.
const axfrDialTimeout = 5 * time.Second

// axfrReadTimeout is the read timeout for AXFR transfers.
const axfrReadTimeout = 30 * time.Second

// ImportExportHandler handles zone import and export operations.
type ImportExportHandler struct {
	store      ZoneStore
	zoneReload ZoneReloader
}

// NewImportExportHandler creates a new ImportExportHandler.
func NewImportExportHandler(store ZoneStore, zoneReload ZoneReloader) *ImportExportHandler {
	return &ImportExportHandler{store: store, zoneReload: zoneReload}
}

// ServeHTTP routes import/export requests.
func (h *ImportExportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(path, "/export"):
		h.handleExportZone(w, r)
	case r.Method == http.MethodPost && path == "/api/zones/import":
		h.handleImportZoneFile(w, r)
	case r.Method == http.MethodPost && path == "/api/zones/import/axfr":
		h.handleImportAXFR(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// handleExportZone exports a zone as an RFC 1035 zone file.
// GET /api/zones/{domain}/export?view=
func (h *ImportExportHandler) handleExportZone(w http.ResponseWriter, r *http.Request) {
	// Extract domain from path: /api/zones/{domain}/export
	path := strings.TrimPrefix(r.URL.Path, "/api/zones/")
	domain := strings.TrimSuffix(path, "/export")
	if domain == "" || !dns.IsValidDomain(domain) {
		writeError(w, http.StatusBadRequest, "INVALID_ZONE", "Invalid domain name")
		return
	}

	view := r.URL.Query().Get("view")
	if view != "" && !isValidViewName(view) {
		writeError(w, http.StatusBadRequest, "INVALID_VIEW", "Invalid view name (only [a-z0-9_-] allowed)")
		return
	}

	ctx := r.Context()
	var zone *dns.Zone
	var err error
	if view != "" {
		zone, err = h.store.GetZoneView(ctx, domain, view)
	} else {
		zone, err = h.store.GetZone(ctx, domain)
	}
	if err != nil {
		if err == dns.ErrZoneNotFound {
			writeError(w, http.StatusNotFound, "ZONE_NOT_FOUND", "Zone not found")
			return
		}
		writeInternalError(w, "DB_ERROR", err)
		return
	}

	zone.EnsureSOA()

	var sb strings.Builder
	sb.WriteString("$ORIGIN " + mdns.Fqdn(zone.Domain) + "\n")
	sb.WriteString(fmt.Sprintf("$TTL %d\n", zone.TTL))

	// SOA record
	if zone.SOA != nil {
		sb.WriteString(fmt.Sprintf("%s %d IN SOA %s %s %d %d %d %d %d\n",
			mdns.Fqdn(zone.Domain),
			zone.TTL,
			mdns.Fqdn(zone.SOA.MName),
			mdns.Fqdn(zone.SOA.RName),
			zone.SOA.Serial,
			zone.SOA.Refresh,
			zone.SOA.Retry,
			zone.SOA.Expire,
			zone.SOA.Minimum,
		))
	}

	// All other records
	for _, rec := range zone.Records {
		if rec.Type == dns.TypeFWD || rec.Type == dns.TypeSOA {
			continue
		}
		rr := exportRecordToRR(zone, rec)
		if rr == nil {
			continue
		}
		sb.WriteString(rr.String() + "\n")
	}

	filename := domain + ".zone"
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, sb.String())
}

// handleImportZoneFile imports an RFC 1035 zone file via multipart upload.
// POST /api/zones/import (multipart/form-data, fields: file, domain, view)
func (h *ImportExportHandler) handleImportZoneFile(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(maxZoneFileSize); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Failed to parse multipart form")
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "MISSING_FILE", "Zone file is required (field: file)")
		return
	}
	defer file.Close()

	domain := strings.TrimSpace(r.FormValue("domain"))
	view := strings.TrimSpace(r.FormValue("view"))

	if view != "" && !isValidViewName(view) {
		writeError(w, http.StatusBadRequest, "INVALID_VIEW", "Invalid view name (only [a-z0-9_-] allowed)")
		return
	}

	// Determine origin for the parser
	origin := ""
	if domain != "" {
		if !dns.IsValidDomain(domain) {
			writeError(w, http.StatusBadRequest, "INVALID_ZONE", "Invalid domain name")
			return
		}
		origin = mdns.Fqdn(domain)
	}

	rrs, parseErr := parseZoneFile(file, origin)
	if parseErr != nil {
		writeError(w, http.StatusBadRequest, "INVALID_ZONE_FILE", parseErr.Error())
		return
	}
	if len(rrs) == 0 {
		writeError(w, http.StatusBadRequest, "EMPTY_ZONE_FILE", "Zone file contains no valid records")
		return
	}

	// Extract domain from SOA if not provided
	if domain == "" {
		for _, rr := range rrs {
			if soa, ok := rr.(*mdns.SOA); ok {
				domain = strings.TrimSuffix(soa.Hdr.Name, ".")
				break
			}
		}
	}
	if domain == "" {
		writeError(w, http.StatusBadRequest, "MISSING_DOMAIN", "Domain could not be determined; include a SOA record or pass domain= form field")
		return
	}
	if !dns.IsValidDomain(domain) {
		writeError(w, http.StatusBadRequest, "INVALID_ZONE", "Invalid domain name extracted from zone file")
		return
	}

	imported, merged, err := h.importAndMerge(r.Context(), rrs, domain, view)
	if err != nil {
		writeInternalError(w, "IMPORT_ERROR", err)
		return
	}

	log.Info().
		Str("zone", domain).
		Str("view", view).
		Int("imported", imported).
		Int("merged", merged).
		Msg("zone file imported")

	writeSuccess(w, map[string]interface{}{
		"zone":     domain,
		"imported": imported,
		"merged":   merged,
	}, http.StatusOK)
}

// handleImportAXFR imports a zone via AXFR from a remote DNS server.
// POST /api/zones/import/axfr
// Body: {"server": "1.2.3.4:53", "domain": "example.com", "view": ""}
func (h *ImportExportHandler) handleImportAXFR(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Server string `json:"server"`
		Domain string `json:"domain"`
		View   string `json:"view"`
	}
	if err := DecodeJSON(r, &req, 0); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return
	}

	req.Server = strings.TrimSpace(req.Server)
	req.Domain = strings.TrimSpace(req.Domain)
	req.View = strings.TrimSpace(req.View)

	if req.Server == "" {
		writeError(w, http.StatusBadRequest, "MISSING_SERVER", "server is required")
		return
	}
	if req.Domain == "" {
		writeError(w, http.StatusBadRequest, "MISSING_DOMAIN", "domain is required")
		return
	}
	if !dns.IsValidDomain(req.Domain) {
		writeError(w, http.StatusBadRequest, "INVALID_DOMAIN", "Invalid domain name")
		return
	}
	if req.View != "" && !isValidViewName(req.View) {
		writeError(w, http.StatusBadRequest, "INVALID_VIEW", "Invalid view name (only [a-z0-9_-] allowed)")
		return
	}

	// Normalize server address (ensure port)
	server := req.Server
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = server + ":53"
	}

	rrs, err := axfrTransfer(server, req.Domain)
	if err != nil {
		writeError(w, http.StatusBadGateway, "AXFR_ERROR", fmt.Sprintf("AXFR transfer failed: %s", err.Error()))
		return
	}
	if len(rrs) == 0 {
		writeError(w, http.StatusBadGateway, "AXFR_EMPTY", "AXFR transfer returned no records")
		return
	}

	imported, merged, err := h.importAndMerge(r.Context(), rrs, req.Domain, req.View)
	if err != nil {
		writeInternalError(w, "IMPORT_ERROR", err)
		return
	}

	log.Info().
		Str("zone", req.Domain).
		Str("server", req.Server).
		Int("imported", imported).
		Int("merged", merged).
		Msg("zone imported via AXFR")

	writeSuccess(w, map[string]interface{}{
		"zone":     req.Domain,
		"imported": imported,
		"merged":   merged,
	}, http.StatusOK)
}

// importAndMerge converts RRs to a zone, merges with an existing zone (if any), and stores it.
// Returns (imported record count, merged record count, error).
func (h *ImportExportHandler) importAndMerge(ctx context.Context, rrs []mdns.RR, domain, view string) (imported, merged int, err error) {
	zone := rrsToZone(rrs, domain, view)
	if zone.TTL == 0 {
		zone.TTL = 3600
	}
	zone.EnsureSOA()
	imported = len(zone.Records)

	// Load existing zone for merge
	var existing *dns.Zone
	if view != "" {
		existing, _ = h.store.GetZoneView(ctx, domain, view)
	} else {
		existing, _ = h.store.GetZone(ctx, domain)
	}
	if existing != nil {
		zone, merged = mergeZones(existing, zone)
	}

	if err := h.store.PutZone(ctx, zone); err != nil {
		return 0, 0, fmt.Errorf("importAndMerge: store zone: %w", err)
	}

	h.triggerReload()
	return imported, merged, nil
}

// triggerReload calls the zone reloader asynchronously (fire-and-forget).
func (h *ImportExportHandler) triggerReload() {
	if h.zoneReload == nil {
		return
	}
	go func() {
		if err := h.zoneReload(); err != nil {
			log.Warn().Err(err).Msg("zone reload after import failed")
		}
	}()
}

// --- Parsing Helpers ---

// parseZoneFile parses an RFC 1035 zone file and returns all valid RRs.
func parseZoneFile(r io.Reader, origin string) ([]mdns.RR, error) {
	var rrs []mdns.RR
	zp := mdns.NewZoneParser(r, origin, "")
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		rrs = append(rrs, rr)
	}
	if err := zp.Err(); err != nil {
		return nil, fmt.Errorf("zone file parse error: %w", err)
	}
	return rrs, nil
}

// axfrTransfer performs an AXFR zone transfer from a remote server.
func axfrTransfer(server, domain string) ([]mdns.RR, error) {
	msg := new(mdns.Msg)
	msg.SetAxfr(mdns.Fqdn(domain))

	t := &mdns.Transfer{
		DialTimeout: axfrDialTimeout,
		ReadTimeout: axfrReadTimeout,
	}
	ch, err := t.In(msg, server)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", server, err)
	}

	var rrs []mdns.RR
	for env := range ch {
		if env.Error != nil {
			return nil, fmt.Errorf("transfer error: %w", env.Error)
		}
		rrs = append(rrs, env.RR...)
	}
	return rrs, nil
}

// --- Conversion Helpers ---

// rrsToZone converts a list of miekg/dns RRs to a dns.Zone.
// SOA is stored in zone.SOA; all other supported record types are converted to Records.
func rrsToZone(rrs []mdns.RR, domain, view string) *dns.Zone {
	zone := &dns.Zone{
		Domain:  domain,
		View:    view,
		TTL:     3600,
		Records: []dns.Record{},
	}

	nextID := 1
	for _, rr := range rrs {
		if soa, ok := rr.(*mdns.SOA); ok {
			zone.SOA = &dns.SOA{
				MName:   strings.TrimSuffix(soa.Ns, "."),
				RName:   strings.TrimSuffix(soa.Mbox, "."),
				Serial:  soa.Serial,
				Refresh: int(soa.Refresh),
				Retry:   int(soa.Retry),
				Expire:  int(soa.Expire),
				Minimum: int(soa.Minttl),
			}
			if int(rr.Header().Ttl) > 0 {
				zone.TTL = int(rr.Header().Ttl)
			}
			continue
		}

		rec, ok := rrToRecord(rr, domain)
		if !ok {
			continue
		}
		if int(rr.Header().Ttl) > 0 {
			rec.TTL = int(rr.Header().Ttl)
		}
		rec.ID = nextID
		nextID++
		zone.Records = append(zone.Records, rec)
	}

	return zone
}

// rrToRecord converts a single miekg/dns RR to an internal dns.Record.
// Returns (record, true) on success, (_, false) if the RR type is unsupported.
func rrToRecord(rr mdns.RR, zoneDomain string) (dns.Record, bool) {
	hdr := rr.Header()
	name := normalizeRecordName(strings.TrimSuffix(hdr.Name, "."), zoneDomain)

	switch v := rr.(type) {
	case *mdns.A:
		return dns.Record{Name: name, Type: dns.TypeA, Value: v.A.String()}, true
	case *mdns.AAAA:
		return dns.Record{Name: name, Type: dns.TypeAAAA, Value: v.AAAA.String()}, true
	case *mdns.CNAME:
		return dns.Record{Name: name, Type: dns.TypeCNAME, Value: strings.TrimSuffix(v.Target, ".")}, true
	case *mdns.MX:
		return dns.Record{Name: name, Type: dns.TypeMX, Priority: int(v.Preference), Value: strings.TrimSuffix(v.Mx, ".")}, true
	case *mdns.TXT:
		return dns.Record{Name: name, Type: dns.TypeTXT, Value: strings.Join(v.Txt, " ")}, true
	case *mdns.NS:
		return dns.Record{Name: name, Type: dns.TypeNS, Value: strings.TrimSuffix(v.Ns, ".")}, true
	case *mdns.SRV:
		return dns.Record{Name: name, Type: dns.TypeSRV, Priority: int(v.Priority), Weight: int(v.Weight), Port: int(v.Port), Value: strings.TrimSuffix(v.Target, ".")}, true
	case *mdns.PTR:
		return dns.Record{Name: name, Type: dns.TypePTR, Value: strings.TrimSuffix(v.Ptr, ".")}, true
	case *mdns.CAA:
		return dns.Record{Name: name, Type: dns.TypeCAA, Priority: int(v.Flag), Tag: v.Tag, Value: v.Value}, true
	case *mdns.DNAME:
		return dns.Record{Name: name, Type: dns.TypeDNAME, Value: strings.TrimSuffix(v.Target, ".")}, true
	default:
		log.Debug().
			Str("type", mdns.TypeToString[hdr.Rrtype]).
			Str("name", name).
			Msg("zone import: skipping unsupported record type")
		return dns.Record{}, false
	}
}

// normalizeRecordName converts an FQDN record name to an internal label.
// "example.com" → "@"; "www.example.com" → "www"
func normalizeRecordName(fqdn, zoneDomain string) string {
	zoneDomain = strings.ToLower(strings.TrimSuffix(zoneDomain, "."))
	fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))
	if fqdn == zoneDomain {
		return "@"
	}
	suffix := "." + zoneDomain
	if strings.HasSuffix(fqdn, suffix) {
		return strings.TrimSuffix(fqdn, suffix)
	}
	return fqdn
}

// mergeZones merges an imported zone into an existing zone.
// For each (Name, Type) group in imported.Records, all matching records in existing
// are replaced by the imported ones. Unaffected records remain unchanged.
// Returns the merged zone and the count of replaced existing records.
func mergeZones(existing, imported *dns.Zone) (*dns.Zone, int) {
	type nameType struct {
		name string
		typ  dns.RecordType
	}

	// Build a set of (Name, Type) groups present in the import
	importedGroups := make(map[nameType]struct{}, len(imported.Records))
	for _, rec := range imported.Records {
		importedGroups[nameType{rec.Name, rec.Type}] = struct{}{}
	}

	// Keep existing records whose (Name, Type) is not in the import
	merged := 0
	var kept []dns.Record
	for _, rec := range existing.Records {
		if _, replaced := importedGroups[nameType{rec.Name, rec.Type}]; replaced {
			merged++
		} else {
			kept = append(kept, rec)
		}
	}

	// Combine kept + imported records and reassign IDs
	all := append(kept, imported.Records...)
	for i := range all {
		all[i].ID = i + 1
	}

	result := *imported
	result.Records = all
	if result.Records == nil {
		result.Records = []dns.Record{}
	}

	// Keep existing SOA if import did not provide one
	if result.SOA == nil && existing.SOA != nil {
		result.SOA = existing.SOA
	}
	// Keep existing TTL if import uses default
	if result.TTL == 0 {
		result.TTL = existing.TTL
	}

	return &result, merged
}

// exportRecordToRR converts an internal dns.Record to a miekg/dns RR for zone file export.
func exportRecordToRR(zone *dns.Zone, rec dns.Record) mdns.RR {
	var fqdn string
	if rec.Name == "@" || rec.Name == "" {
		fqdn = mdns.Fqdn(zone.Domain)
	} else {
		fqdn = mdns.Fqdn(rec.Name + "." + zone.Domain)
	}

	ttl := uint32(rec.TTL)
	if ttl == 0 {
		ttl = uint32(zone.TTL)
		if ttl == 0 {
			ttl = 3600
		}
	}

	hdr := mdns.RR_Header{Name: fqdn, Class: mdns.ClassINET, Ttl: ttl}
	switch rec.Type {
	case dns.TypeA:
		ip := net.ParseIP(rec.Value)
		if ip == nil || ip.To4() == nil {
			return nil
		}
		hdr.Rrtype = mdns.TypeA
		return &mdns.A{Hdr: hdr, A: ip.To4()}
	case dns.TypeAAAA:
		ip := net.ParseIP(rec.Value)
		if ip == nil {
			return nil
		}
		hdr.Rrtype = mdns.TypeAAAA
		return &mdns.AAAA{Hdr: hdr, AAAA: ip.To16()}
	case dns.TypeCNAME:
		hdr.Rrtype = mdns.TypeCNAME
		return &mdns.CNAME{Hdr: hdr, Target: mdns.Fqdn(rec.Value)}
	case dns.TypeMX:
		hdr.Rrtype = mdns.TypeMX
		return &mdns.MX{Hdr: hdr, Preference: uint16(rec.Priority), Mx: mdns.Fqdn(rec.Value)}
	case dns.TypeTXT:
		hdr.Rrtype = mdns.TypeTXT
		return &mdns.TXT{Hdr: hdr, Txt: []string{rec.Value}}
	case dns.TypeNS:
		hdr.Rrtype = mdns.TypeNS
		return &mdns.NS{Hdr: hdr, Ns: mdns.Fqdn(rec.Value)}
	case dns.TypeSRV:
		hdr.Rrtype = mdns.TypeSRV
		return &mdns.SRV{Hdr: hdr, Priority: uint16(rec.Priority), Weight: uint16(rec.Weight), Port: uint16(rec.Port), Target: mdns.Fqdn(rec.Value)}
	case dns.TypePTR:
		hdr.Rrtype = mdns.TypePTR
		return &mdns.PTR{Hdr: hdr, Ptr: mdns.Fqdn(rec.Value)}
	case dns.TypeCAA:
		hdr.Rrtype = mdns.TypeCAA
		return &mdns.CAA{Hdr: hdr, Flag: uint8(rec.Priority), Tag: rec.Tag, Value: rec.Value}
	case dns.TypeDNAME:
		hdr.Rrtype = mdns.TypeDNAME
		return &mdns.DNAME{Hdr: hdr, Target: mdns.Fqdn(rec.Value)}
	default:
		return nil
	}
}
