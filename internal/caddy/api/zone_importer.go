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
	"github.com/mw7101/domudns/internal/store"
	mdns "github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

const maxAXFRRecords = 50000

// maxZoneFileSize is the maximum accepted zone file size (10 MB).
const maxZoneFileSize = 10 * 1024 * 1024

// axfrDialTimeout is the TCP dial timeout for AXFR transfers.
const axfrDialTimeout = 5 * time.Second

// axfrReadTimeout is the read timeout for AXFR transfers.
const axfrReadTimeout = 30 * time.Second

// ImportExportHandler handles zone import and export operations.
// It is shared between zone_importer.go (import) and zone_exporter.go (export).
type ImportExportHandler struct {
	store      store.ZoneStore
	zoneReload ZoneReloader
}

// NewImportExportHandler creates a new ImportExportHandler.
func NewImportExportHandler(store store.ZoneStore, zoneReload ZoneReloader) *ImportExportHandler {
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

// handleImportZoneFile imports an RFC 1035 zone file via multipart upload.
// POST /api/zones/import (multipart/form-data, fields: file, domain, view)
func (h *ImportExportHandler) handleImportZoneFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxZoneFileSize)
	if err := r.ParseMultipartForm(maxZoneFileSize); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Failed to parse multipart form")
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "MISSING_FILE", "Zone file is required (field: file)")
		return
	}
	defer func() { _ = file.Close() }()

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

	rrs, ok := parseUploadedZoneFile(w, file, origin)
	if !ok {
		return
	}

	domain, ok = resolveImportDomain(w, rrs, domain)
	if !ok {
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

// axfrImportRequest is the decoded POST body for an AXFR zone import.
type axfrImportRequest struct {
	Server string `json:"server"`
	Domain string `json:"domain"`
	View   string `json:"view"`
}

// parseAXFRImportRequest decodes and validates the AXFR import request
// body. Writes the error response itself on failure.
func parseAXFRImportRequest(w http.ResponseWriter, r *http.Request) (axfrImportRequest, bool) {
	var req axfrImportRequest
	if err := DecodeJSON(r, &req, 0); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return axfrImportRequest{}, false
	}
	req.Server = strings.TrimSpace(req.Server)
	req.Domain = strings.TrimSpace(req.Domain)
	req.View = strings.TrimSpace(req.View)

	if req.Server == "" {
		writeError(w, http.StatusBadRequest, "MISSING_SERVER", "server is required")
		return axfrImportRequest{}, false
	}
	if req.Domain == "" {
		writeError(w, http.StatusBadRequest, "MISSING_DOMAIN", "domain is required")
		return axfrImportRequest{}, false
	}
	if !dns.IsValidDomain(req.Domain) {
		writeError(w, http.StatusBadRequest, "INVALID_DOMAIN", "Invalid domain name")
		return axfrImportRequest{}, false
	}
	if req.View != "" && !isValidViewName(req.View) {
		writeError(w, http.StatusBadRequest, "INVALID_VIEW", "Invalid view name (only [a-z0-9_-] allowed)")
		return axfrImportRequest{}, false
	}
	return req, true
}

// resolveAXFRServer normalizes server to host:port (default :53) and
// rejects private/loopback targets (SSRF prevention). Writes the error
// response itself on failure.
func resolveAXFRServer(w http.ResponseWriter, rawServer string) (string, bool) {
	server := rawServer
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = server + ":53"
	}
	if err := validateAXFRServer(server); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_SERVER", err.Error())
		return "", false
	}
	return server, true
}

// handleImportAXFR imports a zone via AXFR from a remote DNS server.
// POST /api/zones/import/axfr
// Body: {"server": "1.2.3.4:53", "domain": "example.com", "view": ""}
func (h *ImportExportHandler) handleImportAXFR(w http.ResponseWriter, r *http.Request) {
	req, ok := parseAXFRImportRequest(w, r)
	if !ok {
		return
	}

	server, ok := resolveAXFRServer(w, req.Server)
	if !ok {
		return
	}

	rrs, err := axfrTransfer(server, req.Domain)
	if err != nil {
		writeInternalError(w, "AXFR_ERROR", fmt.Errorf("axfr transfer from %s: %w", server, err))
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

// parseUploadedZoneFile parses the uploaded RFC 1035 zone file and rejects
// an empty result. Writes the error response itself on failure.
func parseUploadedZoneFile(w http.ResponseWriter, file io.Reader, origin string) ([]mdns.RR, bool) {
	rrs, parseErr := parseZoneFile(file, origin)
	if parseErr != nil {
		writeError(w, http.StatusBadRequest, "INVALID_ZONE_FILE", parseErr.Error())
		return nil, false
	}
	if len(rrs) == 0 {
		writeError(w, http.StatusBadRequest, "EMPTY_ZONE_FILE", "Zone file contains no valid records")
		return nil, false
	}
	return rrs, true
}

// resolveImportDomain returns domain if given, otherwise extracts it from
// the zone file's SOA record. Writes the error response itself on failure.
func resolveImportDomain(w http.ResponseWriter, rrs []mdns.RR, domain string) (string, bool) {
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
		return "", false
	}
	if !dns.IsValidDomain(domain) {
		writeError(w, http.StatusBadRequest, "INVALID_ZONE", "Invalid domain name extracted from zone file")
		return "", false
	}
	return domain, true
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

// validateAXFRServer rejects private/loopback IPs to prevent SSRF.
func validateAXFRServer(server string) error {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return fmt.Errorf("invalid server address")
	}
	ips, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("cannot resolve server hostname")
	}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("AXFR to private/loopback addresses is not allowed")
		}
	}
	return nil
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
		if len(rrs) > maxAXFRRecords {
			return nil, fmt.Errorf("AXFR exceeded maximum record count (%d)", maxAXFRRecords)
		}
	}
	return rrs, nil
}

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

		// Skip RRs whose owner name is neither the zone apex nor inside the
		// zone. normalizeRecordName leaves an out-of-zone FQDN unchanged, and
		// such a record could be stored but never served.
		fqdn := strings.ToLower(strings.TrimSuffix(rr.Header().Name, "."))
		zd := strings.ToLower(strings.TrimSuffix(domain, "."))
		if fqdn != zd && !strings.HasSuffix(fqdn, "."+zd) {
			log.Debug().Str("name", rr.Header().Name).Str("zone", domain).Msg("zone import: skipping out-of-zone record")
			continue
		}

		rec, ok := rrToRecord(rr, domain)
		if !ok {
			continue
		}
		if int(rr.Header().Ttl) > 0 {
			rec.TTL = int(rr.Header().Ttl)
		}
		if err := dns.ValidateRecord(rec, domain); err != nil {
			log.Debug().Err(err).Str("name", rec.Name).Str("type", string(rec.Type)).Msg("zone import: skipping invalid record")
			continue
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
