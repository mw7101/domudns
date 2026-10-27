// Package api: PowerDNS-compatible REST API for third-party ACME DNS-01
// tooling (Proxmox VE "DNS-01 PowerDNS API" plugin, acme.sh dns_pdns).
//
// This is an additional, independent surface next to the native
// /api/acme/dns-01/* endpoints (acme.go) — it is not used internally and
// exists solely so external tools that only speak the PowerDNS Authoritative
// HTTP API (doc.powerdns.com/authoritative/http-api/zone.html) can manage
// TXT records (and, incidentally, any other record type) in an existing
// domudns zone.
//
// Supported subset (served at both the canonical and the legacy prefix):
//
//	GET   /api/v1/servers/{server_id}/zones
//	GET   /api/v1/servers/{server_id}/zones/{zone_id}
//	PATCH /api/v1/servers/{server_id}/zones/{zone_id}
//	PUT   /api/v1/servers/{server_id}/zones/{zone_id}/notify
//
// The canonical prefix is /api/v1/servers/ — what acme.sh's dns_pdns hook and
// the Proxmox VE "DNS-01 PowerDNS API" plugin build (acme.sh always inserts
// /api/v1/ and appends the notify call). /api/pdns/v1/servers/ is retained as
// a legacy alias and behaves identically.
//
// server_id is accepted but never inspected (PowerDNS convention — a client
// may use any value, e.g. "localhost"). Responses use the plain PowerDNS
// JSON shapes, not domudns's own {success,data,error} envelope, since real
// PowerDNS clients parse the former.
package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/mw7101/domudns/internal/dns"
	"github.com/mw7101/domudns/internal/dnsserver"
	"github.com/mw7101/domudns/internal/store"
	mdns "github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

const (
	// pdnsCanonicalAPIPrefix is the canonical PowerDNS Authoritative API path
	// prefix — acme.sh's dns_pdns hook and the Proxmox VE pdns plugin always
	// build /api/v1/servers/{server_id}/zones...
	pdnsCanonicalAPIPrefix = "/api/v1/servers/"
	// pdnsLegacyAPIPrefix is domudns's original path prefix, kept as an alias
	// so existing clients keep working.
	pdnsLegacyAPIPrefix = "/api/pdns/v1/servers/"
)

// pdnsRepresentableTypes lists the record types this compatibility layer can
// read and write. It mirrors the set dnsserver.BuildRR / rrToRecord (used
// for the reverse direction, in zone_importer.go) actually support — domudns
// synthetic types (FWD, ALIAS) and types domudns never serves live (SPF,
// URI) are intentionally excluded: skipped on GET, rejected with 422 on
// PATCH rather than silently corrupting the zone.
var pdnsRepresentableTypes = map[dns.RecordType]bool{
	dns.TypeA:     true,
	dns.TypeAAAA:  true,
	dns.TypeCNAME: true,
	dns.TypeMX:    true,
	dns.TypeTXT:   true,
	dns.TypeNS:    true,
	dns.TypeSRV:   true,
	dns.TypePTR:   true,
	dns.TypeCAA:   true,
	dns.TypeDNAME: true,
	dns.TypeSOA:   true, // zone.SOA field, handled outside the Records loop
}

// PDNSCompatHandler serves the PowerDNS-compatible zones API.
type PDNSCompatHandler struct {
	store      store.ZoneStore
	zoneReload ZoneReloader // optional, nil = no in-memory zone reload
}

// NewPDNSCompatHandler creates a PowerDNS-compat handler backed by store.
// store is the same ZoneStore instance passed to ZonesHandler/RecordsHandler
// so writes propagate through the cluster like any other zone change.
//
// zoneReload is optional. When set it is invoked after a successful PATCH so
// the master's in-memory authoritative zones pick up the change; without it
// the master keeps serving its startup snapshot and only slaves (which reload
// on cluster sync) see new records. See triggerZoneReload.
func NewPDNSCompatHandler(s store.ZoneStore, zoneReload ZoneReloader) *PDNSCompatHandler {
	return &PDNSCompatHandler{store: s, zoneReload: zoneReload}
}

// triggerZoneReload calls the zone reloader asynchronously (fire-and-forget),
// matching RecordsHandler.triggerZoneReload — a slow/failed reload must not
// fail or delay an otherwise successful PATCH response.
func (h *PDNSCompatHandler) triggerZoneReload() {
	if h.zoneReload == nil {
		return
	}
	go func() {
		if err := h.zoneReload(); err != nil {
			log.Warn().Err(err).Msg("zone reload after PowerDNS-compat change failed")
		}
	}()
}

// writePDNSError writes {"error": message} — the PowerDNS API's own error
// shape, distinct from domudns's {success,error:{code,message}} envelope,
// since real PowerDNS clients parse the former.
func writePDNSError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// ServeHTTP routes PowerDNS-compat requests:
// GET .../zones, GET .../zones/{zone_id}, PATCH .../zones/{zone_id},
// PUT .../zones/{zone_id}/notify.
func (h *PDNSCompatHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Exactly one prefix matches; TrimPrefix on the non-matching one is a no-op,
	// so applying both keeps the parse below identical for either path shape.
	path := strings.TrimPrefix(r.URL.Path, pdnsCanonicalAPIPrefix)
	path = strings.TrimPrefix(path, pdnsLegacyAPIPrefix)
	path = strings.Trim(path, "/")
	// path is now "{server_id}/zones[/{zone_id}]"; server_id can never
	// contain "/" here since SplitN below splits on the first one, so no
	// further validation of it is needed — it is discarded either way.
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		writePDNSError(w, http.StatusNotFound, "Not Found")
		return
	}
	rest := strings.SplitN(strings.Trim(parts[1], "/"), "/", 2)
	if len(rest) == 0 || rest[0] != "zones" {
		writePDNSError(w, http.StatusNotFound, "Not Found")
		return
	}

	if len(rest) == 1 {
		if r.Method != http.MethodGet {
			writePDNSError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		h.listZones(r.Context(), w)
		return
	}

	zoneID := rest[1]
	// A trailing "/notify" after the zone id is acme.sh dns_pdns's post-write
	// notify step. PowerDNS zone ids never contain "/", so this split is
	// unambiguous; any other trailing segment falls through to the existing
	// zone-id validation below (unchanged behavior).
	if id, action, found := strings.Cut(zoneID, "/"); found && action == "notify" {
		h.notifyZone(w, r, id)
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.getZone(r.Context(), w, zoneID)
	case http.MethodPatch:
		h.patchZone(r.Context(), w, r, zoneID)
	default:
		writePDNSError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// notifyZone serves PUT .../zones/{zone_id}/notify. PowerDNS uses it to tell
// slaves to refresh; domudns's cluster pushes changes itself, so this is a
// no-op that acme.sh dns_pdns requires to succeed after setting a record. The
// zone id is still validated so a malformed path fails like the other routes.
func (h *PDNSCompatHandler) notifyZone(w http.ResponseWriter, r *http.Request, zoneID string) {
	if r.Method != http.MethodPut {
		writePDNSError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if _, ok := validatePDNSZoneID(zoneID); !ok {
		writePDNSError(w, http.StatusUnprocessableEntity, "Invalid zone id")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// validatePDNSZoneID validates a {zone_id} path segment and returns the
// underlying domain name. PowerDNS zone IDs are the zone name plus a
// trailing dot; rejecting anything that doesn't pass dns.IsValidDomain also
// rejects path-traversal attempts ("..", "/", etc.) since those never form
// a valid domain label.
func validatePDNSZoneID(zoneID string) (string, bool) {
	domain := strings.ToLower(strings.TrimSuffix(zoneID, "."))
	if domain == "" || !dns.IsValidDomain(domain) {
		return "", false
	}
	return domain, true
}

// pdnsZoneSummary is one entry of GET .../zones.
type pdnsZoneSummary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

func (h *PDNSCompatHandler) listZones(ctx context.Context, w http.ResponseWriter) {
	zones, err := h.store.ListZones(ctx)
	if err != nil {
		writeInternalError(w, "DB_ERROR", err)
		return
	}
	result := make([]pdnsZoneSummary, 0, len(zones))
	for _, z := range zones {
		if z.View != "" {
			// PowerDNS compat only exposes the default (global) view; a
			// split-horizon zone has no single canonical answer.
			continue
		}
		fqdn := mdns.Fqdn(z.Domain)
		result = append(result, pdnsZoneSummary{ID: fqdn, Name: fqdn, Kind: "Native"})
	}
	writeJSON(w, http.StatusOK, result)
}

// pdnsRRSet is one RRset, used both in GET zone detail responses and (with
// ChangeType/Disabled set) in PATCH request bodies.
type pdnsRRSet struct {
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	TTL        int               `json:"ttl,omitempty"`
	ChangeType string            `json:"changetype,omitempty"`
	Records    []pdnsRecordEntry `json:"records"`
}

// pdnsRecordEntry is one record inside an rrset. Disabled is always
// serialized (no omitempty): dns-lexicon's PowerDNS provider — used by
// certbot-dns-powerdns and other ACME tooling — reads record["disabled"]
// unconditionally when it merges an existing rrset. Omitting the field for
// the common disabled=false case makes it raise KeyError: 'disabled'.
type pdnsRecordEntry struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type pdnsZoneDetail struct {
	ID     string      `json:"id"`
	Name   string      `json:"name"`
	Kind   string      `json:"kind"`
	Serial uint32      `json:"serial,omitempty"`
	RRSets []pdnsRRSet `json:"rrsets"`
}

func (h *PDNSCompatHandler) getZone(ctx context.Context, w http.ResponseWriter, zoneID string) {
	domain, ok := validatePDNSZoneID(zoneID)
	if !ok {
		writePDNSError(w, http.StatusUnprocessableEntity, "Invalid zone id")
		return
	}
	zone, err := h.store.GetZone(ctx, domain)
	if err != nil {
		if errors.Is(err, dns.ErrZoneNotFound) {
			writePDNSError(w, http.StatusNotFound, "Not Found")
			return
		}
		writeInternalError(w, "DB_ERROR", err)
		return
	}

	detail := pdnsZoneDetail{
		ID:     mdns.Fqdn(zone.Domain),
		Name:   mdns.Fqdn(zone.Domain),
		Kind:   "Native",
		RRSets: zoneToRRSets(zone),
	}
	if zone.SOA != nil {
		detail.Serial = zone.SOA.Serial
	}
	writeJSON(w, http.StatusOK, detail)
}

// rdataFromRR extracts the RDATA portion of rr's presentation-format text.
// mdns.RR.String() is "<name>\t<ttl>\t<class>\t<type>\t<rdata>" (see
// RR_Header.String() in miekg/dns) — the RDATA half already matches
// PowerDNS's "content" field format exactly (TXT/CAA quoting included),
// which is why this reuses the library's own stringer instead of a
// hand-rolled per-type formatter.
func rdataFromRR(rr mdns.RR) (string, bool) {
	parts := strings.SplitN(rr.String(), "\t", 5)
	if len(parts) != 5 {
		return "", false
	}
	return parts[4], true
}

// soaAsRecord packs zone.SOA into the dns.Record shape buildSOARR (in
// dnsserver/zones.go) expects, so SOA can be rendered through the same
// dnsserver.BuildRR path as every other record type below.
func soaAsRecord(soa *dns.SOA) dns.Record {
	return dns.Record{
		Name: "@",
		Type: dns.TypeSOA,
		Value: fmt.Sprintf("%s %s %d %d %d %d %d",
			soa.MName, soa.RName, soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minimum),
	}
}

// recordContent renders rec (already resolved to its zone) as an RRset
// name/content/ttl triple via dnsserver.BuildRR, or ok=false for record
// types BuildRR doesn't produce a wire RR for (FWD, ALIAS, and any
// unsupported/malformed record already on disk) — callers skip those
// rather than fail the whole response.
func recordContent(zone *dns.Zone, rec dns.Record) (fqdn, content string, ttl int, ok bool) {
	atApex := rec.Name == "@" || rec.Name == ""
	if atApex {
		fqdn = mdns.Fqdn(zone.Domain)
	} else {
		fqdn = mdns.Fqdn(rec.Name + "." + zone.Domain)
	}
	ttl = rec.TTL
	if ttl == 0 {
		ttl = zone.TTL
	}

	rr := dnsserver.BuildRR(dnsserver.RRBuildContext{
		Hdr:      mdns.RR_Header{Name: fqdn, Class: mdns.ClassINET, Ttl: uint32(ttl)},
		Rec:      rec,
		ZoneName: zone.Domain,
		AtApex:   atApex,
	})
	if rr == nil {
		return "", "", 0, false
	}
	content, ok = rdataFromRR(rr)
	return fqdn, content, ttl, ok
}

// zoneToRRSets groups zone's SOA and Records into PowerDNS rrsets, keyed by
// (name, type). Order follows first appearance so responses are
// deterministic. Records of a type this compat layer can't represent are
// silently skipped (see pdnsRepresentableTypes).
func zoneToRRSets(zone *dns.Zone) []pdnsRRSet {
	type key struct {
		name  string
		rtype string
	}
	grouped := make(map[key]*pdnsRRSet)
	var order []key

	add := func(fqdn string, rtype dns.RecordType, ttl int, content string) {
		k := key{fqdn, string(rtype)}
		rs, exists := grouped[k]
		if !exists {
			rs = &pdnsRRSet{Name: fqdn, Type: string(rtype), TTL: ttl}
			grouped[k] = rs
			order = append(order, k)
		}
		rs.Records = append(rs.Records, pdnsRecordEntry{Content: content})
	}

	if zone.SOA != nil {
		if fqdn, content, ttl, ok := recordContent(zone, soaAsRecord(zone.SOA)); ok {
			add(fqdn, dns.TypeSOA, ttl, content)
		}
	}
	for _, rec := range zone.Records {
		if !pdnsRepresentableTypes[rec.Type] {
			continue
		}
		if fqdn, content, ttl, ok := recordContent(zone, rec); ok {
			add(fqdn, rec.Type, ttl, content)
		}
	}

	result := make([]pdnsRRSet, 0, len(order))
	for _, k := range order {
		result = append(result, *grouped[k])
	}
	return result
}

// pdnsPatchRequest is the body of PATCH .../zones/{zone_id}.
type pdnsPatchRequest struct {
	RRSets []pdnsRRSet `json:"rrsets"`
}

// Per-request limits for PATCH .../zones/{zone_id}. The endpoint has no
// limit of its own otherwise — only the global 1 MB request body cap
// (middleware.go maxRequestBodyBytes) — so a single request could otherwise
// pack far more rrsets/records than the granular /api/records endpoint's
// natural one-request-per-record friction allows, bloating the zone file
// and slowing zone reloads/AXFR/cluster sync. Values are generous for the
// endpoint's actual use case (ACME DNS-01 TXT record churn, typically one
// record at a time) while still bounding worst case a couple orders of
// magnitude below maxAXFRRecords (zone_importer.go), which is a bulk
// full-zone-replace path with different tradeoffs.
const (
	// maxPDNSPatchRRSets caps the number of rrsets accepted per PATCH request.
	maxPDNSPatchRRSets = 100
	// maxPDNSPatchRecordsPerRRSet caps the number of records accepted per rrset.
	maxPDNSPatchRecordsPerRRSet = 100
)

// validatePDNSPatchLimits rejects oversized PATCH requests before any zone
// is loaded or mutated, so a request that exceeds the limit never touches
// the store (no partial writes, no lock taken).
func validatePDNSPatchLimits(req pdnsPatchRequest) error {
	if len(req.RRSets) > maxPDNSPatchRRSets {
		return fmt.Errorf("too many rrsets in request: %d (max %d)", len(req.RRSets), maxPDNSPatchRRSets)
	}
	for _, rrset := range req.RRSets {
		if len(rrset.Records) > maxPDNSPatchRecordsPerRRSet {
			return fmt.Errorf("too many records in rrset %q: %d (max %d)", rrset.Name, len(rrset.Records), maxPDNSPatchRecordsPerRRSet)
		}
	}
	return nil
}

// pdnsPatchError marks an error produced inside the UpdateZone mutate
// closure below as an unprocessable-request failure (422), as opposed to
// dns.ErrZoneNotFound (404, returned by UpdateZone without calling mutate)
// or any other error (500).
type pdnsPatchError struct{ err error }

func (e *pdnsPatchError) Error() string { return e.err.Error() }
func (e *pdnsPatchError) Unwrap() error { return e.err }

func (h *PDNSCompatHandler) patchZone(ctx context.Context, w http.ResponseWriter, r *http.Request, zoneID string) {
	domain, ok := validatePDNSZoneID(zoneID)
	if !ok {
		writePDNSError(w, http.StatusUnprocessableEntity, "Invalid zone id")
		return
	}

	var req pdnsPatchRequest
	if err := DecodeJSON(r, &req, 0); err != nil {
		writePDNSError(w, http.StatusUnprocessableEntity, "Invalid request body")
		return
	}
	if err := validatePDNSPatchLimits(req); err != nil {
		writePDNSError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	// UpdateZone holds a single write lock across load, RRset application,
	// and validation — see internal/store/interfaces.go
	// (ZoneWriter.UpdateZone) for why a separate GetZone+PutZone pair is not
	// used here.
	err := h.store.UpdateZone(ctx, domain, "", func(zone *dns.Zone) error {
		for _, rrset := range req.RRSets {
			if err := applyRRSetChange(zone, rrset); err != nil {
				return &pdnsPatchError{err}
			}
		}
		if zone.SOA == nil {
			return &pdnsPatchError{errors.New("operation would remove the zone's SOA record")}
		}
		if err := dns.ValidateZone(zone); err != nil {
			return &pdnsPatchError{err}
		}
		return nil
	})

	var patchErr *pdnsPatchError
	switch {
	case errors.As(err, &patchErr):
		writePDNSError(w, http.StatusUnprocessableEntity, patchErr.Error())
	case errors.Is(err, dns.ErrZoneNotFound):
		writePDNSError(w, http.StatusNotFound, "Not Found")
	case err != nil:
		writeInternalError(w, "DB_ERROR", err)
	default:
		w.WriteHeader(http.StatusNoContent)
		// The store now holds the new RRsets, but the master's DNS server
		// serves authoritative zones from an in-memory snapshot loaded at
		// startup. Reload it here (like RecordsHandler does) so ACME
		// DNS-01 TXT records are actually answered — otherwise only cluster
		// slaves see them and LE validation fails with NXDOMAIN.
		h.triggerZoneReload()
	}
}

// relativeRecordName converts an RRset's fully-qualified name into the
// domudns-internal relative name ("@" at apex, otherwise the label(s)
// before the zone suffix).
func relativeRecordName(rrsetName, zoneDomain string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(rrsetName, "."))
	zoneDomain = strings.ToLower(zoneDomain)
	if name == zoneDomain {
		return "@", nil
	}
	suffix := "." + zoneDomain
	if !strings.HasSuffix(name, suffix) {
		return "", fmt.Errorf("name %q is not part of zone %q", rrsetName, zoneDomain)
	}
	rel := strings.TrimSuffix(name, suffix)
	if rel == "" {
		return "", fmt.Errorf("invalid empty record name")
	}
	return rel, nil
}

// removeRecords deletes every record in zone matching (name, rtype).
func removeRecords(zone *dns.Zone, name string, rtype dns.RecordType) {
	kept := zone.Records[:0]
	for _, r := range zone.Records {
		if r.Name == name && r.Type == rtype {
			continue
		}
		kept = append(kept, r)
	}
	zone.Records = kept
}

// applyRRSetChange applies one PATCH rrset entry to zone in place.
func applyRRSetChange(zone *dns.Zone, rrset pdnsRRSet) error {
	rtype := dns.RecordType(strings.ToUpper(rrset.Type))
	relName, err := relativeRecordName(rrset.Name, zone.Domain)
	if err != nil {
		return err
	}
	if !pdnsRepresentableTypes[rtype] {
		return fmt.Errorf("unsupported record type: %s", rrset.Type)
	}

	switch strings.ToUpper(rrset.ChangeType) {
	case "DELETE":
		return applyRRSetDelete(zone, relName, rtype)
	case "REPLACE":
		return applyRRSetReplace(zone, rrset, relName, rtype)
	default:
		return fmt.Errorf("invalid changetype: %q (must be REPLACE or DELETE)", rrset.ChangeType)
	}
}

func applyRRSetDelete(zone *dns.Zone, relName string, rtype dns.RecordType) error {
	if rtype == dns.TypeSOA {
		return errors.New("cannot delete the zone's SOA rrset")
	}
	removeRecords(zone, relName, rtype)
	return nil
}

func applyRRSetReplace(zone *dns.Zone, rrset pdnsRRSet, relName string, rtype dns.RecordType) error {
	if rtype == dns.TypeSOA {
		return applySOAReplace(zone, rrset, relName)
	}

	removeRecords(zone, relName, rtype)
	ttl := rrset.TTL
	if ttl == 0 {
		ttl = zone.TTL
	}
	// PowerDNS/clients may request TTL < 300 (acme.sh's default PDNS_Ttl is 60);
	// domudns enforces a 300s floor, so clamp rather than reject.
	if ttl > 0 && ttl < dns.MinRecordTTL {
		ttl = dns.MinRecordTTL
	}
	for _, entry := range rrset.Records {
		if entry.Disabled {
			// domudns has no per-record disabled flag; the closest
			// equivalent is to not create the record at all.
			continue
		}
		rec, err := parseRRContent(rrset.Name, zone.Domain, rtype, entry.Content, ttl)
		if err != nil {
			return fmt.Errorf("rrset %s/%s: %w", rrset.Name, rrset.Type, err)
		}
		rec.Name = relName
		rec.ID = zone.NextRecordID()
		zone.Records = append(zone.Records, rec)
	}
	return nil
}

func applySOAReplace(zone *dns.Zone, rrset pdnsRRSet, relName string) error {
	if len(rrset.Records) == 0 {
		return errors.New("cannot delete the zone's SOA rrset")
	}
	if relName != "@" {
		return errors.New("SOA must be at the zone apex")
	}
	soa, err := parseSOAContent(rrset.Records[0].Content)
	if err != nil {
		return fmt.Errorf("invalid SOA content: %w", err)
	}
	zone.SOA = soa
	return nil
}

// parseRRContent parses a PowerDNS RRset "content" string for a
// representable, non-SOA type by round-tripping it through the miekg/dns
// zone-file parser (the inverse of recordContent/rdataFromRR above) and the
// existing rrToRecord conversion (zone_importer.go, already used for AXFR
// import) — reusing both instead of a second hand-rolled per-type parser.
func parseRRContent(rrsetName, zoneDomain string, rtype dns.RecordType, content string, ttl int) (dns.Record, error) {
	if ttl <= 0 {
		ttl = 3600
	}
	line := fmt.Sprintf("%s %d IN %s %s", mdns.Fqdn(rrsetName), ttl, string(rtype), content)
	rr, err := mdns.NewRR(line)
	if err != nil {
		return dns.Record{}, fmt.Errorf("invalid content: %w", err)
	}
	if rr == nil {
		return dns.Record{}, errors.New("empty content")
	}
	rec, ok := rrToRecord(rr, zoneDomain)
	if !ok {
		return dns.Record{}, fmt.Errorf("unsupported record type: %s", rtype)
	}
	rec.TTL = ttl
	return rec, nil
}

// parseSOAContent parses a PowerDNS SOA "content" string:
// "<mname> <rname> <serial> <refresh> <retry> <expire> <minimum>".
func parseSOAContent(content string) (*dns.SOA, error) {
	fields := strings.Fields(content)
	if len(fields) != 7 {
		return nil, errors.New(`SOA content must be "<mname> <rname> <serial> <refresh> <retry> <expire> <minimum>"`)
	}
	serial, err := strconv.ParseUint(fields[2], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid serial: %w", err)
	}
	refresh, err := strconv.Atoi(fields[3])
	if err != nil {
		return nil, fmt.Errorf("invalid refresh: %w", err)
	}
	retry, err := strconv.Atoi(fields[4])
	if err != nil {
		return nil, fmt.Errorf("invalid retry: %w", err)
	}
	expire, err := strconv.Atoi(fields[5])
	if err != nil {
		return nil, fmt.Errorf("invalid expire: %w", err)
	}
	minimum, err := strconv.Atoi(fields[6])
	if err != nil {
		return nil, fmt.Errorf("invalid minimum: %w", err)
	}
	return &dns.SOA{
		MName:   strings.TrimSuffix(fields[0], "."),
		RName:   strings.TrimSuffix(fields[1], "."),
		Serial:  uint32(serial),
		Refresh: refresh,
		Retry:   retry,
		Expire:  expire,
		Minimum: minimum,
	}, nil
}
