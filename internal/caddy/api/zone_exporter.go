package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/mw7101/domudns/internal/dns"
	"github.com/mw7101/domudns/internal/dnsserver"
	mdns "github.com/miekg/dns"
)

// handleExportZone exports a zone as an RFC 1035 zone file.
// GET /api/zones/{domain}/export?view=
func (h *ImportExportHandler) handleExportZone(w http.ResponseWriter, r *http.Request) {
	domain, view, ok := parseZoneExportPath(w, r)
	if !ok {
		return
	}

	zone, ok := h.loadExportZone(r.Context(), w, domain, view)
	if !ok {
		return
	}
	zone.EnsureSOA()

	filename := domain + ".zone"
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, buildZoneFile(zone))
}

// parseZoneExportPath extracts and validates domain/view from
// GET /api/zones/{domain}/export?view=. Writes the error response itself
// on failure.
func parseZoneExportPath(w http.ResponseWriter, r *http.Request) (domain, view string, ok bool) {
	path := strings.TrimPrefix(r.URL.Path, "/api/zones/")
	domain = strings.TrimSuffix(path, "/export")
	if domain == "" || !dns.IsValidDomain(domain) {
		writeError(w, http.StatusBadRequest, "INVALID_ZONE", "Invalid domain name")
		return "", "", false
	}
	view = r.URL.Query().Get("view")
	if view != "" && !isValidViewName(view) {
		writeError(w, http.StatusBadRequest, "INVALID_VIEW", "Invalid view name (only [a-z0-9_-] allowed)")
		return "", "", false
	}
	return domain, view, true
}

// loadExportZone loads the zone to export, writing the error response
// itself on failure.
func (h *ImportExportHandler) loadExportZone(ctx context.Context, w http.ResponseWriter, domain, view string) (*dns.Zone, bool) {
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
			return nil, false
		}
		writeInternalError(w, "DB_ERROR", err)
		return nil, false
	}
	return zone, true
}

// buildZoneFile renders zone as an RFC 1035 zone file: $ORIGIN/$TTL header,
// the SOA record, then every other record via exportRecordToRR.
func buildZoneFile(zone *dns.Zone) string {
	var sb strings.Builder
	sb.WriteString("$ORIGIN " + mdns.Fqdn(zone.Domain) + "\n")
	fmt.Fprintf(&sb, "$TTL %d\n", zone.TTL)

	if zone.SOA != nil {
		fmt.Fprintf(&sb, "%s %d IN SOA %s %s %d %d %d %d %d\n",
			mdns.Fqdn(zone.Domain),
			zone.TTL,
			mdns.Fqdn(zone.SOA.MName),
			mdns.Fqdn(zone.SOA.RName),
			zone.SOA.Serial,
			zone.SOA.Refresh,
			zone.SOA.Retry,
			zone.SOA.Expire,
			zone.SOA.Minimum)
	}

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
	return sb.String()
}

// exportRecordToRR converts an internal dns.Record to a miekg/dns RR for
// zone file export, via the same dnsserver.BuildRR dispatch table used for
// live DNS answers (dnsserver/zones.go) — see RRBuildContext's doc comment
// for why the two callers share the per-type construction but not the
// surrounding FQDN/TTL resolution.
func exportRecordToRR(zone *dns.Zone, rec dns.Record) mdns.RR {
	atApex := rec.Name == "@" || rec.Name == ""
	var fqdn string
	if atApex {
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

	return dnsserver.BuildRR(dnsserver.RRBuildContext{
		Hdr:      mdns.RR_Header{Name: fqdn, Class: mdns.ClassINET, Ttl: ttl},
		Rec:      rec,
		ZoneName: zone.Domain,
		AtApex:   atApex,
	})
}
