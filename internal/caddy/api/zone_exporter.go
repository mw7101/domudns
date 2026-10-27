package api

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/mw7101/domudns/internal/dns"
	mdns "github.com/miekg/dns"
)

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
