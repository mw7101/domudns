package dnsserver

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/mw7101/domudns/internal/dns"
	mdns "github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// ZoneManager manages authoritative zones in-memory.
// Supports default zones (for all clients) and view-specific zones
// (only for clients assigned to a specific split-horizon view).
type ZoneManager struct {
	// zones contains default zones (View = "") — domain → zone (normalized, no trailing dot)
	zones map[string]*dns.Zone
	// viewZones contains view-specific zones — domain → viewName → zone
	viewZones map[string]map[string]*dns.Zone
	mu        sync.RWMutex
}

// NewZoneManager creates a new zone manager.
func NewZoneManager() *ZoneManager {
	return &ZoneManager{
		zones:     make(map[string]*dns.Zone),
		viewZones: make(map[string]map[string]*dns.Zone),
	}
}

// Load loads authoritative zones from the store.
// Records are already included in the zone objects returned by ListZones
// (filestore loads records directly from JSON files).
func (z *ZoneManager) Load(ctx context.Context, store ZoneProvider) error {
	zones, err := store.ListZones(ctx)
	if err != nil {
		return err
	}

	// Update in-memory zones
	z.mu.Lock()
	defer z.mu.Unlock()

	z.zones = make(map[string]*dns.Zone, len(zones))
	z.viewZones = make(map[string]map[string]*dns.Zone)

	for _, zone := range zones {
		normalized := strings.ToLower(strings.TrimSuffix(zone.Domain, "."))
		if zone.View != "" {
			// View-specific zone
			if z.viewZones[normalized] == nil {
				z.viewZones[normalized] = make(map[string]*dns.Zone)
			}
			z.viewZones[normalized][zone.View] = zone
		} else {
			// Default zone (visible to all)
			z.zones[normalized] = zone
		}
	}

	viewCount := 0
	for _, views := range z.viewZones {
		viewCount += len(views)
	}
	log.Info().
		Int("zones", len(z.zones)).
		Int("view_zones", viewCount).
		Msg("authoritative zones loaded")
	return nil
}

// FindZone finds the zone responsible for a query name.
// clientView specifies the view name of the requesting client ("" = no view).
// Lookup order: view zone (if clientView != "") → default zone → nil.
// Returns the zone and the subdomain label (e.g., "www" for www.example.com in example.com zone).
func (z *ZoneManager) FindZone(clientView, qname string) (*dns.Zone, string) {
	z.mu.RLock()
	defer z.mu.RUnlock()

	normalized := strings.ToLower(strings.TrimSuffix(qname, "."))

	// Try exact match first (apex)
	if zone := z.findByName(clientView, normalized); zone != nil {
		return zone, "@"
	}

	// Try parent zones (e.g., "www.example.com" -> check "example.com")
	parts := strings.Split(normalized, ".")
	for i := 1; i < len(parts); i++ {
		zoneDomain := strings.Join(parts[i:], ".")
		if zone := z.findByName(clientView, zoneDomain); zone != nil {
			subdomain := strings.Join(parts[:i], ".")
			return zone, subdomain
		}
	}

	return nil, ""
}

// findByName looks up a zone first in viewZones (if clientView != ""), then in zones.
// Must be called under RLock.
func (z *ZoneManager) findByName(clientView, normalizedDomain string) *dns.Zone {
	if clientView != "" {
		if views, ok := z.viewZones[normalizedDomain]; ok {
			if zone, ok := views[clientView]; ok {
				return zone
			}
		}
	}
	if zone, ok := z.zones[normalizedDomain]; ok {
		return zone
	}
	return nil
}

// zoneResponse carries the result of GenerateResponse.
// When aliasTarget != "", msg is a NOERROR shell (Authoritative=true, empty Answer)
// and pipeline_alias.go is responsible for populating the answer and writing the response.
type zoneResponse struct {
	msg         *mdns.Msg
	aliasTarget string // "" = no ALIAS; non-empty = target FQDN to resolve
}

// GenerateResponse generates a DNS response for an authoritative zone.
func (z *ZoneManager) GenerateResponse(req *mdns.Msg, zone *dns.Zone, subdomain string) zoneResponse {
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true

	q := req.Question[0]
	qtype := q.Qtype

	// Find matching records
	var matchedRecords []dns.Record
	var cnameRecords []dns.Record  // CNAME records at this node (for CNAME chasing)
	var aliasRecords []dns.Record  // ALIAS records for transparent resolution
	for _, rec := range zone.Records {
		// Normalize record name
		recName := rec.Name
		if recName == "@" || recName == "" {
			recName = "@"
		}

		// Match subdomain
		if subdomain == "@" && recName != "@" {
			continue
		}
		if subdomain != "@" && recName != subdomain {
			continue
		}

		// Collect CNAME records separately for RFC 1034 §4.3.2 CNAME chasing.
		// CNAME at zone apex (@) is forbidden (RFC 1035) and handled in recordToRR.
		if rec.Type == dns.TypeCNAME && subdomain != "@" {
			cnameRecords = append(cnameRecords, rec)
			// Only include in matchedRecords when CNAME or ANY is explicitly queried.
			if qtype == mdns.TypeCNAME || qtype == mdns.TypeANY {
				matchedRecords = append(matchedRecords, rec)
			}
			continue
		}

		// ALIAS records are collected separately for transparent resolution.
		if rec.Type == dns.TypeALIAS {
			aliasRecords = append(aliasRecords, rec)
			// Count ALIAS as "name exists" to suppress NXDOMAIN for non-A/AAAA queries (R3).
			continue
		}

		// Match record type (or ANY)
		if qtype != mdns.TypeANY && string(rec.Type) != mdns.TypeToString[qtype] {
			continue
		}

		matchedRecords = append(matchedRecords, rec)
	}

	// RFC 1034 §4.3.2: if no records of the requested type exist but a CNAME does,
	// return the CNAME and follow the chain within this zone.
	if len(matchedRecords) == 0 && len(cnameRecords) > 0 && qtype != mdns.TypeCNAME && qtype != mdns.TypeANY {
		for _, rec := range cnameRecords {
			rr := z.recordToRR(zone, rec, subdomain)
			if rr == nil {
				continue
			}
			resp.Answer = append(resp.Answer, rr)

			// Try to resolve the CNAME target within this zone.
			target := strings.ToLower(strings.TrimSuffix(mdns.Fqdn(rec.Value), "."))
			zoneDomain := strings.ToLower(strings.TrimSuffix(zone.Domain, "."))
			if strings.HasSuffix(target, "."+zoneDomain) {
				targetSub := strings.TrimSuffix(target, "."+zoneDomain)
				for _, rec2 := range zone.Records {
					recName2 := rec2.Name
					if recName2 == "@" || recName2 == "" {
						recName2 = "@"
					}
					if recName2 != targetSub {
						continue
					}
					if string(rec2.Type) != mdns.TypeToString[qtype] {
						continue
					}
					rr2 := z.recordToRR(zone, rec2, targetSub)
					if rr2 != nil {
						resp.Answer = append(resp.Answer, rr2)
					}
				}
			}
		}
	} else {
		// Add matched records to answer
		for _, rec := range matchedRecords {
			rr := z.recordToRR(zone, rec, subdomain)
			if rr != nil {
				resp.Answer = append(resp.Answer, rr)
			}
		}
	}

	// R2/R4: trigger ALIAS resolution when A or AAAA is queried,
	// no direct A/AAAA records exist, but ALIAS records do.
	if len(resp.Answer) == 0 && len(aliasRecords) > 0 &&
		(qtype == mdns.TypeA || qtype == mdns.TypeAAAA) {
		return zoneResponse{
			msg:         resp, // NOERROR shell, Authoritative=true, empty Answer
			aliasTarget: aliasRecords[0].Value,
		}
	}

	// If no records found but zone exists, set NOERROR (empty answer)
	// If subdomain doesn't exist in zone, set NXDOMAIN
	if len(resp.Answer) == 0 {
		hasSubdomain := false
		for _, rec := range zone.Records {
			recName := rec.Name
			if recName == "@" || recName == "" {
				recName = "@"
			}
			if recName == subdomain {
				hasSubdomain = true
				break
			}
		}
		if !hasSubdomain && subdomain != "@" {
			resp.Rcode = mdns.RcodeNameError // NXDOMAIN
		}
	}

	return zoneResponse{msg: resp}
}

// recordToRR converts a dns.Record to a miekg/dns RR.
// If zone.TTLOverride > 0, TTL of all records (except SOA) is normalized to this value.
func (z *ZoneManager) recordToRR(zone *dns.Zone, rec dns.Record, subdomain string) mdns.RR {
	// Build FQDN
	var fqdn string
	if subdomain == "@" {
		fqdn = mdns.Fqdn(zone.Domain)
	} else {
		fqdn = mdns.Fqdn(subdomain + "." + zone.Domain)
	}

	ttl := uint32(rec.TTL)
	if ttl == 0 {
		ttl = 3600
	}
	// TTL override per zone: overrides record TTL for all types except SOA
	// (SOA TTL has semantic meaning for zone transfers and negative caching)
	if zone.TTLOverride > 0 && rec.Type != dns.TypeSOA {
		ttl = uint32(zone.TTLOverride)
	}

	switch rec.Type {
	case dns.TypeA:
		ip := net.ParseIP(rec.Value)
		if ip == nil || ip.To4() == nil {
			return nil
		}
		return &mdns.A{
			Hdr: mdns.RR_Header{
				Name:   fqdn,
				Rrtype: mdns.TypeA,
				Class:  mdns.ClassINET,
				Ttl:    ttl,
			},
			A: ip.To4(),
		}

	case dns.TypeAAAA:
		ip := net.ParseIP(rec.Value)
		if ip == nil || ip.To16() == nil {
			return nil
		}
		return &mdns.AAAA{
			Hdr: mdns.RR_Header{
				Name:   fqdn,
				Rrtype: mdns.TypeAAAA,
				Class:  mdns.ClassINET,
				Ttl:    ttl,
			},
			AAAA: ip.To16(),
		}

	case dns.TypeCNAME:
		// RFC 1035: CNAME is not allowed at zone apex
		if subdomain == "@" {
			log.Warn().
				Str("zone", zone.Domain).
				Msg("CNAME at zone apex is not allowed (RFC 1035), ignoring record")
			return nil
		}
		return &mdns.CNAME{
			Hdr: mdns.RR_Header{
				Name:   fqdn,
				Rrtype: mdns.TypeCNAME,
				Class:  mdns.ClassINET,
				Ttl:    ttl,
			},
			Target: mdns.Fqdn(rec.Value),
		}

	case dns.TypeMX:
		return &mdns.MX{
			Hdr: mdns.RR_Header{
				Name:   fqdn,
				Rrtype: mdns.TypeMX,
				Class:  mdns.ClassINET,
				Ttl:    ttl,
			},
			Preference: uint16(rec.Priority),
			Mx:         mdns.Fqdn(rec.Value),
		}

	case dns.TypeTXT:
		return &mdns.TXT{
			Hdr: mdns.RR_Header{
				Name:   fqdn,
				Rrtype: mdns.TypeTXT,
				Class:  mdns.ClassINET,
				Ttl:    ttl,
			},
			Txt: []string{rec.Value},
		}

	case dns.TypeNS:
		return &mdns.NS{
			Hdr: mdns.RR_Header{
				Name:   fqdn,
				Rrtype: mdns.TypeNS,
				Class:  mdns.ClassINET,
				Ttl:    ttl,
			},
			Ns: mdns.Fqdn(rec.Value),
		}

	case dns.TypeSRV:
		return &mdns.SRV{
			Hdr: mdns.RR_Header{
				Name:   fqdn,
				Rrtype: mdns.TypeSRV,
				Class:  mdns.ClassINET,
				Ttl:    ttl,
			},
			Priority: uint16(rec.Priority),
			Weight:   uint16(rec.Weight),
			Port:     uint16(rec.Port),
			Target:   mdns.Fqdn(rec.Value),
		}

	case dns.TypeCAA:
		// CAA: flags (Priority), tag, value
		flags := uint8(rec.Priority)
		if flags > 255 {
			flags = 0
		}
		return &mdns.CAA{
			Hdr: mdns.RR_Header{
				Name:   fqdn,
				Rrtype: mdns.TypeCAA,
				Class:  mdns.ClassINET,
				Ttl:    ttl,
			},
			Flag:  flags,
			Tag:   rec.Tag,
			Value: rec.Value,
		}

	case dns.TypePTR:
		return &mdns.PTR{
			Hdr: mdns.RR_Header{
				Name:   fqdn,
				Rrtype: mdns.TypePTR,
				Class:  mdns.ClassINET,
				Ttl:    ttl,
			},
			Ptr: mdns.Fqdn(rec.Value),
		}

	case dns.TypeSOA:
		// Parse SOA value (format: "mname rname serial refresh retry expire minimum")
		parts := strings.Fields(rec.Value)
		if len(parts) < 7 {
			return nil
		}
		serial, _ := strconv.ParseUint(parts[2], 10, 32)
		refresh, _ := strconv.ParseUint(parts[3], 10, 32)
		retry, _ := strconv.ParseUint(parts[4], 10, 32)
		expire, _ := strconv.ParseUint(parts[5], 10, 32)
		minttl, _ := strconv.ParseUint(parts[6], 10, 32)

		return &mdns.SOA{
			Hdr: mdns.RR_Header{
				Name:   fqdn,
				Rrtype: mdns.TypeSOA,
				Class:  mdns.ClassINET,
				Ttl:    ttl,
			},
			Ns:      mdns.Fqdn(parts[0]),
			Mbox:    mdns.Fqdn(parts[1]),
			Serial:  uint32(serial),
			Refresh: uint32(refresh),
			Retry:   uint32(retry),
			Expire:  uint32(expire),
			Minttl:  uint32(minttl),
		}

	case dns.TypeFWD:
		return nil // FWD does not produce a DNS RR
	case dns.TypeALIAS:
		return nil // ALIAS is resolved transparently in pipeline_alias.go
	default:
		// Unsupported record type
		return nil
	}
}

// Stats returns current zone statistics.
func (z *ZoneManager) Stats() (defaultZones, viewZones int) {
	z.mu.RLock()
	defer z.mu.RUnlock()
	defaultZones = len(z.zones)
	for _, views := range z.viewZones {
		viewZones += len(views)
	}
	return
}

// FindFWDServers returns the FWD servers defined at zone apex (@), or nil if none exist.
func (z *ZoneManager) FindFWDServers(zone *dns.Zone) []string {
	for _, rec := range zone.Records {
		if rec.Type == dns.TypeFWD && (rec.Name == "@" || rec.Name == "") {
			var servers []string
			for _, s := range strings.Split(rec.Value, ",") {
				s = strings.TrimSpace(s)
				if s == "" {
					continue
				}
				if _, _, err := net.SplitHostPort(s); err != nil {
					s = s + ":53"
				}
				servers = append(servers, s)
			}
			return servers
		}
	}
	return nil
}
