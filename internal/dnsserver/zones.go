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
// When cnameTarget != "", the answer already carries the CNAME RR(s) of a chain whose
// canonical name is not in the queried zone, and pipeline_cname.go continues the lookup.
type zoneResponse struct {
	msg         *mdns.Msg
	aliasTarget string // "" = no ALIAS; non-empty = target FQDN to resolve
	cnameTarget string // "" = chain answered in-zone; else canonical name to resolve elsewhere
}

// matchedZoneRecords groups the records matchZoneRecords found for a query:
// those to answer with directly, CNAME candidates for chasing, and ALIAS
// candidates for transparent resolution.
type matchedZoneRecords struct {
	matched []dns.Record
	cname   []dns.Record // CNAME records at this node (for CNAME chasing)
	alias   []dns.Record // ALIAS records for transparent resolution

	// nameExists reports whether subdomain has any record in the zone at
	// all (exact name match, or covered by a single-label "*" wildcard per
	// RFC 1034 §4.3.3), independent of qtype. GenerateResponse uses it for
	// NXDOMAIN-vs-NOERROR classification instead of re-walking zone.Records
	// a second time.
	nameExists bool
}

// matchZoneRecords finds the records in zone that answer a query for
// subdomain/qtype.
// RFC 1034 §4.3.3: wildcard "*" is a fallback — exact records at the
// queried name take precedence. Exact and wildcard candidates are collected
// separately and wildcards are only promoted when no exact name match exists.
func (z *ZoneManager) matchZoneRecords(zone *dns.Zone, subdomain string, qtype uint16) matchedZoneRecords {
	var matchedRecords []dns.Record
	var cnameRecords []dns.Record
	var aliasRecords []dns.Record

	// wildcardCandidates accumulates records whose name is "*" that may match
	// a single-label subdomain. They are used only when hasExactName is false.
	var wildcardCandidates []dns.Record
	var wildcardCNAME []dns.Record
	var wildcardALIAS []dns.Record
	hasExactName := false    // true when any record in the zone has Name == subdomain
	hasWildcardName := false // true when a "*" record covers subdomain (single-label), regardless of its type

	for _, rec := range zone.Records {
		// Normalize record name
		recName := rec.Name
		if recName == "@" || recName == "" {
			recName = "@"
		}

		// Detect whether the zone contains any record with the exact subdomain name.
		// This drives the wildcard-vs-exact precedence decision below.
		if subdomain != "@" && recName == subdomain {
			hasExactName = true
		}
		if subdomain != "@" && recName == "*" && !strings.Contains(subdomain, ".") {
			hasWildcardName = true
		}

		// Match subdomain — exact first; wildcards are collected separately.
		if subdomain == "@" && recName != "@" {
			continue
		}
		if subdomain != "@" {
			if recName == subdomain {
				// Exact match — fall through to record-type filtering below.
			} else if recName == "*" && !strings.Contains(subdomain, ".") {
				// RFC 1034 §4.3.3: wildcard candidate for single-label subdomains.
				// Buffer separately; only use if no exact name match exists.
				if rec.Type == dns.TypeCNAME {
					wildcardCNAME = append(wildcardCNAME, rec)
				} else if rec.Type == dns.TypeALIAS {
					wildcardALIAS = append(wildcardALIAS, rec)
				} else if qtype == mdns.TypeANY || string(rec.Type) == mdns.TypeToString[qtype] {
					wildcardCandidates = append(wildcardCandidates, rec)
				}
				continue
			} else {
				continue
			}
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

	// Promote wildcard candidates only when the zone has no exact record for the
	// queried subdomain (RFC 1034 §4.3.3 precedence rule).
	if subdomain != "@" && !hasExactName {
		matchedRecords = append(matchedRecords, wildcardCandidates...)
		cnameRecords = append(cnameRecords, wildcardCNAME...)
		if qtype == mdns.TypeCNAME || qtype == mdns.TypeANY {
			matchedRecords = append(matchedRecords, wildcardCNAME...)
		}
		aliasRecords = append(aliasRecords, wildcardALIAS...)
	}

	return matchedZoneRecords{
		matched:    matchedRecords,
		cname:      cnameRecords,
		alias:      aliasRecords,
		nameExists: hasExactName || hasWildcardName,
	}
}

// maxCNAMEChainDepth bounds CNAME chain following (in-zone and across zones) so
// that misconfigured zones (e.g. a → b → a) cannot loop forever.
const maxCNAMEChainDepth = 8

// appendCNAMEChainAnswer implements RFC 1034 §4.3.2: when no records of the
// requested type exist but a CNAME does, it appends the CNAME RRs and follows
// each chain inside this zone (step 3a of the RFC: repeat the lookup with the
// canonical name as the new QNAME) until records of qtype are found.
//
// It returns the canonical name at which the in-zone part of the chain ended
// without an answer ("" = every chain was answered inside this zone) so the
// caller can continue outside the zone: pipeline_cname.go resolves that name in
// the other local zones and, for A/AAAA, via the upstream forwarder. Without
// that second step a CNAME pointing into another local zone would leave stub
// resolvers that do not follow CNAMEs (musl, glibc getaddrinfo) with no address.
func (z *ZoneManager) appendCNAMEChainAnswer(resp *mdns.Msg, zone *dns.Zone, cnameRecords []dns.Record, subdomain string, qtype uint16) string {
	// seen carries every name already followed, seeded with the queried name, so
	// a loop (a → b → a) neither repeats RRs nor runs to the depth limit.
	seen := map[string]bool{z.zoneFQDN(zone, subdomain): true}

	unresolved := ""
	for _, rec := range cnameRecords {
		rr := z.recordToRR(zone, rec, subdomain)
		if rr == nil {
			continue
		}
		resp.Answer = append(resp.Answer, rr)

		if target, ok := z.appendInZoneCNAMEChain(resp, zone, rec.Value, qtype, seen); !ok && unresolved == "" {
			unresolved = target
		}
	}
	return unresolved
}

// appendInZoneCNAMEChain follows the chain starting at target (a record value,
// which may well point outside zone) and appends every intermediate CNAME RR
// plus the records answering qtype to resp.Answer. ok=false reports that the
// chain left the zone (or revisited a name); the returned name is then the
// canonical name the caller has to resolve elsewhere (or has to treat as a
// loop). seen is shared across all CNAME records of one query and is updated.
func (z *ZoneManager) appendInZoneCNAMEChain(resp *mdns.Msg, zone *dns.Zone, target string, qtype uint16, seen map[string]bool) (string, bool) {
	zoneDomain := z.normalizedDomain(zone)
	current := strings.ToLower(strings.TrimSuffix(mdns.Fqdn(target), "."))

	for depth := 0; depth < maxCNAMEChainDepth; depth++ {
		// A name already followed means the chain loops: stop appending, the
		// caller reports it and the client gets the CNAME chain without
		// duplicates (RFC 1035 §3.6.2).
		if seen[current] {
			return current, false
		}
		seen[current] = true

		// A target outside the zone — and the apex, where RFC 1035 forbids a
		// CNAME — ends the in-zone part of the chain.
		if current == zoneDomain || !strings.HasSuffix(current, "."+zoneDomain) {
			return current, false
		}

		sub := strings.TrimSuffix(current, "."+zoneDomain)
		m := z.matchZoneRecords(zone, sub, qtype)

		if len(m.matched) > 0 {
			for _, rec := range m.matched {
				if rr := z.recordToRR(zone, rec, sub); rr != nil {
					resp.Answer = append(resp.Answer, rr)
				}
			}
			return "", true
		}
		// A name that exists but has no CNAME (and no record of qtype) ends the
		// chain: there is nothing left to return for this query type. The same
		// holds for a name whose zone holds only an ALIAS — pipeline_cname.go
		// synthesizes that one.
		if len(m.cname) == 0 {
			return current, false
		}
		for _, rec := range m.cname {
			if rr := z.recordToRR(zone, rec, sub); rr != nil {
				resp.Answer = append(resp.Answer, rr)
			}
		}
		current = strings.ToLower(strings.TrimSuffix(mdns.Fqdn(m.cname[0].Value), "."))
	}
	return current, false
}

// zoneFQDN returns the normalized FQDN of subdomain inside zone ("@" = apex).
func (z *ZoneManager) zoneFQDN(zone *dns.Zone, subdomain string) string {
	if subdomain == "@" {
		return z.normalizedDomain(zone)
	}
	return strings.ToLower(subdomain + "." + z.normalizedDomain(zone))
}

// normalizedDomain returns zone.Domain lowercased and without the trailing dot.
func (z *ZoneManager) normalizedDomain(zone *dns.Zone) string {
	return strings.ToLower(strings.TrimSuffix(zone.Domain, "."))
}

// hasAnswerOfType reports whether rrs already contains a record answering qtype.
// Used to decide whether an out-of-zone CNAME target still has to be resolved.
func hasAnswerOfType(rrs []mdns.RR, qtype uint16) bool {
	for _, rr := range rrs {
		if rr.Header().Rrtype == qtype {
			return true
		}
	}
	return false
}

// GenerateResponse generates a DNS response for an authoritative zone.
func (z *ZoneManager) GenerateResponse(req *mdns.Msg, zone *dns.Zone, subdomain string) zoneResponse {
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true

	q := req.Question[0]
	qtype := q.Qtype

	m := z.matchZoneRecords(zone, subdomain, qtype)

	unresolvedCNAME := ""
	if len(m.matched) == 0 && len(m.cname) > 0 && qtype != mdns.TypeCNAME && qtype != mdns.TypeANY {
		unresolvedCNAME = z.appendCNAMEChainAnswer(resp, zone, m.cname, subdomain, qtype)
	} else {
		// Add matched records to answer
		for _, rec := range m.matched {
			rr := z.recordToRR(zone, rec, subdomain)
			if rr != nil {
				resp.Answer = append(resp.Answer, rr)
			}
		}
	}

	// R2/R4: trigger ALIAS resolution when A or AAAA is queried,
	// no direct A/AAAA records exist, but ALIAS records do.
	if len(resp.Answer) == 0 && len(m.alias) > 0 &&
		(qtype == mdns.TypeA || qtype == mdns.TypeAAAA) {
		return zoneResponse{
			msg:         resp, // NOERROR shell, Authoritative=true, empty Answer
			aliasTarget: m.alias[0].Value,
		}
	}

	// If no records found but zone exists, set NOERROR (empty answer)
	// If subdomain doesn't exist in zone, set NXDOMAIN
	if len(resp.Answer) == 0 && !m.nameExists && subdomain != "@" {
		resp.Rcode = mdns.RcodeNameError // NXDOMAIN
	}

	zr := zoneResponse{msg: resp}
	// RFC 1034 §4.3.2: a CNAME chain whose canonical name is not in this zone is
	// incomplete for stub resolvers that do not follow CNAMEs themselves (musl,
	// glibc getaddrinfo). The answer already carries the CNAME RR(s); the pipeline
	// (pipeline_cname.go) continues the lookup in the other local zones and, for
	// A/AAAA, upstream.
	if unresolvedCNAME != "" && !hasAnswerOfType(resp.Answer, qtype) {
		zr.cnameTarget = unresolvedCNAME
	}
	return zr
}

// RRBuildContext carries everything a record-type RR builder needs to turn
// a dns.Record into a miekg/dns RR: a header with Name/Class/Ttl already
// resolved by the caller (each builder fills in Rrtype itself, since that's
// the one header field that varies per record type), the record, and — for
// the one builder that needs it (CNAME, for the RFC 1035 zone-apex check) —
// the zone name (for the warning log) and whether Rec sits at the zone apex.
//
// This struct and BuildRR are shared by live DNS serving (recordToRR below)
// and zone-file export (zone_exporter.go's exportRecordToRR) so a fix to one
// record type's conversion always reaches both callers. FQDN/TTL resolution
// differs between the two callers (e.g. TTLOverride only applies to live
// serving) and stays in each caller — only the actual dns.Record → mdns.RR
// construction, keyed by type, is shared here.
type RRBuildContext struct {
	Hdr      mdns.RR_Header
	Rec      dns.Record
	ZoneName string // zone.Domain; used only by buildCNAMERR's warning log
	AtApex   bool   // true when Rec's resolved name is the zone apex ("@")
}

// rrBuilders holds one RR-construction function per record type, keyed by
// Record.Type. BuildRR dispatches here; each builder does exactly one
// type's mdns.RR construction.
var rrBuilders = map[dns.RecordType]func(RRBuildContext) mdns.RR{
	dns.TypeA:     buildARR,
	dns.TypeAAAA:  buildAAAARR,
	dns.TypeCNAME: buildCNAMERR,
	dns.TypeMX:    buildMXRR,
	dns.TypeTXT:   buildTXTRR,
	dns.TypeNS:    buildNSRR,
	dns.TypeSRV:   buildSRVRR,
	dns.TypeCAA:   buildCAARR,
	dns.TypePTR:   buildPTRRR,
	dns.TypeSOA:   buildSOARR,
	dns.TypeDNAME: buildDNAMERR,
	dns.TypeFWD:   func(RRBuildContext) mdns.RR { return nil }, // FWD does not produce a DNS RR
	dns.TypeALIAS: func(RRBuildContext) mdns.RR { return nil }, // ALIAS is resolved transparently in pipeline_alias.go
}

// BuildRR converts ctx.Rec into a miekg/dns RR by dispatching to the
// type-specific builder in rrBuilders. Returns nil for unsupported record
// types (and for the few builders that reject the record, e.g. CNAME at
// zone apex).
func BuildRR(ctx RRBuildContext) mdns.RR {
	build, ok := rrBuilders[ctx.Rec.Type]
	if !ok {
		return nil // unsupported record type
	}
	return build(ctx)
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

	return BuildRR(RRBuildContext{
		Hdr:      mdns.RR_Header{Name: fqdn, Class: mdns.ClassINET, Ttl: ttl},
		Rec:      rec,
		ZoneName: zone.Domain,
		AtApex:   subdomain == "@",
	})
}

func buildARR(c RRBuildContext) mdns.RR {
	ip := net.ParseIP(c.Rec.Value)
	if ip == nil || ip.To4() == nil {
		return nil
	}
	c.Hdr.Rrtype = mdns.TypeA
	return &mdns.A{Hdr: c.Hdr, A: ip.To4()}
}

func buildAAAARR(c RRBuildContext) mdns.RR {
	ip := net.ParseIP(c.Rec.Value)
	if ip == nil || ip.To16() == nil {
		return nil
	}
	c.Hdr.Rrtype = mdns.TypeAAAA
	return &mdns.AAAA{Hdr: c.Hdr, AAAA: ip.To16()}
}

func buildCNAMERR(c RRBuildContext) mdns.RR {
	// RFC 1035: CNAME is not allowed at zone apex
	if c.AtApex {
		log.Warn().
			Str("zone", c.ZoneName).
			Msg("CNAME at zone apex is not allowed (RFC 1035), ignoring record")
		return nil
	}
	c.Hdr.Rrtype = mdns.TypeCNAME
	return &mdns.CNAME{Hdr: c.Hdr, Target: mdns.Fqdn(c.Rec.Value)}
}

func buildMXRR(c RRBuildContext) mdns.RR {
	c.Hdr.Rrtype = mdns.TypeMX
	return &mdns.MX{Hdr: c.Hdr, Preference: uint16(c.Rec.Priority), Mx: mdns.Fqdn(c.Rec.Value)}
}

func buildTXTRR(c RRBuildContext) mdns.RR {
	c.Hdr.Rrtype = mdns.TypeTXT
	return &mdns.TXT{Hdr: c.Hdr, Txt: []string{c.Rec.Value}}
}

func buildNSRR(c RRBuildContext) mdns.RR {
	c.Hdr.Rrtype = mdns.TypeNS
	return &mdns.NS{Hdr: c.Hdr, Ns: mdns.Fqdn(c.Rec.Value)}
}

func buildSRVRR(c RRBuildContext) mdns.RR {
	c.Hdr.Rrtype = mdns.TypeSRV
	return &mdns.SRV{
		Hdr:      c.Hdr,
		Priority: uint16(c.Rec.Priority),
		Weight:   uint16(c.Rec.Weight),
		Port:     uint16(c.Rec.Port),
		Target:   mdns.Fqdn(c.Rec.Value),
	}
}

func buildCAARR(c RRBuildContext) mdns.RR {
	// CAA: flags (Priority), tag, value. ValidateRecord() enforces 0-255 on
	// write, but defend against corrupted on-disk records too: check the
	// range before truncating to uint8, not after.
	flags := c.Rec.Priority
	if flags < 0 || flags > 255 {
		flags = 0
	}
	c.Hdr.Rrtype = mdns.TypeCAA
	return &mdns.CAA{Hdr: c.Hdr, Flag: uint8(flags), Tag: c.Rec.Tag, Value: c.Rec.Value}
}

func buildPTRRR(c RRBuildContext) mdns.RR {
	c.Hdr.Rrtype = mdns.TypePTR
	return &mdns.PTR{Hdr: c.Hdr, Ptr: mdns.Fqdn(c.Rec.Value)}
}

func buildDNAMERR(c RRBuildContext) mdns.RR {
	c.Hdr.Rrtype = mdns.TypeDNAME
	return &mdns.DNAME{Hdr: c.Hdr, Target: mdns.Fqdn(c.Rec.Value)}
}

// buildSOARR parses the SOA value (format: "mname rname serial refresh retry expire minimum").
func buildSOARR(c RRBuildContext) mdns.RR {
	parts := strings.Fields(c.Rec.Value)
	if len(parts) < 7 {
		return nil
	}
	serial, _ := strconv.ParseUint(parts[2], 10, 32)
	refresh, _ := strconv.ParseUint(parts[3], 10, 32)
	retry, _ := strconv.ParseUint(parts[4], 10, 32)
	expire, _ := strconv.ParseUint(parts[5], 10, 32)
	minttl, _ := strconv.ParseUint(parts[6], 10, 32)

	c.Hdr.Rrtype = mdns.TypeSOA
	return &mdns.SOA{
		Hdr:     c.Hdr,
		Ns:      mdns.Fqdn(parts[0]),
		Mbox:    mdns.Fqdn(parts[1]),
		Serial:  uint32(serial),
		Refresh: uint32(refresh),
		Retry:   uint32(retry),
		Expire:  uint32(expire),
		Minttl:  uint32(minttl),
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
