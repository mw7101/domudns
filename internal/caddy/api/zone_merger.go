package api

import "github.com/mw7101/domudns/internal/dns"

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
