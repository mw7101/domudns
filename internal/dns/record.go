package dns

import (
	"encoding/json"
	"fmt"
)

// RecordType represents a DNS record type.
type RecordType string

const (
	TypeA     RecordType = "A"
	TypeAAAA  RecordType = "AAAA"
	TypeCNAME RecordType = "CNAME"
	TypeMX    RecordType = "MX"
	TypeTXT   RecordType = "TXT"
	TypeNS    RecordType = "NS"
	TypeSOA   RecordType = "SOA"
	TypeSRV   RecordType = "SRV"
	TypePTR   RecordType = "PTR"
	TypeCAA   RecordType = "CAA"
	TypeDNAME RecordType = "DNAME"
	TypeSPF   RecordType = "SPF"
	TypeURI   RecordType = "URI"
	TypeFWD   RecordType = "FWD"
	TypeALIAS RecordType = "ALIAS"
)

// Record represents a DNS record.
type Record struct {
	ID    int        `json:"id"`
	Name  string     `json:"name"` // "@" for apex, or subdomain label
	Type  RecordType `json:"type"`
	TTL   int        `json:"ttl"`
	Value string     `json:"value"`
	// MX: priority. SRV: priority. CAA: stored in Extra as "flags tag"
	Priority int `json:"priority,omitempty"`
	// SRV: weight and port
	Weight int `json:"weight,omitempty"`
	Port   int `json:"port,omitempty"`
	// CAA: tag (issue, issuewild, iodef). Flags in Priority (0-255)
	Tag string `json:"tag,omitempty"`
}

// UnmarshalJSON handles Record deserialization with backward compatibility.
func (r *Record) UnmarshalJSON(data []byte) error {
	type recordAlias Record
	aux := &struct {
		*recordAlias
	}{
		recordAlias: (*recordAlias)(r),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	return nil
}

// FQDN returns the fully qualified domain name for this record in the given zone.
func (r *Record) FQDN(zone string) string {
	if r.Name == "" || r.Name == "@" {
		return zone
	}
	return r.Name + "." + zone
}

// String returns a human-readable representation.
func (r *Record) String() string {
	return fmt.Sprintf("%s %s %s %d %s", r.Name, r.Type, r.FQDN("?"), r.TTL, r.Value)
}
