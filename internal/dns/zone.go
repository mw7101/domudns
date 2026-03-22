package dns

import (
	"errors"
	"time"
)

// ErrZoneNotFound is returned when a zone does not exist.
var ErrZoneNotFound = errors.New("zone not found")

// ErrRecordNotFound is returned when a record does not exist.
var ErrRecordNotFound = errors.New("record not found")

// Zone represents a DNS zone with its metadata and records.
type Zone struct {
	Domain      string   `json:"domain"`
	View        string   `json:"view,omitempty"` // Split-Horizon View-Name ("" = global sichtbar)
	TTL         int      `json:"ttl"`
	TTLOverride int      `json:"ttl_override,omitempty"` // 0 = no override; >0 = all response TTLs of this zone are normalized to this value
	Nameservers []string `json:"nameservers,omitempty"`
	Records     []Record `json:"records"`
	SOA         *SOA     `json:"soa,omitempty"`
}

// SOA holds the Start of Authority record fields.
type SOA struct {
	MName   string `json:"mname"`
	RName   string `json:"rname"`
	Serial  uint32 `json:"serial"`
	Refresh int    `json:"refresh"`
	Retry   int    `json:"retry"`
	Expire  int    `json:"expire"`
	Minimum int    `json:"minimum"`
}

// DefaultSOA returns a default SOA record for the zone domain.
// Used when creating zones via API; MName and RName are derived from the domain.
func DefaultSOA(domain string) *SOA {
	t := time.Now()
	serial := uint32(t.Year())*10000 + uint32(t.Month())*100 + uint32(t.Day())
	if serial < 20200101 {
		serial = 20200101
	}
	serial *= 100 // YYYYMMDDnn style
	return &SOA{
		MName:   "ns1." + domain,
		RName:   "hostmaster." + domain,
		Serial:  serial,
		Refresh: 3600,
		Retry:   1800,
		Expire:  604800,
		Minimum: 300,
	}
}

// EnsureSOA sets zone.SOA to DefaultSOA if nil.
func (z *Zone) EnsureSOA() {
	if z != nil && z.SOA == nil && z.Domain != "" {
		z.SOA = DefaultSOA(z.Domain)
	}
}

// IncrementSerial increments the SOA serial number using the YYYYMMDDnn convention:
// if the current serial is behind today's date prefix, it resets to today+01;
// otherwise it increments by one.
func (s *SOA) IncrementSerial() {
	t := time.Now()
	today := uint32(t.Year())*1000000 + uint32(t.Month())*10000 + uint32(t.Day())*100
	if s.Serial < today {
		s.Serial = today + 1
	} else {
		s.Serial++
	}
}

// RecordByID returns the record with the given ID, or nil if not found.
func (z *Zone) RecordByID(id int) *Record {
	for i := range z.Records {
		if z.Records[i].ID == id {
			return &z.Records[i]
		}
	}
	return nil
}

// NextRecordID returns the next available record ID.
func (z *Zone) NextRecordID() int {
	max := 0
	for _, r := range z.Records {
		if r.ID > max {
			max = r.ID
		}
	}
	return max + 1
}
