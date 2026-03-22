package dns

import (
	"testing"
	"time"
)

func TestValidateRecord(t *testing.T) {
	tests := []struct {
		name    string
		record  Record
		zone    string
		wantErr bool
	}{
		{
			name:    "valid A record",
			record:  Record{Name: "@", Type: TypeA, TTL: 3600, Value: "192.168.1.1"},
			zone:    "example.com",
			wantErr: false,
		},
		{
			name:    "invalid A record",
			record:  Record{Name: "@", Type: TypeA, TTL: 3600, Value: "invalid"},
			zone:    "example.com",
			wantErr: true,
		},
		{
			name:    "valid AAAA record",
			record:  Record{Name: "www", Type: TypeAAAA, TTL: 3600, Value: "::1"},
			zone:    "example.com",
			wantErr: false,
		},
		{
			name:    "invalid AAAA with IPv4",
			record:  Record{Name: "www", Type: TypeAAAA, TTL: 3600, Value: "192.168.1.1"},
			zone:    "example.com",
			wantErr: true,
		},
		{
			name:    "CNAME at apex not allowed",
			record:  Record{Name: "@", Type: TypeCNAME, TTL: 3600, Value: "other.example.com"},
			zone:    "example.com",
			wantErr: true,
		},
		{
			name:    "valid CNAME",
			record:  Record{Name: "www", Type: TypeCNAME, TTL: 3600, Value: "example.com"},
			zone:    "example.com",
			wantErr: false,
		},
		{
			name:    "valid MX record",
			record:  Record{Name: "@", Type: TypeMX, TTL: 3600, Value: "mail.example.com", Priority: 10},
			zone:    "example.com",
			wantErr: false,
		},
		{
			name:    "invalid MX priority",
			record:  Record{Name: "@", Type: TypeMX, TTL: 3600, Value: "mail.example.com", Priority: 70000},
			zone:    "example.com",
			wantErr: true,
		},
		{
			name:    "valid TXT record",
			record:  Record{Name: "@", Type: TypeTXT, TTL: 3600, Value: "v=spf1 include:_spf.example.com"},
			zone:    "example.com",
			wantErr: false,
		},
		{
			name:    "TXT too long",
			record:  Record{Name: "@", Type: TypeTXT, TTL: 3600, Value: string(make([]byte, 256))},
			zone:    "example.com",
			wantErr: true,
		},
		{
			name:    "empty name",
			record:  Record{Name: "", Type: TypeA, TTL: 3600, Value: "192.168.1.1"},
			zone:    "example.com",
			wantErr: true,
		},
		{
			name:    "valid name - underscore allowed (e.g. DHCP hostname esp_cc8108)",
			record:  Record{Name: "invalid_name", Type: TypeA, TTL: 3600, Value: "192.168.1.1"},
			zone:    "example.com",
			wantErr: false,
		},
		{
			name:    "valid name - DHCP-style hostname with underscore",
			record:  Record{Name: "esp_cc8108", Type: TypeA, TTL: 3600, Value: "192.168.1.50"},
			zone:    "example.com",
			wantErr: false,
		},
		{
			name:    "valid name - ACME challenge label",
			record:  Record{Name: "_acme-challenge", Type: TypeTXT, TTL: 300, Value: "sometoken"},
			zone:    "example.com",
			wantErr: false,
		},
		{
			name:    "valid name - DMARC label",
			record:  Record{Name: "_dmarc", Type: TypeTXT, TTL: 3600, Value: "v=DMARC1; p=none"},
			zone:    "example.com",
			wantErr: false,
		},
		{
			name:    "invalid name - dot",
			record:  Record{Name: "sub.domain", Type: TypeA, TTL: 3600, Value: "192.168.1.1"},
			zone:    "example.com",
			wantErr: true,
		},
		{
			name:    "invalid name - too long",
			record:  Record{Name: string(make([]byte, 64)), Type: TypeA, TTL: 3600, Value: "192.168.1.1"},
			zone:    "example.com",
			wantErr: true,
		},
		// PTR records
		{
			name:    "valid PTR record in in-addr.arpa zone",
			record:  Record{Name: "1", Type: TypePTR, TTL: 3600, Value: "router.int.example.com"},
			zone:    "100.168.192.in-addr.arpa",
			wantErr: false,
		},
		{
			name:    "valid PTR record - DHCP hostname with underscore",
			record:  Record{Name: "79", Type: TypePTR, TTL: 3600, Value: "ESP_CC8108.int.example.com"},
			zone:    "100.168.192.in-addr.arpa",
			wantErr: false,
		},
		{
			name:    "valid PTR at apex",
			record:  Record{Name: "@", Type: TypePTR, TTL: 3600, Value: "host.example.com"},
			zone:    "100.168.192.in-addr.arpa",
			wantErr: false,
		},
		{
			name:    "PTR value is IP address (Fehler: muss Hostname sein)",
			record:  Record{Name: "1", Type: TypePTR, TTL: 3600, Value: "192.168.100.1"},
			zone:    "100.168.192.in-addr.arpa",
			wantErr: true,
		},
		{
			name:    "PTR name not a number in in-addr.arpa zone",
			record:  Record{Name: "host", Type: TypePTR, TTL: 3600, Value: "router.example.com"},
			zone:    "100.168.192.in-addr.arpa",
			wantErr: true,
		},
		{
			name:    "PTR name > 255 in in-addr.arpa zone",
			record:  Record{Name: "256", Type: TypePTR, TTL: 3600, Value: "router.example.com"},
			zone:    "100.168.192.in-addr.arpa",
			wantErr: true,
		},
		{
			name:    "valid PTR record in ip6.arpa zone",
			record:  Record{Name: "a", Type: TypePTR, TTL: 3600, Value: "host.example.com"},
			zone:    "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
			wantErr: false,
		},
		{
			name:    "PTR name invalid hex in ip6.arpa zone",
			record:  Record{Name: "g", Type: TypePTR, TTL: 3600, Value: "host.example.com"},
			zone:    "0.0.0.0.ip6.arpa",
			wantErr: true,
		},
		{
			name:    "PTR invalid target FQDN",
			record:  Record{Name: "1", Type: TypePTR, TTL: 3600, Value: ""},
			zone:    "100.168.192.in-addr.arpa",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRecord(tt.record, tt.zone)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRecord() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsValidDNSLabel(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"@", true},
		{"www", true},
		{"mail", true},
		{"a", true},
		{"-x", false},
		{"x-", false},
		{"a.b", false},
		{"", false},
		{"valid-label", true},
		{"x", true},
		{string(make([]byte, 64)), false},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := IsValidDNSLabel(tt.s); got != tt.want {
				t.Errorf("IsValidDNSLabel(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestValidateZone(t *testing.T) {
	tests := []struct {
		name    string
		zone    *Zone
		wantErr bool
	}{
		{
			name:    "valid zone",
			zone:    &Zone{Domain: "example.com", TTL: 3600, Records: []Record{}},
			wantErr: false,
		},
		{
			name:    "nil zone",
			zone:    nil,
			wantErr: true,
		},
		{
			name:    "empty domain",
			zone:    &Zone{Domain: "", TTL: 3600},
			wantErr: true,
		},
		{
			name: "zone with invalid record",
			zone: &Zone{
				Domain: "example.com",
				TTL:    3600,
				Records: []Record{
					{Name: "@", Type: TypeA, TTL: 3600, Value: "invalid"},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateZone(tt.zone)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateZone() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSOA_IncrementSerial(t *testing.T) {
	t.Run("serial behind today is reset to today+1", func(t *testing.T) {
		soa := &SOA{Serial: 2020010100}
		soa.IncrementSerial()
		today := time.Now()
		todayPrefix := uint32(today.Year())*1000000 + uint32(today.Month())*10000 + uint32(today.Day())*100
		if soa.Serial != todayPrefix+1 {
			t.Errorf("want %d, got %d", todayPrefix+1, soa.Serial)
		}
	})

	t.Run("serial at today is incremented by one", func(t *testing.T) {
		today := time.Now()
		todayPrefix := uint32(today.Year())*1000000 + uint32(today.Month())*10000 + uint32(today.Day())*100
		soa := &SOA{Serial: todayPrefix + 5}
		soa.IncrementSerial()
		if soa.Serial != todayPrefix+6 {
			t.Errorf("want %d, got %d", todayPrefix+6, soa.Serial)
		}
	})

	t.Run("serial ahead of today is incremented by one", func(t *testing.T) {
		soa := &SOA{Serial: 4000010100}
		before := soa.Serial
		soa.IncrementSerial()
		if soa.Serial != before+1 {
			t.Errorf("want %d, got %d", before+1, soa.Serial)
		}
	})
}
