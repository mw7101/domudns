package dhcp

import (
	"context"
	"fmt"
)

// LeaseParser reads DHCP leases from a source.
type LeaseParser interface {
	// Parse reads all active leases from the configured source.
	Parse(ctx context.Context) ([]Lease, error)
}

// NewParser creates a parser for the specified source.
// source: "dnsmasq", "dhcpd", "fritzbox"
func NewParser(source, sourcePath, fritzboxURL, fritzboxUser, fritzboxPassword string) (LeaseParser, error) {
	switch source {
	case "dnsmasq":
		if sourcePath == "" {
			return nil, fmt.Errorf("dhcp: source_path ist Pflicht fuer dnsmasq")
		}
		return &DnsmasqParser{Path: sourcePath}, nil
	case "dhcpd":
		if sourcePath == "" {
			return nil, fmt.Errorf("dhcp: source_path ist Pflicht fuer dhcpd")
		}
		return &DhcpdParser{Path: sourcePath}, nil
	case "fritzbox":
		if fritzboxURL == "" {
			return nil, fmt.Errorf("dhcp: fritzbox_url ist Pflicht fuer fritzbox")
		}
		return &FritzBoxParser{
			URL:      fritzboxURL,
			User:     fritzboxUser,
			Password: fritzboxPassword,
		}, nil
	default:
		return nil, fmt.Errorf("dhcp: unbekannte Quelle %q (erlaubt: dnsmasq, dhcpd, fritzbox)", source)
	}
}
