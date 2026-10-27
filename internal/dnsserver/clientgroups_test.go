package dnsserver

import (
	"net"
	"testing"

	"github.com/mw7101/domudns/internal/dns"
)

func TestClientGroupResolverNoGroups(t *testing.T) {
	r := NewClientGroupResolver()
	ip := net.ParseIP("192.168.1.1")
	cats := r.GetCategories(ip)
	if len(cats) != len(dns.DefaultCategories()) {
		t.Errorf("no groups → expected DefaultCategories, got %v", cats)
	}
}

func TestClientGroupResolverFirstMatch(t *testing.T) {
	r := NewClientGroupResolver()
	groups := []*dns.ClientGroup{
		{Name: "kinder", CIDRs: []string{"192.168.2.0/24"}, Categories: []string{"ads", "adult"}},
		{Name: "iot", CIDRs: []string{"192.168.10.0/24"}, Categories: []string{"malware"}},
	}
	if err := r.Update(groups); err != nil {
		t.Fatalf("Update: %v", err)
	}

	ip2 := net.ParseIP("192.168.2.50")
	cats := r.GetCategories(ip2)
	if len(cats) != 2 || cats[0] != "ads" {
		t.Errorf("expected [ads adult], got %v", cats)
	}

	ip10 := net.ParseIP("192.168.10.1")
	cats10 := r.GetCategories(ip10)
	if len(cats10) != 1 || cats10[0] != "malware" {
		t.Errorf("expected [malware], got %v", cats10)
	}

	ipNone := net.ParseIP("10.0.0.1")
	catsNone := r.GetCategories(ipNone)
	if len(catsNone) != len(dns.DefaultCategories()) {
		t.Errorf("no match → expected DefaultCategories, got %v", catsNone)
	}
}

func TestClientGroupResolverInvalidCIDR(t *testing.T) {
	r := NewClientGroupResolver()
	groups := []*dns.ClientGroup{
		{Name: "bad", CIDRs: []string{"not-a-cidr"}, Categories: []string{"ads"}},
	}
	if err := r.Update(groups); err == nil {
		t.Error("expected error for invalid CIDR, got nil")
	}
}

func TestClientGroupResolverCategoriesMutationSafe(t *testing.T) {
	r := NewClientGroupResolver()
	groups := []*dns.ClientGroup{
		{Name: "test", CIDRs: []string{"10.0.0.0/8"}, Categories: []string{"ads"}},
	}
	if err := r.Update(groups); err != nil {
		t.Fatalf("Update: %v", err)
	}

	ip := net.ParseIP("10.1.2.3")
	cats := r.GetCategories(ip)

	// Mutate the returned slice — should not affect next call
	if len(cats) > 0 {
		cats[0] = "mutated"
	}

	cats2 := r.GetCategories(ip)
	if len(cats2) == 0 || cats2[0] != "ads" {
		t.Errorf("mutation of returned slice affected resolver: got %v", cats2)
	}
}

func TestClientGroupResolverEmptyGroupsReturnsDefault(t *testing.T) {
	r := NewClientGroupResolver()
	if err := r.Update([]*dns.ClientGroup{}); err != nil {
		t.Fatalf("Update empty: %v", err)
	}
	ip := net.ParseIP("1.2.3.4")
	cats := r.GetCategories(ip)
	if len(cats) != len(dns.DefaultCategories()) {
		t.Errorf("empty groups → expected DefaultCategories, got %v", cats)
	}
}
