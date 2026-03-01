package dnsserver

import (
	"testing"
)

func TestConditionalForwarder_Match(t *testing.T) {
	rules := []ConditionalForwardRule{
		{Domain: "fritz.box", Servers: []string{"192.168.178.1:53"}},
		{Domain: "corp.internal", Servers: []string{"10.0.0.1:53", "10.0.0.2:53"}},
		{Domain: "sub.corp.internal", Servers: []string{"10.1.0.1:53"}},
	}
	cf := NewConditionalForwarder(rules)

	tests := []struct {
		name     string
		qname    string
		wantNil  bool
		wantSrv0 string
	}{
		{"exact match", "fritz.box.", false, "192.168.178.1:53"},
		{"subdomain match", "mydevice.fritz.box.", false, "192.168.178.1:53"},
		{"deep subdomain", "a.b.fritz.box.", false, "192.168.178.1:53"},
		{"no match", "google.com.", true, ""},
		{"corp exact", "corp.internal.", false, "10.0.0.1:53"},
		{"corp subdomain", "host.corp.internal.", false, "10.0.0.1:53"},
		{"longest match wins", "host.sub.corp.internal.", false, "10.1.0.1:53"},
		{"case insensitive", "FRITZ.BOX.", false, "192.168.178.1:53"},
		{"no trailing dot", "fritz.box", false, "192.168.178.1:53"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cf.Match(tt.qname)
			if tt.wantNil {
				if got != nil {
					t.Errorf("Match(%q) = %v, want nil", tt.qname, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("Match(%q) = nil, want %q", tt.qname, tt.wantSrv0)
			}
			if got[0] != tt.wantSrv0 {
				t.Errorf("Match(%q)[0] = %q, want %q", tt.qname, got[0], tt.wantSrv0)
			}
		})
	}
}

func TestConditionalForwarder_UpdateRules(t *testing.T) {
	cf := NewConditionalForwarder([]ConditionalForwardRule{
		{Domain: "fritz.box", Servers: []string{"192.168.178.1"}},
	})

	if cf.Match("fritz.box.") == nil {
		t.Fatal("expected match before update")
	}

	cf.UpdateRules([]ConditionalForwardRule{
		{Domain: "example.com", Servers: []string{"1.2.3.4"}},
	})

	if cf.Match("fritz.box.") != nil {
		t.Error("expected no match for fritz.box after update")
	}
	if cf.Match("example.com.") == nil {
		t.Error("expected match for example.com after update")
	}
}

func TestConditionalForwarder_PortNormalization(t *testing.T) {
	cf := NewConditionalForwarder([]ConditionalForwardRule{
		{Domain: "fritz.box", Servers: []string{"192.168.178.1"}}, // kein Port
	})
	servers := cf.Match("fritz.box.")
	if servers == nil {
		t.Fatal("expected match")
	}
	if servers[0] != "192.168.178.1:53" {
		t.Errorf("expected port :53 appended, got %q", servers[0])
	}
}

func TestConditionalForwarder_EmptyRules(t *testing.T) {
	cf := NewConditionalForwarder(nil)
	if cf.Match("anything.example.com.") != nil {
		t.Error("expected nil for empty rules")
	}
}
