package dnsserver

import (
	"net"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		private bool
	}{
		// RFC1918
		{"RFC1918 Klasse A", "10.0.0.1", true},
		{"RFC1918 Klasse A Grenze", "10.255.255.255", true},
		{"RFC1918 Klasse B", "172.16.0.1", true},
		{"RFC1918 Klasse B Mitte", "172.31.255.255", true},
		{"RFC1918 Klasse B vor Range", "172.15.255.255", false},
		{"RFC1918 Klasse B nach Range", "172.32.0.0", false},
		{"RFC1918 Klasse C", "192.168.0.1", true},
		{"RFC1918 Klasse C Ende", "192.168.255.255", true},
		// Loopback
		{"IPv4 Loopback", "127.0.0.1", true},
		{"IPv4 Loopback Ende", "127.255.255.255", true},
		// Link-Local
		{"IPv4 Link-Local", "169.254.1.1", true},
		// Carrier-Grade NAT
		{"Carrier-Grade NAT", "100.64.0.1", true},
		// Public IPs
		{"Google DNS", "8.8.8.8", false},
		{"Cloudflare DNS", "1.1.1.1", false},
		{"Öffentliche IP", "203.0.113.1", false},
		// IPv6
		{"IPv6 Loopback", "::1", true},
		{"IPv6 ULA fc", "fc00::1", true},
		{"IPv6 ULA fd", "fd00::1", true},
		{"IPv6 Link-Local", "fe80::1", true},
		{"IPv6 öffentlich", "2606:4700:4700::1111", false},
		// Edge cases
		{"nil", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ip net.IP
			if tt.ip != "" {
				ip = net.ParseIP(tt.ip)
			}
			got := isPrivateIP(ip)
			if got != tt.private {
				t.Errorf("isPrivateIP(%q) = %v, wollte %v", tt.ip, got, tt.private)
			}
		})
	}
}

func TestRebindingProtector_IsRebindingAttack(t *testing.T) {
	// Hilfsfunktion: DNS-Antwort mit A-Record erstellen
	makeAResp := func(domain, ip string) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(&dns.Msg{})
		m.Rcode = dns.RcodeSuccess
		m.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   domain,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP(ip),
			},
		}
		return m
	}

	makeAAAAResp := func(domain, ip string) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(&dns.Msg{})
		m.Rcode = dns.RcodeSuccess
		m.Answer = []dns.RR{
			&dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   domain,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				AAAA: net.ParseIP(ip),
			},
		}
		return m
	}

	makeNXResp := func() *dns.Msg {
		m := new(dns.Msg)
		m.Rcode = dns.RcodeNameError
		return m
	}

	tests := []struct {
		name      string
		enabled   bool
		whitelist []string
		qname     string
		resp      *dns.Msg
		wantBlock bool
	}{
		{
			name:      "deaktiviert, private IP → kein Block",
			enabled:   false,
			qname:     "evil.com.",
			resp:      makeAResp("evil.com.", "192.168.1.1"),
			wantBlock: false,
		},
		{
			name:      "aktiviert, öffentliche IP → kein Block",
			enabled:   true,
			qname:     "google.com.",
			resp:      makeAResp("google.com.", "8.8.8.8"),
			wantBlock: false,
		},
		{
			name:      "aktiviert, private IPv4 → Block",
			enabled:   true,
			qname:     "evil.com.",
			resp:      makeAResp("evil.com.", "192.168.1.1"),
			wantBlock: true,
		},
		{
			name:      "aktiviert, 10.x.x.x → Block",
			enabled:   true,
			qname:     "evil.com.",
			resp:      makeAResp("evil.com.", "10.0.0.1"),
			wantBlock: true,
		},
		{
			name:      "aktiviert, Loopback → Block",
			enabled:   true,
			qname:     "evil.com.",
			resp:      makeAResp("evil.com.", "127.0.0.1"),
			wantBlock: true,
		},
		{
			name:      "aktiviert, IPv6 Loopback → Block",
			enabled:   true,
			qname:     "evil.com.",
			resp:      makeAAAAResp("evil.com.", "::1"),
			wantBlock: true,
		},
		{
			name:      "aktiviert, IPv6 ULA → Block",
			enabled:   true,
			qname:     "evil.com.",
			resp:      makeAAAAResp("evil.com.", "fd00::1"),
			wantBlock: true,
		},
		{
			name:      "aktiviert, NXDOMAIN-Antwort → kein Block",
			enabled:   true,
			qname:     "evil.com.",
			resp:      makeNXResp(),
			wantBlock: false,
		},
		{
			name:      "aktiviert, nil-Antwort → kein Block (kein Panic)",
			enabled:   true,
			qname:     "evil.com.",
			resp:      nil,
			wantBlock: false,
		},
		{
			name:    "aktiviert, leere Antwort → kein Block",
			enabled: true,
			qname:   "evil.com.",
			resp: func() *dns.Msg {
				m := new(dns.Msg)
				m.Rcode = dns.RcodeSuccess
				return m
			}(),
			wantBlock: false,
		},
		{
			name:      "aktiviert, Whitelist exakter Match → kein Block",
			enabled:   true,
			whitelist: []string{"fritz.box"},
			qname:     "fritz.box.",
			resp:      makeAResp("fritz.box.", "192.168.178.1"),
			wantBlock: false,
		},
		{
			name:      "aktiviert, Whitelist Subdomain → kein Block",
			enabled:   true,
			whitelist: []string{"fritz.box"},
			qname:     "mydevice.fritz.box.",
			resp:      makeAResp("mydevice.fritz.box.", "192.168.178.42"),
			wantBlock: false,
		},
		{
			name:      "aktiviert, Whitelist kein Match → Block",
			enabled:   true,
			whitelist: []string{"fritz.box"},
			qname:     "evil.com.",
			resp:      makeAResp("evil.com.", "192.168.1.1"),
			wantBlock: true,
		},
		{
			name:      "aktiviert, Whitelist case-insensitive → kein Block",
			enabled:   true,
			whitelist: []string{"Fritz.Box"},
			qname:     "MyDevice.fritz.box.",
			resp:      makeAResp("mydevice.fritz.box.", "192.168.178.42"),
			wantBlock: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rp := NewRebindingProtector(tt.enabled, tt.whitelist)
			got := rp.IsRebindingAttack(tt.qname, tt.resp)
			if got != tt.wantBlock {
				t.Errorf("IsRebindingAttack() = %v, wollte %v", got, tt.wantBlock)
			}
		})
	}
}

func TestRebindingProtector_Update_LiveReload(t *testing.T) {
	rp := NewRebindingProtector(false, nil)

	resp := &dns.Msg{
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Rrtype: dns.TypeA, Class: dns.ClassINET},
				A:   net.ParseIP("192.168.1.1"),
			},
		},
	}
	resp.Rcode = dns.RcodeSuccess

	// Vor Update: deaktiviert → kein Block
	if rp.IsRebindingAttack("evil.com.", resp) {
		t.Error("sollte vor Update nicht blockieren")
	}

	// Live-Update: aktivieren
	rp.Update(true, nil)
	if !rp.IsRebindingAttack("evil.com.", resp) {
		t.Error("sollte nach Update blockieren")
	}

	// Erneut deaktivieren
	rp.Update(false, nil)
	if rp.IsRebindingAttack("evil.com.", resp) {
		t.Error("sollte nach Deaktivierung nicht mehr blockieren")
	}
}

func TestRebindingProtector_ConcurrentUpdate(t *testing.T) {
	rp := NewRebindingProtector(true, nil)

	resp := &dns.Msg{
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Rrtype: dns.TypeA, Class: dns.ClassINET},
				A:   net.ParseIP("192.168.1.1"),
			},
		},
	}
	resp.Rcode = dns.RcodeSuccess

	var wg sync.WaitGroup

	// 100 Goroutinen lesen gleichzeitig
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = rp.IsRebindingAttack("evil.com.", resp)
		}()
	}

	// 10 Goroutinen schreiben gleichzeitig
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(enabled bool) {
			defer wg.Done()
			rp.Update(enabled, []string{"fritz.box"})
		}(i%2 == 0)
	}

	wg.Wait()
	// Kein Panic, kein Race → Test bestanden (mit go test -race prüfen)
}
