package dhcp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ─── dnsmasq Parser Tests ────────────────────────────────────────────────────

func TestDnsmasqParser_Parse(t *testing.T) {
	now := time.Now()
	future := now.Add(1 * time.Hour).Unix()
	past := now.Add(-1 * time.Hour).Unix()

	content := ""
	// Aktiver Lease
	content += fmt.Sprintf("%d aa:bb:cc:dd:ee:01 192.168.1.10 laptop 01:aa:bb:cc:dd:ee:01\n", future)
	// Abgelaufener Lease
	content += fmt.Sprintf("%d aa:bb:cc:dd:ee:02 192.168.1.11 old-pc *\n", past)
	// Statischer Lease (timestamp 0 = nie ablaufend)
	content += "0 aa:bb:cc:dd:ee:03 192.168.1.12 server-01\n"
	// Lease ohne Hostname (* = kein Name)
	content += fmt.Sprintf("%d aa:bb:cc:dd:ee:04 192.168.1.13 * 01:aa:bb:cc:dd:ee:04\n", future)
	// Empty line and comment
	content += "\n# Kommentar\n"

	dir := t.TempDir()
	path := filepath.Join(dir, "dnsmasq.leases")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	parser := &DnsmasqParser{Path: path}
	leases, err := parser.Parse(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(leases) != 2 {
		t.Fatalf("erwartet 2 Leases, bekommen %d", len(leases))
	}

	// Erster Lease: laptop (aktiv)
	if leases[0].Hostname != "laptop" || leases[0].IP != "192.168.1.10" {
		t.Errorf("Lease 0: erwartet laptop/192.168.1.10, bekommen %s/%s", leases[0].Hostname, leases[0].IP)
	}

	// Zweiter Lease: server-01 (statisch)
	if leases[1].Hostname != "server-01" || leases[1].IP != "192.168.1.12" {
		t.Errorf("Lease 1: erwartet server-01/192.168.1.12, bekommen %s/%s", leases[1].Hostname, leases[1].IP)
	}
}

func TestDnsmasqParser_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsmasq.leases")
	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	parser := &DnsmasqParser{Path: path}
	leases, err := parser.Parse(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 0 {
		t.Fatalf("erwartet 0 Leases, bekommen %d", len(leases))
	}
}

func TestDnsmasqParser_FileNotFound(t *testing.T) {
	parser := &DnsmasqParser{Path: "/tmp/nonexistent-dhcp-leases-file"}
	_, err := parser.Parse(context.Background())
	if err == nil {
		t.Fatal("erwartet Fehler bei nicht existierender Datei")
	}
}

// ─── dhcpd Parser Tests ─────────────────────────────────────────────────────

func TestDhcpdParser_Parse(t *testing.T) {
	content := `# dhcpd.leases
lease 192.168.1.10 {
  starts 4 2030/01/01 10:00:00;
  ends 4 2030/01/01 18:00:00;
  hardware ethernet aa:bb:cc:dd:ee:01;
  client-hostname "Laptop";
}

lease 192.168.1.11 {
  starts 4 2020/01/01 10:00:00;
  ends 4 2020/01/01 18:00:00;
  hardware ethernet aa:bb:cc:dd:ee:02;
  client-hostname "expired-pc";
}

lease 192.168.1.12 {
  starts 4 2030/01/01 10:00:00;
  ends never;
  hardware ethernet aa:bb:cc:dd:ee:03;
  client-hostname "server";
}
`

	dir := t.TempDir()
	path := filepath.Join(dir, "dhcpd.leases")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	parser := &DhcpdParser{Path: path}
	leases, err := parser.Parse(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// laptop (Zukunfts-Datum) + server (never) = 2
	// expired-pc has ends in the past = skipped
	if len(leases) != 2 {
		t.Fatalf("erwartet 2 Leases, bekommen %d: %+v", len(leases), leases)
	}

	found := map[string]bool{}
	for _, l := range leases {
		found[l.Hostname] = true
	}
	if !found["Laptop"] {
		t.Error("Laptop nicht gefunden")
	}
	if !found["server"] {
		t.Error("server nicht gefunden")
	}
}

func TestDhcpdParser_Duplicates(t *testing.T) {
	// Gleiche IP, neuerer Lease soll gewinnen
	content := `
lease 192.168.1.10 {
  starts 4 2030/01/01 08:00:00;
  ends 4 2030/01/01 16:00:00;
  hardware ethernet aa:bb:cc:dd:ee:01;
  client-hostname "old-name";
}

lease 192.168.1.10 {
  starts 4 2030/01/01 12:00:00;
  ends 4 2030/01/01 20:00:00;
  hardware ethernet aa:bb:cc:dd:ee:01;
  client-hostname "new-name";
}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "dhcpd.leases")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	parser := &DhcpdParser{Path: path}
	leases, err := parser.Parse(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(leases) != 1 {
		t.Fatalf("erwartet 1 Lease (dedupliziert), bekommen %d", len(leases))
	}
	if leases[0].Hostname != "new-name" {
		t.Errorf("erwartet new-name (neuerer Lease), bekommen %s", leases[0].Hostname)
	}
}

// ─── sanitizeHostname Tests ─────────────────────────────────────────────────

func TestSanitizeHostname(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"einfach", "laptop", "laptop"},
		{"Grossbuchstaben", "MyLaptop", "mylaptop"},
		{"Sonderzeichen", "my_laptop!", "my-laptop"},
		{"Stern", "*", ""},
		{"leer", "", ""},
		{"Domain-Suffix", "pc.home.lan", "pc"},
		{"Bindestriche am Rand", "-test-", "test"},
		{"Leerzeichen", "my laptop", "my-laptop"},
		{"Umlaute", "büro-pc", "b-ro-pc"},
		{"lang", string(make([]byte, 100)), ""},
	}

	// Langen Test-Hostnamen vorbereiten
	longName := make([]byte, 100)
	for i := range longName {
		longName[i] = 'a'
	}
	tests[len(tests)-1].in = string(longName)
	tests[len(tests)-1].want = string(longName[:63])

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeHostname(tt.in)
			if got != tt.want {
				t.Errorf("sanitizeHostname(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
