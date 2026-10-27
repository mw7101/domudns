package filestore_test

import (
	"context"
	"testing"

	"github.com/mw7101/domudns/internal/dns"
	"github.com/mw7101/domudns/internal/filestore"
)

func TestClientGroupsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	fs, err := filestore.NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	ctx := context.Background()

	// File absent → empty slice, no error
	groups, err := fs.GetClientGroups(ctx)
	if err != nil {
		t.Fatalf("GetClientGroups (absent): %v", err)
	}
	if groups == nil {
		t.Error("GetClientGroups: expected non-nil empty slice, got nil")
	}
	if len(groups) != 0 {
		t.Errorf("expected empty, got %d groups", len(groups))
	}

	// Round-trip
	want := []*dns.ClientGroup{
		{Name: "kinder", CIDRs: []string{"192.168.2.0/24"}, Categories: []string{"ads", "adult"}},
		{Name: "iot", CIDRs: []string{"192.168.10.0/24"}, Categories: []string{"malware"}},
	}
	if err := fs.SetClientGroups(ctx, want); err != nil {
		t.Fatalf("SetClientGroups: %v", err)
	}
	got, err := fs.GetClientGroups(ctx)
	if err != nil {
		t.Fatalf("GetClientGroups after set: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(got))
	}
	if got[0].Name != "kinder" || got[1].Name != "iot" {
		t.Errorf("unexpected group names: %v, %v", got[0].Name, got[1].Name)
	}
}
