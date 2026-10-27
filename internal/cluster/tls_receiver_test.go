package cluster_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/mw7101/domudns/internal/cluster"
	"github.com/mw7101/domudns/internal/store"
)

func TestApplyTLSCert(t *testing.T) {
	fs := newTestStore(t)
	reloadedCh := make(chan struct{}, 1)
	callbacks := cluster.ReloadCallbacks{
		TLSReloader: func() error {
			reloadedCh <- struct{}{}
			return nil
		},
	}
	h := cluster.NewReceiverHandler(fs, "testsecret", callbacks)

	payload := store.TLSCertPayload{CertPEM: "cert", KeyPEM: "key"}
	data, _ := json.Marshal(payload)
	req := cluster.SyncRequest{Type: cluster.EventTLSCert, Data: json.RawMessage(data)}

	ctx := context.Background()
	if err := h.ApplyEventForTest(ctx, req); err != nil {
		t.Fatalf("applyEvent: %v", err)
	}

	// Wait for async TLSReloader call
	select {
	case <-reloadedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("TLSReloader not called within timeout")
	}

	got, err := fs.GetTLSCert(ctx)
	if err != nil {
		t.Fatalf("GetTLSCert: %v", err)
	}
	if got == nil || got.CertPEM != "cert" {
		t.Fatalf("cert not stored: %+v", got)
	}
}
