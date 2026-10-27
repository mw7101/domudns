package filestore_test

import (
	"context"
	"testing"
	"time"

	"github.com/mw7101/domudns/internal/filestore"
	"github.com/mw7101/domudns/internal/store"
)

func newTSIGStore(t *testing.T) *filestore.FileStore {
	t.Helper()
	fs, err := filestore.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func TestTSIG_PutAndGet(t *testing.T) {
	fs := newTSIGStore(t)
	ctx := context.Background()

	key := store.TSIGKey{
		Name:      "dhcp-dns",
		Algorithm: "hmac-sha256",
		Secret:    "base64secret==",
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}

	if err := fs.PutTSIGKey(ctx, key); err != nil {
		t.Fatalf("PutTSIGKey: %v", err)
	}

	keys, err := fs.GetTSIGKeys(ctx)
	if err != nil {
		t.Fatalf("GetTSIGKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(keys))
	}
	if keys[0].Name != key.Name {
		t.Errorf("want name=%q, got %q", key.Name, keys[0].Name)
	}
	if keys[0].Secret != key.Secret {
		t.Errorf("want secret=%q, got %q", key.Secret, keys[0].Secret)
	}
	if keys[0].Algorithm != key.Algorithm {
		t.Errorf("want algorithm=%q, got %q", key.Algorithm, keys[0].Algorithm)
	}
}

func TestTSIG_Put_Upsert(t *testing.T) {
	fs := newTSIGStore(t)
	ctx := context.Background()

	key1 := store.TSIGKey{Name: "my-key", Algorithm: "hmac-sha256", Secret: "secret1"}
	if err := fs.PutTSIGKey(ctx, key1); err != nil {
		t.Fatal(err)
	}

	// Same name → replace (Upsert)
	key2 := store.TSIGKey{Name: "my-key", Algorithm: "hmac-sha512", Secret: "secret2"}
	if err := fs.PutTSIGKey(ctx, key2); err != nil {
		t.Fatal(err)
	}

	keys, err := fs.GetTSIGKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("upsert: want 1 key, got %d", len(keys))
	}
	if keys[0].Secret != "secret2" {
		t.Errorf("upsert: want secret2, got %q", keys[0].Secret)
	}
	if keys[0].Algorithm != "hmac-sha512" {
		t.Errorf("upsert: want hmac-sha512, got %q", keys[0].Algorithm)
	}
}

func TestTSIG_Delete(t *testing.T) {
	fs := newTSIGStore(t)
	ctx := context.Background()

	for _, name := range []string{"key-a", "key-b", "key-c"} {
		if err := fs.PutTSIGKey(ctx, store.TSIGKey{Name: name, Algorithm: "hmac-sha256", Secret: "s"}); err != nil {
			t.Fatal(err)
		}
	}

	if err := fs.DeleteTSIGKey(ctx, "key-b"); err != nil {
		t.Fatalf("DeleteTSIGKey: %v", err)
	}

	keys, err := fs.GetTSIGKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("want 2 keys after delete, got %d", len(keys))
	}
	for _, k := range keys {
		if k.Name == "key-b" {
			t.Error("deleted key still present")
		}
	}
}

func TestTSIG_Delete_NonExistent(t *testing.T) {
	fs := newTSIGStore(t)
	ctx := context.Background()

	// Deleting a non-existent key must not fail
	if err := fs.DeleteTSIGKey(ctx, "does-not-exist"); err != nil {
		t.Errorf("DeleteTSIGKey non-existent: %v", err)
	}
}

func TestTSIG_GetEmpty(t *testing.T) {
	fs := newTSIGStore(t)
	ctx := context.Background()

	keys, err := fs.GetTSIGKeys(ctx)
	if err != nil {
		t.Fatalf("GetTSIGKeys on empty store: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("want empty list, got %d", len(keys))
	}
}

func TestTSIG_SetTSIGKeys_BulkReplace(t *testing.T) {
	fs := newTSIGStore(t)
	ctx := context.Background()

	// First create 3 keys
	for _, name := range []string{"a", "b", "c"} {
		_ = fs.PutTSIGKey(ctx, store.TSIGKey{Name: name, Algorithm: "hmac-sha256", Secret: "s"})
	}

	// SetTSIGKeys replaces completely
	newKeys := []store.TSIGKey{
		{Name: "x", Algorithm: "hmac-sha256", Secret: "sx"},
		{Name: "y", Algorithm: "hmac-sha512", Secret: "sy"},
	}
	if err := fs.SetTSIGKeys(ctx, newKeys); err != nil {
		t.Fatalf("SetTSIGKeys: %v", err)
	}

	keys, err := fs.GetTSIGKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("want 2 keys after SetTSIGKeys, got %d", len(keys))
	}
	names := map[string]bool{}
	for _, k := range keys {
		names[k.Name] = true
	}
	if !names["x"] || !names["y"] {
		t.Errorf("wrong keys after SetTSIGKeys: %v", keys)
	}
	if names["a"] || names["b"] || names["c"] {
		t.Error("old keys still present after SetTSIGKeys")
	}
}
