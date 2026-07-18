package peer

import (
	"path/filepath"
	"testing"

	"github.com/bigblue-r4/slate/internal/evidence"
	"github.com/bigblue-r4/slate/internal/store"
)

func mkBundle(t *testing.T) (*TransferBundle, string, string) {
	t.Helper()
	pubHex, privHex, err := GenerateNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	item := evidence.Item{ID: "EV-1", CaseNumber: "C-1", Description: "Glock", Category: "firearms", Status: "active"}
	events := []store.Entry{{Seq: 1, Event: "slate/intake"}}
	b, err := NewTransferBundle("node-A", "node-B", item, events, "handoff")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(NodeKeyEnv, privHex)
	priv, _, err := LoadNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return b, pubHex, privHex
}

func TestBundleSignVerifyRoundTrip(t *testing.T) {
	b, pubHex, _ := mkBundle(t)
	if err := b.Verify(pubHex); err != nil {
		t.Fatalf("verify should succeed: %v", err)
	}
}

func TestBundleTamperItemRejected(t *testing.T) {
	b, pubHex, _ := mkBundle(t)
	// Mutate the item after signing — verification must fail.
	b.Item.Description = "swapped evidence"
	if err := b.Verify(pubHex); err == nil {
		t.Fatal("tampered item passed verification")
	}
}

func TestBundleTamperEventsRejected(t *testing.T) {
	b, pubHex, _ := mkBundle(t)
	b.Events = append(b.Events, store.Entry{Seq: 2, Event: "slate/injected"})
	if err := b.Verify(pubHex); err == nil {
		t.Fatal("tampered events passed verification")
	}
}

func TestBundleWrongKeyRejected(t *testing.T) {
	b, _, _ := mkBundle(t)
	otherPub, _, _ := GenerateNodeKey()
	if err := b.Verify(otherPub); err == nil {
		t.Fatal("bundle verified under the wrong public key")
	}
}

func TestBundleUnsignedRejected(t *testing.T) {
	item := evidence.Item{ID: "EV-1"}
	b, _ := NewTransferBundle("node-A", "node-B", item, nil, "")
	if err := b.Verify("00"); err == nil {
		t.Fatal("unsigned bundle should not verify")
	}
}

func TestPeerStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := GenerateNodeKey()
	if err := s.Add("node-B", pub, "127.0.0.1:8899"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, ok := s.Lookup("node-B"); !ok {
		t.Fatal("lookup failed")
	}
	// Persistence: reopen and confirm the peer survives.
	s2, _ := Open(path)
	if p, ok := s2.Lookup("node-B"); !ok || p.Address != "127.0.0.1:8899" {
		t.Fatal("peer did not persist")
	}
	if err := s2.Remove("node-B"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, ok := s2.Lookup("node-B"); ok {
		t.Fatal("peer not removed")
	}
}

func TestPeerAddRejectsBadKey(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "peers.json"))
	if err := s.Add("node-X", "xyz", "addr"); err == nil {
		t.Fatal("expected rejection of malformed public key")
	}
}
