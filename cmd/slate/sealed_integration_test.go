package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bigblue-r4/slate/internal/evidence"
	"github.com/bigblue-r4/slate/internal/peer"
)

// newSealedReceiver builds a node-B server that has its own X25519 key set (so it
// can open sealed bundles) and node-A enrolled as sender. Returns the server, the
// sender's private key hex, and node-B's enrolled encryption public key.
func newSealedReceiver(t *testing.T) (*server, string, string) {
	t.Helper()
	evDir := t.TempDir()
	ev, err := evidence.Open(evDir, intKey())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ev.Close() })

	senderPub, senderPriv, _ := peer.GenerateNodeKey()
	ps, _ := peer.Open(t.TempDir() + "/peers.json")
	if err := ps.Add("node-A", senderPub, "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}

	// Node-B's own identity → derived X25519 key it decrypts with.
	_, bPrivHex, _ := peer.GenerateNodeKey()
	bEd, _, _ := peer.DecodeNodeKey(bPrivHex)
	bEncPriv, bEncPub, err := peer.DeriveEncKey(bEd)
	if err != nil {
		t.Fatal(err)
	}

	srv := &server{store: ev, cfg: Config{NodeID: "node-B"}, dir: evDir, key: intKey(), peerStore: ps, nodeEncPriv: bEncPriv}
	return srv, senderPriv, bEncPub
}

func sealedFor(t *testing.T, senderPrivHex, recipientEncPub string) *peer.SealedBundle {
	t.Helper()
	item := evidence.Item{ID: "EV-SEALED-1", CaseNumber: "C-7", Description: "confidential item", Category: "narcotics", Status: "active"}
	b, _ := peer.NewTransferBundle("node-A", "node-B", item, nil, "encrypted handoff")
	t.Setenv(peer.NodeKeyEnv, senderPrivHex)
	priv, _, err := peer.LoadNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Sign(priv); err != nil {
		t.Fatal(err)
	}
	sealed, err := peer.SealTo(b, recipientEncPub)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func postSealed(t *testing.T, srv *server, s *peer.SealedBundle) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(s)
	r := httptest.NewRequest(http.MethodPost, "/api/peer/receive-sealed", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handlePeerReceiveSealed(w, r)
	return w
}

func TestSealedReceiveAccepts(t *testing.T) {
	srv, senderPriv, bEncPub := newSealedReceiver(t)
	w := postSealed(t, srv, sealedFor(t, senderPriv, bEncPub))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if _, ok := srv.store.GetItem("EV-SEALED-1"); !ok {
		t.Fatal("item was not stored after sealed accept")
	}
	if res, _ := srv.store.VerifyChain(); !res.OK {
		t.Fatalf("receiver chain broken after sealed accept: %+v", res)
	}
}

func TestSealedReceiveRejectsTamperedCiphertext(t *testing.T) {
	srv, senderPriv, bEncPub := newSealedReceiver(t)
	sealed := sealedFor(t, senderPriv, bEncPub)
	raw, _ := base64.StdEncoding.DecodeString(sealed.Ciphertext)
	raw[len(raw)/2] ^= 0xFF
	sealed.Ciphertext = base64.StdEncoding.EncodeToString(raw)

	w := postSealed(t, srv, sealed)
	if w.Code == http.StatusOK {
		t.Fatal("tampered sealed bundle was accepted")
	}
	if _, ok := srv.store.GetItem("EV-SEALED-1"); ok {
		t.Fatal("tampered sealed item must not be stored")
	}
	assertRejectLogged(t, srv)
}

func TestSealedReceiveRejectsWrongRecipientKey(t *testing.T) {
	srv, senderPriv, _ := newSealedReceiver(t)
	// Seal to a DIFFERENT recipient key than node-B holds.
	_, strangerHex, _ := peer.GenerateNodeKey()
	strangerEd, _, _ := peer.DecodeNodeKey(strangerHex)
	_, strangerEncPub, _ := peer.DeriveEncKey(strangerEd)

	w := postSealed(t, srv, sealedFor(t, senderPriv, strangerEncPub))
	if w.Code == http.StatusOK {
		t.Fatal("sealed bundle for a different recipient was accepted")
	}
	assertRejectLogged(t, srv)
}

func TestSealedReceiveRejectsUnenrolledSenderAfterDecrypt(t *testing.T) {
	srv, _, bEncPub := newSealedReceiver(t)
	// A stranger signs and seals correctly to node-B, but is not enrolled.
	_, strangerPriv, _ := peer.GenerateNodeKey()
	sealed := sealedForFrom(t, "node-UNKNOWN", strangerPriv, bEncPub)
	w := postSealed(t, srv, sealed)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unenrolled sender after decrypt, got %d: %s", w.Code, w.Body.String())
	}
	assertRejectLogged(t, srv)
}

func TestSealedReceiveUnavailableWithoutNodeKey(t *testing.T) {
	srv, senderPriv, bEncPub := newSealedReceiver(t)
	srv.nodeEncPriv = nil // simulate SLATE_NODE_KEY unset on the receiver
	w := postSealed(t, srv, sealedFor(t, senderPriv, bEncPub))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when node key unset, got %d", w.Code)
	}
}

// sealedForFrom is like sealedFor but lets the caller set the claimed from-node.
func sealedForFrom(t *testing.T, fromNode, senderPrivHex, recipientEncPub string) *peer.SealedBundle {
	t.Helper()
	item := evidence.Item{ID: "EV-SEALED-2", CaseNumber: "C-8", Description: "x", Category: "documents", Status: "active"}
	b, _ := peer.NewTransferBundle(fromNode, "node-B", item, nil, "")
	t.Setenv(peer.NodeKeyEnv, senderPrivHex)
	priv, _, err := peer.LoadNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Sign(priv); err != nil {
		t.Fatal(err)
	}
	sealed, err := peer.SealTo(b, recipientEncPub)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}
