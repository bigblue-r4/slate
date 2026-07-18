package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bigblue-r4/slate/internal/apiwire"
	"github.com/bigblue-r4/slate/internal/evidence"
	"github.com/bigblue-r4/slate/internal/peer"
)

func intKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

// newReceiver builds a node-B server with an enrolled sender node-A.
func newReceiver(t *testing.T) (*server, string) {
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
	srv := &server{store: ev, cfg: Config{NodeID: "node-B"}, dir: evDir, key: intKey(), peerStore: ps}
	return srv, senderPriv
}

func signedBundle(t *testing.T, privHex string) *peer.TransferBundle {
	t.Helper()
	item := evidence.Item{ID: "EV-XNODE-1", CaseNumber: "C-1", Description: "sealed bag", Category: "documents", Status: "active"}
	b, _ := peer.NewTransferBundle("node-A", "node-B", item, nil, "handoff")
	t.Setenv(peer.NodeKeyEnv, privHex)
	priv, _, err := peer.LoadNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return b
}

func postBundle(t *testing.T, srv *server, b *peer.TransferBundle) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(b)
	r := httptest.NewRequest(http.MethodPost, "/api/peer/receive", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.handlePeerReceive(w, r)
	return w
}

func TestPeerReceiveAccepts(t *testing.T) {
	srv, priv := newReceiver(t)
	w := postBundle(t, srv, signedBundle(t, priv))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if _, ok := srv.store.GetItem("EV-XNODE-1"); !ok {
		t.Fatal("item was not stored after accept")
	}
	// The receiver's chain must remain intact across the handoff.
	if res, _ := srv.store.VerifyChain(); !res.OK {
		t.Fatalf("receiver chain broken: %+v", res)
	}
}

func TestPeerReceiveRejectsTamper(t *testing.T) {
	srv, priv := newReceiver(t)
	b := signedBundle(t, priv)
	b.Item.Description = "SWAPPED evidence" // mutate after signing
	w := postBundle(t, srv, b)
	if w.Code == http.StatusOK {
		t.Fatal("tampered bundle was accepted")
	}
	if _, ok := srv.store.GetItem("EV-XNODE-1"); ok {
		t.Fatal("tampered item must not be stored")
	}
	// The rejection must be recorded in the audit log.
	assertRejectLogged(t, srv)
}

func TestPeerReceiveRejectsUnenrolled(t *testing.T) {
	srv, _ := newReceiver(t)
	_, strangerPriv, _ := peer.GenerateNodeKey()
	b := signedBundle(t, strangerPriv)
	b.FromNode = "node-UNKNOWN"
	w := postBundle(t, srv, b)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unenrolled sender, got %d", w.Code)
	}
	assertRejectLogged(t, srv)
}

func assertRejectLogged(t *testing.T, srv *server) {
	t.Helper()
	events, _ := srv.store.GetAllEvents()
	for _, e := range events {
		if e.Event == "slate/peer_reject" && e.Level == "WARN" {
			return
		}
	}
	t.Fatal("expected a slate/peer_reject WARN audit event")
}

func TestPeerReceiveResponseEnvelope(t *testing.T) {
	srv, priv := newReceiver(t)
	w := postBundle(t, srv, signedBundle(t, priv))
	var env apiwire.Envelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("response not an envelope: %v", err)
	}
	if env.Schema != apiwire.Schema || !env.OK {
		t.Fatalf("bad envelope: %+v", env)
	}
}
