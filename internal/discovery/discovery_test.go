package discovery

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func newKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, hex.EncodeToString(pub)
}

func signed(t *testing.T, priv ed25519.PrivateKey, nodeID string, port int, ts time.Time) *Announcement {
	t.Helper()
	a := &Announcement{NodeID: nodeID, Port: port, Department: "HPD", Time: ts}
	if err := a.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAnnouncementSignVerifyRoundTrip(t *testing.T) {
	priv, pubHex := newKey(t)
	a := signed(t, priv, "node-A", 8891, time.Now().UTC())
	if a.PubKey != pubHex {
		t.Fatalf("Sign did not stamp the public key: got %s want %s", a.PubKey, pubHex)
	}
	if err := a.Verify(); err != nil {
		t.Fatalf("verify should succeed: %v", err)
	}
}

func TestAnnouncementTamperRejected(t *testing.T) {
	priv, _ := newKey(t)
	a := signed(t, priv, "node-A", 8891, time.Now().UTC())
	a.Port = 9999 // mutate a signed field
	if err := a.Verify(); err == nil {
		t.Fatal("tampered announcement passed verification")
	}
}

func TestAnnouncementForgedKeyRejected(t *testing.T) {
	priv, _ := newKey(t)
	a := signed(t, priv, "node-A", 8891, time.Now().UTC())
	// Swap in a different public key while keeping the original signature —
	// simulates an attacker trying to claim someone else's identity.
	_, otherPub := newKey(t)
	a.PubKey = otherPub
	if err := a.Verify(); err == nil {
		t.Fatal("announcement verified under a swapped public key")
	}
}

func TestAnnouncementUnsignedRejected(t *testing.T) {
	a := &Announcement{NodeID: "node-A", Port: 8891, Time: time.Now().UTC()}
	if err := a.Verify(); err == nil {
		t.Fatal("unsigned announcement should not verify")
	}
}

func TestFingerprintStableAndDistinct(t *testing.T) {
	_, pubA := newKey(t)
	_, pubB := newKey(t)
	fpA1 := Fingerprint(pubA)
	fpA2 := Fingerprint(pubA)
	if fpA1 != fpA2 {
		t.Fatal("fingerprint is not stable")
	}
	if fpA1 == Fingerprint(pubB) {
		t.Fatal("distinct keys produced the same fingerprint")
	}
	if Fingerprint("not-hex") != "invalid" {
		t.Fatal("malformed key should fingerprint as invalid")
	}
}

func TestCollectorVerifiesAndResolvesAddress(t *testing.T) {
	priv, _ := newKey(t)
	a := signed(t, priv, "node-A", 8891, time.Now().UTC())
	raw, _ := json.Marshal(a)

	c := newCollector()
	if !c.offer(raw, "192.168.1.50") {
		t.Fatal("valid announcement was not accepted")
	}
	res := c.results()
	if len(res) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res))
	}
	if res[0].Addr != "192.168.1.50:8891" {
		t.Fatalf("address not resolved from source host: %s", res[0].Addr)
	}
	if res[0].Fingerprint != a.Fingerprint() {
		t.Fatal("fingerprint mismatch in result")
	}
}

func TestCollectorRejectsUnverifiable(t *testing.T) {
	priv, _ := newKey(t)
	a := signed(t, priv, "node-A", 8891, time.Now().UTC())
	a.Signature = "00" // corrupt signature
	raw, _ := json.Marshal(a)

	c := newCollector()
	if c.offer(raw, "192.168.1.50") {
		t.Fatal("unverifiable announcement was accepted")
	}
	if c.offer([]byte("{not json"), "192.168.1.50") {
		t.Fatal("garbage packet was accepted")
	}
	if len(c.results()) != 0 {
		t.Fatal("collector should hold nothing")
	}
}

func TestCollectorKeepsLatestPerNode(t *testing.T) {
	priv, _ := newKey(t)
	base := time.Now().UTC()

	older := signed(t, priv, "node-A", 8891, base)
	newer := signed(t, priv, "node-A", 8892, base.Add(time.Second))
	rawOld, _ := json.Marshal(older)
	rawNew, _ := json.Marshal(newer)

	c := newCollector()
	// Deliver newest first, then an older duplicate — the older must not win.
	c.offer(rawNew, "10.0.0.9")
	c.offer(rawOld, "10.0.0.9")

	res := c.results()
	if len(res) != 1 {
		t.Fatalf("expected dedupe to 1 node, got %d", len(res))
	}
	if res[0].Addr != "10.0.0.9:8892" {
		t.Fatalf("collector did not keep the newest announcement: %s", res[0].Addr)
	}
}

func TestCollectorRejectsBadPort(t *testing.T) {
	priv, _ := newKey(t)
	a := signed(t, priv, "node-A", 0, time.Now().UTC())
	raw, _ := json.Marshal(a)
	c := newCollector()
	if c.offer(raw, "10.0.0.1") {
		t.Fatal("announcement with invalid port was accepted")
	}
}

// TestBroadcastRequiresSignature guards the send path against leaking unsigned
// beacons.
func TestBroadcastRequiresSignature(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &Announcement{NodeID: "node-A", Port: 8891}
	if err := Broadcast(ctx, "239.255.42.99:8892", a, DefaultInterval); err == nil {
		t.Fatal("broadcasting an unsigned announcement should fail")
	}
}

// TestListenBroadcastLoopback is a best-effort end-to-end check over real
// multicast sockets. Environments that forbid multicast (some CI sandboxes) skip
// it rather than fail.
func TestListenBroadcastLoopback(t *testing.T) {
	const group = "239.255.42.123:8899"
	priv, _ := newKey(t)
	a := signed(t, priv, "node-live", 8891, time.Now().UTC())

	bctx, bcancel := context.WithCancel(context.Background())
	broadcastErr := make(chan error, 1)
	go func() { broadcastErr <- Broadcast(bctx, group, a, 200*time.Millisecond) }()

	res, err := Listen(context.Background(), group, 1200*time.Millisecond)
	bcancel()
	if berr := <-broadcastErr; berr != nil {
		t.Skipf("multicast not available in this environment: %v", berr)
	}
	if err != nil {
		t.Skipf("multicast listen unavailable: %v", err)
	}
	if len(res) == 0 {
		t.Skip("no packets received — multicast likely filtered in this environment")
	}
	if res[0].NodeID != "node-live" {
		t.Fatalf("unexpected node discovered: %s", res[0].NodeID)
	}
}
