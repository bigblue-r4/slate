// Package discovery implements SLATE's LAN peer auto-discovery.
//
// Discovery answers one question — "which SLATE nodes are on this LAN, and at
// what address?" — WITHOUT ever granting trust. It is deliberately separate from
// enrollment:
//
//   - A serving node MAY broadcast a signed Announcement (opt-in, `slate serve
//     --announce`). The announcement is self-signed with the node's Ed25519
//     identity key: the signature proves the announcer holds the private key for
//     the public key it advertises, and makes the packet tamper-evident.
//   - A discovering node collects and verifies announcements. Verification proves
//     integrity and key-possession — it does NOT imply the peer should be trusted.
//     Trust is still established by hand (`slate peer add`) after operators compare
//     fingerprints out of band.
//
// The safe, automatable win discovery unlocks is address refresh: for a peer that
// is ALREADY enrolled, an announcement signed by its enrolled public key can be
// used to update that peer's address (the DHCP-drift fix), because forging it
// would require the peer's private key. An announcement whose key does NOT match
// the enrolled key is a possible impersonation and is refused.
//
// Only the standard library is used (UDP multicast) — no third-party mDNS/zeroconf
// dependency — matching SLATE's minimal-surface-area posture.
package discovery

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"time"
)

// Defaults for the discovery transport. The group is an organization-local scope
// multicast address (239.0.0.0/8), analogous to how mDNS uses 224.0.0.251.
const (
	DefaultGroup    = "239.255.42.99"
	DefaultPort     = 8892
	DefaultInterval = 5 * time.Second
	maxPacket       = 2048
)

// Announcement is a node's self-signed presence beacon. The host is intentionally
// absent — the discoverer learns it from the UDP packet's source address, so the
// beacon stays correct even when DHCP moves the node. The signature therefore
// covers only fields the announcer can vouch for.
type Announcement struct {
	NodeID     string    `json:"node_id"`
	PubKey     string    `json:"pub_key"`             // Ed25519 public key, hex
	Port       int       `json:"port"`                // the node's peer-listen port
	Department string    `json:"department"`          // informational
	Time       time.Time `json:"time"`                // send time (UTC)
	Signature  string    `json:"signature,omitempty"` // Ed25519 hex over all fields except this one
}

// Sign self-signs the announcement with the node's private key and stamps PubKey.
func (a *Announcement) Sign(priv ed25519.PrivateKey) error {
	a.PubKey = hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	payload, err := a.payload()
	if err != nil {
		return err
	}
	a.Signature = hex.EncodeToString(ed25519.Sign(priv, payload))
	return nil
}

// Verify checks the announcement's self-signature against its own advertised
// PubKey. Success proves the packet is intact and the sender holds the private
// key for PubKey. It does NOT imply the node is trusted — enrollment is separate.
func (a *Announcement) Verify() error {
	if a.Signature == "" {
		return fmt.Errorf("announcement is not signed")
	}
	pub, err := hex.DecodeString(a.PubKey)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("public key wrong size")
	}
	sig, err := hex.DecodeString(a.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	payload, err := a.payload()
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// Fingerprint returns a short, human-comparable fingerprint of the public key
// (first 8 bytes of its SHA-256, grouped) for out-of-band verification.
func (a *Announcement) Fingerprint() string {
	return Fingerprint(a.PubKey)
}

// Fingerprint returns a short comparable fingerprint for an Ed25519 public key hex.
func Fingerprint(pubHex string) string {
	raw, err := hex.DecodeString(pubHex)
	if err != nil {
		return "invalid"
	}
	sum := sha256.Sum256(raw)
	h := hex.EncodeToString(sum[:8])
	return fmt.Sprintf("%s-%s-%s-%s", h[0:4], h[4:8], h[8:12], h[12:16])
}

func (a *Announcement) payload() ([]byte, error) {
	tmp := *a
	tmp.Signature = ""
	return json.Marshal(tmp)
}

// Result is a discovered node: a verified announcement plus the address resolved
// from the UDP packet's source IP.
type Result struct {
	NodeID      string    `json:"node_id"`
	PubKey      string    `json:"pub_key"`
	Addr        string    `json:"addr"` // resolved host:port
	Department  string    `json:"department"`
	Fingerprint string    `json:"fingerprint"`
	Time        time.Time `json:"time"`
}

// collector verifies incoming packets and keeps the most recent announcement per
// node ID. It is transport-agnostic so it can be unit-tested without sockets.
type collector struct {
	seen map[string]Result
}

func newCollector() *collector { return &collector{seen: map[string]Result{}} }

// offer decodes, verifies, and records one raw packet observed from srcHost.
// Invalid or unverifiable packets are ignored. It reports whether the packet was
// accepted (useful for tests).
func (c *collector) offer(raw []byte, srcHost string) bool {
	var a Announcement
	if err := json.Unmarshal(raw, &a); err != nil {
		return false
	}
	if err := a.Verify(); err != nil {
		return false
	}
	if a.NodeID == "" || a.Port <= 0 || a.Port > 65535 {
		return false
	}
	prev, ok := c.seen[a.NodeID]
	if ok && !a.Time.After(prev.Time) {
		return true // older or duplicate; keep the newer record
	}
	c.seen[a.NodeID] = Result{
		NodeID:      a.NodeID,
		PubKey:      a.PubKey,
		Addr:        net.JoinHostPort(srcHost, fmt.Sprintf("%d", a.Port)),
		Department:  a.Department,
		Fingerprint: a.Fingerprint(),
		Time:        a.Time,
	}
	return true
}

// results returns the collected nodes sorted by node ID.
func (c *collector) results() []Result {
	out := make([]Result, 0, len(c.seen))
	for _, r := range c.seen {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

// Broadcast periodically sends the signed announcement to the multicast group
// until ctx is cancelled. It sends one announcement immediately, then every
// interval. group is "host:port"; if interval <= 0, DefaultInterval is used.
func Broadcast(ctx context.Context, group string, ann *Announcement, interval time.Duration) error {
	if ann.Signature == "" {
		return fmt.Errorf("announcement must be signed before broadcasting")
	}
	if interval <= 0 {
		interval = DefaultInterval
	}
	dst, err := net.ResolveUDPAddr("udp4", group)
	if err != nil {
		return fmt.Errorf("resolve group %q: %w", group, err)
	}
	conn, err := net.DialUDP("udp4", nil, dst)
	if err != nil {
		return fmt.Errorf("dial multicast group: %w", err)
	}
	defer conn.Close()

	data, err := json.Marshal(ann)
	if err != nil {
		return err
	}

	send := func() {
		_, _ = conn.Write(data)
	}
	send()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			send()
		}
	}
}

// Listen joins the multicast group and collects verified announcements for the
// given duration, returning the most recent record per node. group is "host:port".
func Listen(ctx context.Context, group string, d time.Duration) ([]Result, error) {
	gaddr, err := net.ResolveUDPAddr("udp4", group)
	if err != nil {
		return nil, fmt.Errorf("resolve group %q: %w", group, err)
	}
	conn, err := net.ListenMulticastUDP("udp4", nil, gaddr)
	if err != nil {
		return nil, fmt.Errorf("join multicast group: %w", err)
	}
	defer conn.Close()
	_ = conn.SetReadBuffer(maxPacket * 8)

	deadline := time.Now().Add(d)
	_ = conn.SetReadDeadline(deadline)

	c := newCollector()
	buf := make([]byte, maxPacket)
	for {
		select {
		case <-ctx.Done():
			return c.results(), nil
		default:
		}
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			// Deadline reached (or transient error): return what we have.
			return c.results(), nil
		}
		host := ""
		if src != nil {
			host = src.IP.String()
		}
		c.offer(append([]byte(nil), buf[:n]...), host)
	}
}
