// Package peer implements SLATE's multi-node LAN custody handoff.
//
// Trust model (v1.1, manual pairing only):
//
//   - Each node has an Ed25519 identity key. The private key lives ONLY in the
//     SLATE_NODE_KEY environment variable — it is never written to disk, matching
//     SLATE's existing posture for export signing keys.
//   - Peers are enrolled by hand: `slate peer add --node ID --pubkey HEX --addr
//     HOST:PORT`. Enrolled public keys live in peers.json.
//   - A custody handoff is a TransferBundle: the item plus its custody history,
//     signed by the sending node's key. The receiver verifies the signature
//     against the ENROLLED public key for the claimed sender before accepting
//     anything. An unknown sender, a bad signature, or a mutated bundle is
//     rejected and logged — never silently accepted.
//
// The signature covers every field of the bundle (with Signature blanked), so
// any tampering with the item or its events invalidates it.
package peer

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/bigblue-r4/slate/internal/evidence"
	"github.com/bigblue-r4/slate/internal/store"
)

// NodeKeyEnv is the environment variable holding this node's Ed25519 private key
// (hex). It is never persisted to disk.
const NodeKeyEnv = "SLATE_NODE_KEY"

// Peer is an enrolled remote node.
type Peer struct {
	NodeID    string `json:"node_id"`
	PublicKey string `json:"public_key"` // Ed25519 public key, hex
	Address   string `json:"address"`    // host:port of the peer's receive listener
	AddedAt   string `json:"added_at"`   // YYYY-MM-DD
}

// TransferBundle is a signed, single-item custody handoff between nodes.
type TransferBundle struct {
	BundleID     string        `json:"bundle_id"`
	GeneratedAt  time.Time     `json:"generated_at"`
	FromNode     string        `json:"from_node"`
	ToNode       string        `json:"to_node"`
	SenderPubKey string        `json:"sender_pub_key"`      // convenience; receiver verifies against ENROLLED key, not this
	Item         evidence.Item `json:"item"`                // full item snapshot; ID is preserved across the handoff
	Events       []store.Entry `json:"events"`              // the item's custody history from the sender
	EventsHash   string        `json:"events_hash"`         // SHA-256 over the events (also covered by the signature)
	Notes        string        `json:"notes,omitempty"`     // operator note on the handoff
	Signature    string        `json:"signature,omitempty"` // Ed25519 hex over all fields except this one
}

// ── node identity ──────────────────────────────────────────────────────────────

// GenerateNodeKey creates a new Ed25519 node identity keypair. Returns (pubHex, privHex).
func GenerateNodeKey() (string, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(pub), hex.EncodeToString(priv), nil
}

// LoadNodeKey reads this node's private key from SLATE_NODE_KEY and returns the
// private key plus its public-key hex.
func LoadNodeKey() (ed25519.PrivateKey, string, error) {
	h := os.Getenv(NodeKeyEnv)
	if h == "" {
		return nil, "", fmt.Errorf("%s is not set — generate one with `slate peer keygen`", NodeKeyEnv)
	}
	raw, err := hex.DecodeString(h)
	if err != nil {
		return nil, "", fmt.Errorf("decode %s: %w", NodeKeyEnv, err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, "", fmt.Errorf("%s must be %d bytes (%d hex chars)", NodeKeyEnv, ed25519.PrivateKeySize, ed25519.PrivateKeySize*2)
	}
	priv := ed25519.PrivateKey(raw)
	pub := priv.Public().(ed25519.PublicKey)
	return priv, hex.EncodeToString(pub), nil
}

// ── bundle build / sign / verify ───────────────────────────────────────────────

// NewTransferBundle assembles an unsigned bundle for a single item handoff.
func NewTransferBundle(fromNode, toNode string, item evidence.Item, events []store.Entry, notes string) (*TransferBundle, error) {
	id, err := newBundleID()
	if err != nil {
		return nil, err
	}
	return &TransferBundle{
		BundleID:    id,
		GeneratedAt: time.Now().UTC(),
		FromNode:    fromNode,
		ToNode:      toNode,
		Item:        item,
		Events:      events,
		EventsHash:  hashEvents(events),
		Notes:       notes,
	}, nil
}

// Sign signs the bundle with the node private key and records the sender's public key.
func (b *TransferBundle) Sign(priv ed25519.PrivateKey) error {
	b.SenderPubKey = hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	payload, err := b.payload()
	if err != nil {
		return err
	}
	b.Signature = hex.EncodeToString(ed25519.Sign(priv, payload))
	return nil
}

// Verify checks the bundle's signature against the given ENROLLED public key
// (hex) and re-checks the events hash. Returns nil only if the bundle is intact
// and authentic. Callers MUST pass the enrolled key for the claimed sender, not
// bundle.SenderPubKey.
func (b *TransferBundle) Verify(enrolledPubHex string) error {
	if b.Signature == "" {
		return fmt.Errorf("bundle is not signed")
	}
	pub, err := hex.DecodeString(enrolledPubHex)
	if err != nil {
		return fmt.Errorf("decode enrolled public key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("enrolled public key wrong size")
	}
	sig, err := hex.DecodeString(b.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	payload, err := b.payload()
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return fmt.Errorf("signature verification failed")
	}
	if hashEvents(b.Events) != b.EventsHash {
		return fmt.Errorf("events hash mismatch — bundle contents altered")
	}
	return nil
}

func (b *TransferBundle) payload() ([]byte, error) {
	tmp := *b
	tmp.Signature = ""
	return json.Marshal(tmp)
}

func hashEvents(events []store.Entry) string {
	h := sha256.New()
	for _, e := range events {
		b, _ := json.Marshal(e)
		_, _ = h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func newBundleID() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("XFER-%s-%s", time.Now().UTC().Format("20060102"), hex.EncodeToString(b[:])), nil
}

// ── peer registry ──────────────────────────────────────────────────────────────

// Store is the enrolled-peer registry backed by peers.json.
type Store struct {
	mu    sync.RWMutex
	path  string
	peers []Peer
}

// Open reads or creates the peer store at path.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	return s, s.load()
}

// Add enrolls (or updates) a peer.
func (s *Store) Add(nodeID, pubKeyHex, address string) error {
	if nodeID == "" || pubKeyHex == "" {
		return fmt.Errorf("node id and public key are required")
	}
	raw, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("public key must be %d hex chars", ed25519.PublicKeySize*2)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, p := range s.peers {
		if p.NodeID == nodeID {
			s.peers[i] = Peer{NodeID: nodeID, PublicKey: pubKeyHex, Address: address, AddedAt: p.AddedAt}
			return s.save()
		}
	}
	s.peers = append(s.peers, Peer{
		NodeID:    nodeID,
		PublicKey: pubKeyHex,
		Address:   address,
		AddedAt:   time.Now().UTC().Format("2006-01-02"),
	})
	return s.save()
}

// SetAddress updates only the network address of an already-enrolled peer,
// leaving its public key and enrollment date untouched. This is the safe target
// of address auto-refresh: the caller must have already confirmed the refreshing
// announcement was signed by this peer's ENROLLED public key, so the trust anchor
// never changes — only where to reach it.
func (s *Store) SetAddress(nodeID, address string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, p := range s.peers {
		if p.NodeID == nodeID {
			s.peers[i].Address = address
			return s.save()
		}
	}
	return fmt.Errorf("peer not found: %s", nodeID)
}

// Remove drops an enrolled peer by node ID.
func (s *Store) Remove(nodeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var kept []Peer
	found := false
	for _, p := range s.peers {
		if p.NodeID == nodeID {
			found = true
			continue
		}
		kept = append(kept, p)
	}
	if !found {
		return fmt.Errorf("peer not found: %s", nodeID)
	}
	s.peers = kept
	return s.save()
}

// Lookup returns the enrolled peer for a node ID.
func (s *Store) Lookup(nodeID string) (Peer, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.peers {
		if p.NodeID == nodeID {
			return p, true
		}
	}
	return Peer{}, false
}

// Reload re-reads peers.json from disk so enrollment or revocation takes effect
// without restarting the peer listener (parity with the token store).
func (s *Store) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peers = nil
	return s.load()
}

// List returns a copy of all enrolled peers.
func (s *Store) List() []Peer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Peer, len(s.peers))
	copy(out, s.peers)
	return out
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var ps struct {
		Peers []Peer `json:"peers"`
	}
	if err := json.Unmarshal(data, &ps); err != nil {
		return err
	}
	s.peers = ps.Peers
	return nil
}

func (s *Store) save() error {
	ps := struct {
		Peers []Peer `json:"peers"`
	}{Peers: s.peers}
	data, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0600)
}
