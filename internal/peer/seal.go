// Sealed transfer bundles (v1.3): end-to-end confidentiality for LAN handoffs.
//
// v1.1/v1.2 signed the bundle but sent it in cleartext, so item metadata was
// visible to a LAN eavesdropper. Sealing encrypts the whole bundle to the
// recipient's enrolled X25519 key. The design deliberately mirrors the signed-
// bundle philosophy — secure the EVIDENCE ITSELF, not just the pipe — and needs
// no CA/PKI:
//
//   - Each node's X25519 encryption key is derived from its EXISTING Ed25519
//     identity seed (DeriveEncKey). No new secret is introduced — SLATE_NODE_KEY
//     is still the only private key material. The X25519 *public* key cannot be
//     derived from the Ed25519 *public* key, so peers enroll it alongside the
//     signing key (Peer.EncPubKey), exchanged as one combined identity token.
//   - A sealed bundle uses an ephemeral X25519 key per handoff (forward secrecy):
//     ECDH(ephemeral, recipient-static) → HKDF → ChaCha20-Poly1305. Only the
//     ephemeral public key, nonce, and ciphertext travel in the clear; the item,
//     its events, and even the sender's node ID are inside the ciphertext.
//   - The inner Ed25519 signature is untouched, so after decryption the receiver
//     authenticates the sender exactly as before. Encryption adds confidentiality;
//     it does not replace authentication.
//
// Only the standard library (crypto/ecdh) and x/crypto (already a dependency) are
// used — no new third-party surface.
package peer

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	encKDFInfo   = "slate/peer-enc-x25519/v1" // derive a node's X25519 key from its Ed25519 seed
	encKDFSalt   = "slate-peer-enc-salt-2026"
	sealKDFInfo  = "slate/peer-seal/v1" // derive a per-handoff AEAD key
	sealKDFSalt  = "slate-peer-seal-salt-2026"
	sealVersion  = "slate-seal-v1"
	identitySep  = "." // combined identity token: "<ed25519hex>.<x25519hex>"
	x25519KeyLen = 32
)

// DeriveEncKey derives this node's static X25519 encryption key from its Ed25519
// identity private key. The result is a deterministic function of the same secret
// already held in SLATE_NODE_KEY. Returns the X25519 private key plus its public
// key hex — the value peers must enroll to send this node sealed bundles.
func DeriveEncKey(edPriv ed25519.PrivateKey) (*ecdh.PrivateKey, string, error) {
	if len(edPriv) != ed25519.PrivateKeySize {
		return nil, "", fmt.Errorf("invalid Ed25519 private key")
	}
	r := hkdf.New(sha256.New, edPriv.Seed(), []byte(encKDFSalt), []byte(encKDFInfo))
	scalar := make([]byte, x25519KeyLen)
	if _, err := io.ReadFull(r, scalar); err != nil {
		return nil, "", err
	}
	priv, err := ecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		return nil, "", err
	}
	return priv, hex.EncodeToString(priv.PublicKey().Bytes()), nil
}

// IdentityToken combines a node's signing (Ed25519) and encryption (X25519) public
// keys into the single token operators exchange out of band.
func IdentityToken(sigPubHex, encPubHex string) string {
	return sigPubHex + identitySep + encPubHex
}

// SplitIdentityToken parses a combined identity token. A bare signing key (no
// separator) is accepted for backward compatibility and yields an empty encPub.
func SplitIdentityToken(token string) (sigPubHex, encPubHex string) {
	if i := strings.IndexByte(token, identitySep[0]); i >= 0 {
		return token[:i], token[i+1:]
	}
	return token, ""
}

// SealedBundle is a TransferBundle encrypted end-to-end to a recipient's enrolled
// X25519 key. It carries no node identifiers in the clear — every custody detail,
// including the sender's node ID, lives inside Ciphertext.
type SealedBundle struct {
	Version    string `json:"version"`    // sealVersion
	EphPub     string `json:"eph_pub"`    // ephemeral X25519 public key, hex
	Nonce      string `json:"nonce"`      // AEAD nonce, hex
	Ciphertext string `json:"ciphertext"` // base64 AEAD ciphertext of the bundle JSON
}

// SealTo encrypts a signed bundle to the recipient's X25519 public key (hex). An
// unsigned bundle is refused — sealing never substitutes for signing.
func SealTo(b *TransferBundle, recipientEncPubHex string) (*SealedBundle, error) {
	if b.Signature == "" {
		return nil, fmt.Errorf("refusing to seal an unsigned bundle")
	}
	rpub, err := decodeX25519Pub(recipientEncPubHex)
	if err != nil {
		return nil, fmt.Errorf("recipient encryption key: %w", err)
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(rpub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	aead, err := sealAEAD(shared, eph.PublicKey().Bytes(), rpub.Bytes())
	if err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)
	return &SealedBundle{
		Version:    sealVersion,
		EphPub:     hex.EncodeToString(eph.PublicKey().Bytes()),
		Nonce:      hex.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// Open decrypts a sealed bundle with this node's static X25519 private key. It
// returns the inner TransferBundle; the caller still verifies its signature.
func (s *SealedBundle) Open(ownEncPriv *ecdh.PrivateKey) (*TransferBundle, error) {
	if s.Version != sealVersion {
		return nil, fmt.Errorf("unsupported sealed-bundle version %q", s.Version)
	}
	ephBytes, err := hex.DecodeString(s.EphPub)
	if err != nil {
		return nil, fmt.Errorf("decode ephemeral key: %w", err)
	}
	ephPub, err := ecdh.X25519().NewPublicKey(ephBytes)
	if err != nil {
		return nil, fmt.Errorf("ephemeral key: %w", err)
	}
	shared, err := ownEncPriv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	aead, err := sealAEAD(shared, ephBytes, ownEncPriv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	nonce, err := hex.DecodeString(s.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("bad nonce length")
	}
	ct, err := base64.StdEncoding.DecodeString(s.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong key or tampered): %w", err)
	}
	var b TransferBundle
	if err := json.Unmarshal(plaintext, &b); err != nil {
		return nil, fmt.Errorf("decode sealed bundle: %w", err)
	}
	return &b, nil
}

// sealAEAD derives the per-handoff ChaCha20-Poly1305 key from the ECDH secret,
// binding it to both public keys (channel binding) so a key is unique per pairing.
func sealAEAD(shared, ephPub, staticPub []byte) (cipher.AEAD, error) {
	info := make([]byte, 0, len(sealKDFInfo)+len(ephPub)+len(staticPub))
	info = append(info, []byte(sealKDFInfo)...)
	info = append(info, ephPub...)
	info = append(info, staticPub...)
	r := hkdf.New(sha256.New, shared, []byte(sealKDFSalt), info)
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return chacha20poly1305.New(key)
}

func decodeX25519Pub(h string) (*ecdh.PublicKey, error) {
	raw, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if len(raw) != x25519KeyLen {
		return nil, fmt.Errorf("must be %d hex chars", x25519KeyLen*2)
	}
	return ecdh.X25519().NewPublicKey(raw)
}
