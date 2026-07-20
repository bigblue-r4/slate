package peer

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/bigblue-r4/slate/internal/evidence"
	"github.com/bigblue-r4/slate/internal/store"
)

// sealFixture returns a signed bundle plus the recipient's derived X25519 keypair.
func sealFixture(t *testing.T) (*TransferBundle, string) {
	t.Helper()
	// Sender identity signs the bundle.
	_, senderPrivHex, err := GenerateNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(NodeKeyEnv, senderPrivHex)
	senderPriv, _, err := LoadNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	item := evidence.Item{ID: "EV-SEAL-1", CaseNumber: "C-9", Description: "sealed evidence", Category: "narcotics", Status: "active"}
	events := []store.Entry{{Seq: 1, Event: "slate/intake"}}
	b, err := NewTransferBundle("node-A", "node-B", item, events, "encrypted handoff")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Sign(senderPriv); err != nil {
		t.Fatal(err)
	}

	// Recipient identity → derived X25519 key.
	_, recipPrivHex, _ := GenerateNodeKey()
	t.Setenv(NodeKeyEnv, recipPrivHex)
	recipEd, _, _ := LoadNodeKey()
	_, recipEncPub, err := DeriveEncKey(recipEd)
	if err != nil {
		t.Fatal(err)
	}
	return b, recipEncPub
}

func TestSealOpenRoundTrip(t *testing.T) {
	b, recipEncPub := sealFixture(t)
	sealed, err := SealTo(b, recipEncPub)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// The plaintext must not leak into the cleartext envelope metadata: the
	// description and node IDs live only inside the (encrypted) ciphertext.
	cleartext := sealed.Version + sealed.EphPub + sealed.Nonce
	for _, secret := range []string{"sealed evidence", "node-A", "EV-SEAL-1"} {
		if strings.Contains(cleartext, secret) {
			t.Fatalf("secret %q leaked into sealed envelope metadata", secret)
		}
	}

	// The recipient (same node key) can open it.
	recipEd := currentNodeEd(t) // recip key is still in the env from sealFixture
	recipPriv, _, err := DeriveEncKey(recipEd)
	if err != nil {
		t.Fatal(err)
	}
	got, err := sealed.Open(recipPriv)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got.Item.ID != "EV-SEAL-1" || got.Item.Description != "sealed evidence" {
		t.Fatalf("decrypted bundle mismatch: %+v", got.Item)
	}
	// The inner signature survives the round trip and still verifies.
	if got.Signature != b.Signature {
		t.Fatal("inner signature not preserved through sealing")
	}
}

func TestSealRefusesUnsignedBundle(t *testing.T) {
	_, recipEncPub := sealFixture(t)
	item := evidence.Item{ID: "EV-X"}
	b, _ := NewTransferBundle("node-A", "node-B", item, nil, "")
	if _, err := SealTo(b, recipEncPub); err == nil {
		t.Fatal("sealing an unsigned bundle must be refused")
	}
}

func TestOpenWithWrongKeyFails(t *testing.T) {
	b, recipEncPub := sealFixture(t)
	sealed, err := SealTo(b, recipEncPub)
	if err != nil {
		t.Fatal(err)
	}
	// A DIFFERENT node key cannot decrypt.
	_, strangerHex, _ := GenerateNodeKey()
	t.Setenv(NodeKeyEnv, strangerHex)
	strangerEd, _, _ := LoadNodeKey()
	strangerPriv, _, _ := DeriveEncKey(strangerEd)
	if _, err := sealed.Open(strangerPriv); err == nil {
		t.Fatal("sealed bundle opened with the wrong key")
	}
}

func TestOpenTamperedCiphertextFails(t *testing.T) {
	b, recipEncPub := sealFixture(t)
	sealed, err := SealTo(b, recipEncPub)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the ciphertext; AEAD must reject it.
	raw, _ := base64.StdEncoding.DecodeString(sealed.Ciphertext)
	raw[len(raw)/2] ^= 0xFF
	sealed.Ciphertext = base64.StdEncoding.EncodeToString(raw)

	recipEd := currentNodeEd(t)
	recipPriv, _, _ := DeriveEncKey(recipEd)
	if _, err := sealed.Open(recipPriv); err == nil {
		t.Fatal("tampered ciphertext passed AEAD verification")
	}
}

func TestDeriveEncKeyDeterministic(t *testing.T) {
	_, privHex, _ := GenerateNodeKey()
	t.Setenv(NodeKeyEnv, privHex)
	ed, _, _ := LoadNodeKey()
	_, pub1, err := DeriveEncKey(ed)
	if err != nil {
		t.Fatal(err)
	}
	_, pub2, _ := DeriveEncKey(ed)
	if pub1 != pub2 {
		t.Fatal("enc key derivation is not deterministic")
	}
	// A different identity yields a different enc key.
	_, otherHex, _ := GenerateNodeKey()
	t.Setenv(NodeKeyEnv, otherHex)
	otherEd, _, _ := LoadNodeKey()
	_, otherPub, _ := DeriveEncKey(otherEd)
	if otherPub == pub1 {
		t.Fatal("distinct identities produced the same enc key")
	}
}

func TestIdentityTokenRoundTrip(t *testing.T) {
	sig, enc := "aa", "bb"
	tok := IdentityToken(sig, enc)
	gotSig, gotEnc := SplitIdentityToken(tok)
	if gotSig != sig || gotEnc != enc {
		t.Fatalf("token round trip: %q/%q", gotSig, gotEnc)
	}
	// A bare signing key (legacy) parses with an empty enc key.
	s2, e2 := SplitIdentityToken("cc")
	if s2 != "cc" || e2 != "" {
		t.Fatalf("legacy token: %q/%q", s2, e2)
	}
}

// currentNodeEd loads the Ed25519 key currently in the env (set by sealFixture).
func currentNodeEd(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	ed, _, err := LoadNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	return ed
}
