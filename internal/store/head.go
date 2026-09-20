package store

// The truncation anchor.
//
// The hash chain in store.go catches any *edit*: change a record and its
// successor's prev_hash stops matching. What it cannot catch is a *truncation*.
// Delete the last N records and what remains is a shorter, perfectly valid
// chain — every prev_hash still lines up, every seq still counts from 1. For a
// chain-of-custody log the obvious insider attack is removing the most recent
// entries, and until now it left no trace at all.
//
// A head fixes that by recording, outside the log, how long the log is supposed
// to be and what its last record hashed to. Truncate the log and the head no
// longer describes it.
//
// WHAT THIS DOES NOT DO. The node signs its own head with a key held on the
// same machine as the log, so an attacker with root on the node can truncate
// the log AND rewrite the head to match. This is not tamper-proofing. What it
// gives you is detection by an observer who has seen an earlier head: heads are
// chained through PrevHead, so a replacement head cannot be slotted into a
// sequence somebody else already holds a copy of. That makes the existing peer
// and export paths meaningful as witnesses rather than just transports.
//
// Inclusion proofs — proving one item's custody history without disclosing the
// rest of the log — need a Merkle tree and are deliberately not attempted here.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const headFilename = "log-head.json"

// Head is the signed statement "this log is N records long and ends here".
type Head struct {
	Seq       uint64 `json:"seq"`        // number of records the log should contain
	TipHash   string `json:"tip_hash"`   // SHA-256 of the last record's plaintext
	PrevHead  string `json:"prev_head"`  // SHA-256 of the previous head file's bytes; "" for the first
	Timestamp string `json:"ts"`         // RFC3339 UTC, when this head was written
	Signature string `json:"sig"`        // Ed25519 hex over every other field
	SignerKey string `json:"signer_key"` // Ed25519 public key, hex
}

// payload returns the canonical bytes covered by the signature: every field
// except Signature itself. SignerKey is inside the payload on purpose — a
// signature that did not cover it could be replayed under a substituted key.
func (h *Head) payload() ([]byte, error) {
	c := *h
	c.Signature = ""
	return json.Marshal(&c)
}

// Sign stamps SignerKey and signs the head in place.
func (h *Head) Sign(priv ed25519.PrivateKey) error {
	h.SignerKey = hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	payload, err := h.payload()
	if err != nil {
		return err
	}
	h.Signature = hex.EncodeToString(ed25519.Sign(priv, payload))
	return nil
}

// Verify checks the head's self-signature against its own advertised SignerKey.
// Success proves the head is intact and was written by the holder of that key.
// It does NOT establish that the key is one you should trust — compare
// SignerKey against the node identity you expect.
func (h *Head) Verify() error {
	if h.Signature == "" {
		return fmt.Errorf("head is not signed")
	}
	pub, err := hex.DecodeString(h.SignerKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("head signer_key is not a usable Ed25519 public key")
	}
	sig, err := hex.DecodeString(h.Signature)
	if err != nil {
		return fmt.Errorf("head signature is not valid hex")
	}
	payload, err := h.payload()
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return fmt.Errorf("head signature does not verify against signer_key")
	}
	return nil
}

// HeadPath returns the head file path for a store directory.
func HeadPath(dir string) string { return filepath.Join(dir, headFilename) }

// ReadHead loads the head for dir. A missing head is not an error: it returns
// (nil, nil), because logs written before anchoring existed have none and must
// keep verifying.
func ReadHead(dir string) (*Head, error) {
	b, err := os.ReadFile(HeadPath(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var h Head
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, fmt.Errorf("head is not valid JSON: %w", err)
	}
	return &h, nil
}

// hashHeadFile returns the SHA-256 of the head file's bytes as it sits on disk,
// which is what the next head chains to. Hashing the raw bytes rather than a
// re-marshalled struct means the link breaks if the file is edited at all,
// including in ways that round-trip through the struct.
func hashHeadFile(dir string) (string, error) {
	b, err := os.ReadFile(HeadPath(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// writeHead writes a signed head describing seq/tipHash, chained to whatever
// head is currently on disk. Written to a temp file and renamed, so a crash
// mid-write leaves the previous head intact rather than a torn one.
func writeHead(dir string, seq uint64, tipHash, prevHead string, priv ed25519.PrivateKey) error {
	h := Head{
		Seq:       seq,
		TipHash:   tipHash,
		PrevHead:  prevHead,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	if err := h.Sign(priv); err != nil {
		return err
	}
	b, err := json.Marshal(&h)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".log-head-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0600); err != nil {
		return err
	}
	return os.Rename(tmpName, HeadPath(dir))
}

// HeadResult reports whether the log matches its anchor.
type HeadResult struct {
	Present  bool   `json:"present"`   // a head file exists
	OK       bool   `json:"ok"`        // head is signed, valid, and matches the log
	Signed   bool   `json:"signed"`    // signature verified against signer_key
	HeadSeq  uint64 `json:"head_seq"`  // record count the head claims
	LogSeq   uint64 `json:"log_seq"`   // record count actually found
	Signer   string `json:"signer"`    // signer_key from the head, hex
	Reason   string `json:"reason"`    // human-readable cause when OK is false
	Truncate bool   `json:"truncated"` // the log is SHORTER than the head claims
}

// VerifyHead checks dir's log against its anchor. It walks the chain first, so
// a caller gets one answer covering both properties.
//
// A log with no head returns Present=false, OK=false and a Reason saying so —
// callers must treat that as "not anchored", NOT as tampering. Logs created
// before anchoring existed legitimately have no head.
func VerifyHead(dir string, key []byte) (HeadResult, error) {
	chain, err := VerifyChain(dir, key)
	if err != nil {
		return HeadResult{}, err
	}

	h, err := ReadHead(dir)
	if err != nil {
		return HeadResult{Reason: err.Error()}, nil
	}
	if h == nil {
		return HeadResult{
			Present: false,
			LogSeq:  uint64(chain.Entries),
			Reason:  "log is not anchored (no log-head.json) — truncation of the tail cannot be detected",
		}, nil
	}

	res := HeadResult{
		Present: true,
		HeadSeq: h.Seq,
		LogSeq:  uint64(chain.Entries),
		Signer:  h.SignerKey,
	}

	if err := h.Verify(); err != nil {
		res.Reason = err.Error()
		return res, nil
	}
	res.Signed = true

	// The chain must be intact before the anchor means anything: comparing a
	// tip hash against a log with a break in the middle would report the wrong
	// problem.
	if !chain.OK {
		res.Reason = fmt.Sprintf("chain is broken before the anchor can be checked: %s", chain.Reason)
		return res, nil
	}

	switch {
	case res.LogSeq < h.Seq:
		res.Truncate = true
		res.Reason = fmt.Sprintf("the head is signed for %d records, the log holds %d — %d record(s) were removed from the end",
			h.Seq, res.LogSeq, h.Seq-res.LogSeq)
		return res, nil
	case res.LogSeq > h.Seq:
		res.Reason = fmt.Sprintf("head is stale: signed for %d records, the log holds %d (records appended without updating the anchor)",
			h.Seq, res.LogSeq)
		return res, nil
	}

	if chain.TipHash != h.TipHash {
		res.Reason = "tip_hash mismatch: the log's last record is not the one the head was signed for"
		return res, nil
	}

	res.OK = true
	return res, nil
}
