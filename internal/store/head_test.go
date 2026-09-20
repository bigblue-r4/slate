package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func testSigner(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv
}

// seedSignedLog builds an anchored log of n records and returns its dir and key.
func seedSignedLog(t *testing.T, n int) (string, []byte, ed25519.PrivateKey) {
	t.Helper()
	dir := t.TempDir()
	key := testKey()
	priv := testSigner(t)
	s, err := OpenSigned(dir, key, priv)
	if err != nil {
		t.Fatalf("open signed: %v", err)
	}
	for i := 0; i < n; i++ {
		if err := s.Append("INFO", "test/event", "test", map[string]int{"i": i}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return dir, key, priv
}

// truncateRecords removes the last n records by rewinding the file to the byte
// offset the chain reached after (total-n) records — the realistic shape of the
// attack, a clean cut on a record boundary rather than a torn frame.
func truncateRecords(t *testing.T, dir string, keep int) {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, logFilename))
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	var offset int64
	for i := 0; i < keep; i++ {
		var lenBuf [4]byte
		if _, err := io.ReadFull(f, lenBuf[:]); err != nil {
			t.Fatalf("read frame %d: %v", i, err)
		}
		length := int64(uint32(lenBuf[0])<<24 | uint32(lenBuf[1])<<16 | uint32(lenBuf[2])<<8 | uint32(lenBuf[3]))
		if _, err := f.Seek(length, io.SeekCurrent); err != nil {
			t.Fatalf("seek: %v", err)
		}
		offset += 4 + length
	}
	f.Close()
	if err := os.Truncate(filepath.Join(dir, logFilename), offset); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

func TestHeadWrittenAndVerifies(t *testing.T) {
	dir, key, priv := seedSignedLog(t, 5)

	h, err := ReadHead(dir)
	if err != nil {
		t.Fatalf("read head: %v", err)
	}
	if h == nil {
		t.Fatal("no head written by OpenSigned")
	}
	if h.Seq != 5 {
		t.Errorf("head seq = %d, want 5", h.Seq)
	}
	if err := h.Verify(); err != nil {
		t.Errorf("head signature: %v", err)
	}
	wantSigner := ed25519.PublicKey(priv.Public().(ed25519.PublicKey))
	if got := h.SignerKey; len(got) != len(wantSigner)*2 {
		t.Errorf("signer_key looks wrong: %q", got)
	}

	res, err := VerifyHead(dir, key)
	if err != nil {
		t.Fatalf("verify head: %v", err)
	}
	if !res.OK || !res.Present || !res.Signed {
		t.Errorf("clean anchored log did not verify: %+v", res)
	}
}

// The regression this whole feature exists for: after cutting records off the
// end, the hash chain still reports a clean log and only the anchor notices.
func TestTruncationInvisibleToChainButCaughtByHead(t *testing.T) {
	dir, key, _ := seedSignedLog(t, 6)

	truncateRecords(t, dir, 4) // drop the last 2

	chain, err := VerifyChain(dir, key)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if !chain.OK {
		t.Fatalf("expected the truncated chain to still verify clean (that is the gap being closed); got %+v", chain)
	}
	if chain.Entries != 4 {
		t.Fatalf("expected 4 surviving records, got %d", chain.Entries)
	}

	res, err := VerifyHead(dir, key)
	if err != nil {
		t.Fatalf("verify head: %v", err)
	}
	if res.OK {
		t.Fatal("anchor accepted a truncated log")
	}
	if !res.Truncate {
		t.Errorf("truncation not identified as such: %+v", res)
	}
	if res.HeadSeq != 6 || res.LogSeq != 4 {
		t.Errorf("head_seq/log_seq = %d/%d, want 6/4", res.HeadSeq, res.LogSeq)
	}
}

// Logs written before anchoring existed have no head. That must read as "not
// anchored", never as tampering — otherwise every deployed v1.4.0 log starts
// failing verification on upgrade.
func TestUnanchoredLogIsNotAFailure(t *testing.T) {
	dir, key := seedLog(t, 3)

	res, err := VerifyHead(dir, key)
	if err != nil {
		t.Fatalf("verify head: %v", err)
	}
	if res.Present {
		t.Fatal("unsigned Open should not write a head")
	}
	if res.Truncate {
		t.Error("a log with no anchor must not be reported as truncated")
	}
	if res.LogSeq != 3 {
		t.Errorf("log_seq = %d, want 3", res.LogSeq)
	}
	if res.Reason == "" {
		t.Error("expected a reason explaining the log is not anchored")
	}
}

func TestTamperedHeadRejected(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Head)
	}{
		{"tip_hash swapped", func(h *Head) { h.TipHash = "00" }},
		{"seq inflated", func(h *Head) { h.Seq = 99 }},
		{"signature corrupted", func(h *Head) { h.Signature = "aa" + h.Signature[2:] }},
		{"prev_head rewritten", func(h *Head) { h.PrevHead = "ff" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, key, _ := seedSignedLog(t, 3)
			h, err := ReadHead(dir)
			if err != nil || h == nil {
				t.Fatalf("read head: %v", err)
			}
			tc.mutate(h)
			b, err := json.Marshal(h)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if err := os.WriteFile(HeadPath(dir), b, 0600); err != nil {
				t.Fatalf("write head: %v", err)
			}

			res, err := VerifyHead(dir, key)
			if err != nil {
				t.Fatalf("verify head: %v", err)
			}
			if res.OK {
				t.Errorf("tampered head (%s) verified as OK: %+v", tc.name, res)
			}
		})
	}
}

// Heads chain through PrevHead, so a head cannot be slotted into a sequence an
// observer already holds a copy of.
func TestHeadsChainToPredecessor(t *testing.T) {
	dir := t.TempDir()
	key := testKey()
	priv := testSigner(t)

	s, err := OpenSigned(dir, key, priv)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Append("INFO", "first", "test", nil); err != nil {
		t.Fatalf("append: %v", err)
	}
	first, err := ReadHead(dir)
	if err != nil || first == nil {
		t.Fatalf("read first head: %v", err)
	}
	if first.PrevHead != "" {
		t.Errorf("first head should have an empty prev_head, got %q", first.PrevHead)
	}
	firstFileHash, err := hashHeadFile(dir)
	if err != nil {
		t.Fatalf("hash head: %v", err)
	}

	if err := s.Append("INFO", "second", "test", nil); err != nil {
		t.Fatalf("append: %v", err)
	}
	second, err := ReadHead(dir)
	if err != nil || second == nil {
		t.Fatalf("read second head: %v", err)
	}
	if second.PrevHead != firstFileHash {
		t.Errorf("second head prev_head = %q, want the first head's file hash %q", second.PrevHead, firstFileHash)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// Reopening an anchored log must keep the chain of heads going rather than
// restarting it, or the link across a restart is lost.
func TestHeadChainSurvivesReopen(t *testing.T) {
	dir, key, priv := seedSignedLog(t, 2)
	before, err := hashHeadFile(dir)
	if err != nil {
		t.Fatalf("hash head: %v", err)
	}

	s, err := OpenSigned(dir, key, priv)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := s.Append("INFO", "after-restart", "test", nil); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	h, err := ReadHead(dir)
	if err != nil || h == nil {
		t.Fatalf("read head: %v", err)
	}
	if h.PrevHead != before {
		t.Errorf("prev_head after reopen = %q, want %q", h.PrevHead, before)
	}
	if h.Seq != 3 {
		t.Errorf("seq = %d, want 3", h.Seq)
	}

	res, err := VerifyHead(dir, key)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK {
		t.Errorf("reopened log did not verify: %+v", res)
	}
}
