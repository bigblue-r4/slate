package store

import (
	"os"
	"path/filepath"
	"testing"
)

func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func seedLog(t *testing.T, n int) (string, []byte) {
	t.Helper()
	dir := t.TempDir()
	key := testKey()
	s, err := Open(dir, key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := 0; i < n; i++ {
		if err := s.Append("INFO", "test/event", "test", map[string]int{"i": i}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return dir, key
}

func TestVerifyChainClean(t *testing.T) {
	dir, key := seedLog(t, 5)
	res, err := VerifyChain(dir, key)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK || res.Entries != 5 {
		t.Fatalf("expected clean chain of 5, got %+v", res)
	}
}

func TestVerifyEmptyLog(t *testing.T) {
	res, err := VerifyChain(t.TempDir(), testKey())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("empty log should be intact, got %+v", res)
	}
}

func TestVerifyChainDetectsTamper(t *testing.T) {
	dir, key := seedLog(t, 5)
	path := filepath.Join(dir, logFilename)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte inside the last record's ciphertext.
	raw[len(raw)-3] ^= 0xFF
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyChain(dir, key)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.OK {
		t.Fatalf("tampered chain reported OK: %+v", res)
	}
	if res.BreakAt != 5 {
		t.Fatalf("expected break at record 5, got %+v", res)
	}
}

func TestVerifyChainDetectsTruncation(t *testing.T) {
	dir, key := seedLog(t, 4)
	path := filepath.Join(dir, logFilename)
	raw, _ := os.ReadFile(path)
	// Drop the final byte: the last record becomes truncated.
	if err := os.WriteFile(path, raw[:len(raw)-1], 0600); err != nil {
		t.Fatal(err)
	}
	res, _ := VerifyChain(dir, key)
	if res.OK {
		t.Fatalf("truncated chain reported OK: %+v", res)
	}
}

func TestReadAllRoundTrip(t *testing.T) {
	dir, key := seedLog(t, 3)
	entries, err := ReadAll(dir, key)
	if err != nil {
		t.Fatalf("readall: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	for i, e := range entries {
		if e.Seq != uint64(i+1) {
			t.Fatalf("entry %d has seq %d", i, e.Seq)
		}
	}
	if entries[0].PrevHash != "" {
		t.Fatalf("genesis prev_hash should be empty")
	}
}
