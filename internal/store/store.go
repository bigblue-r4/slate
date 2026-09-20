// Package store implements the primary encrypted, append-only, hash-chained witness log.
package store

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bigblue-r4/slate/internal/encrypt"
)

// Entry is one log record.
type Entry struct {
	Seq       uint64          `json:"seq"`
	Timestamp time.Time       `json:"ts"`
	Level     string          `json:"level"` // INFO, WARN, ERROR, DRIFT, DEATH
	Event     string          `json:"event"`
	Source    string          `json:"source"`
	PrevHash  string          `json:"prev_hash"` // SHA-256 of previous entry plaintext
	Data      json.RawMessage `json:"data,omitempty"`
}

const logFilename = "witness.log"

// Store is an encrypted, append-only, hash-chained log.
type Store struct {
	mu       sync.Mutex
	path     string
	dir      string
	key      []byte
	seq      uint64
	prevHash string
	f        *os.File

	// signer is nil unless the store was opened via OpenSigned. When set, every
	// successful Append rewrites the signed head in log-head.json. See head.go.
	signer   ed25519.PrivateKey
	prevHead string
}

// Open opens or creates the log at dir/witness.log.
// If existing entries are present it resumes the chain from the last entry.
//
// A store opened this way writes no truncation anchor. That is the correct
// behaviour for read paths and for callers with no node key; use OpenSigned on
// a live node so the log is anchored. See head.go for what the anchor is worth.
func Open(dir string, key []byte) (*Store, error) {
	return openStore(dir, key, nil)
}

// OpenSigned opens the log and anchors it: every Append rewrites a signed
// log-head.json recording how many records the log holds and what the last one
// hashed to, so that removing records from the end becomes detectable.
//
// priv is the node's Ed25519 identity key — the same key used for signed
// discovery announcements and sealed transfers. No new key is introduced.
func OpenSigned(dir string, key []byte, priv ed25519.PrivateKey) (*Store, error) {
	return openStore(dir, key, priv)
}

func openStore(dir string, key []byte, priv ed25519.PrivateKey) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, logFilename)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	s := &Store{path: path, dir: dir, key: key, f: f, signer: priv}

	// Chain the next head to whatever head is already on disk, so a sequence of
	// heads cannot be silently replaced by one somebody else has not seen.
	if priv != nil {
		ph, err := hashHeadFile(dir)
		if err != nil {
			return nil, err
		}
		s.prevHead = ph
	}

	// Resume chain state from existing entries.
	if entries, err := ReadAll(dir, key); err == nil && len(entries) > 0 {
		last := entries[len(entries)-1]
		s.seq = last.Seq
		raw, _ := json.Marshal(last)
		sum := sha256.Sum256(raw)
		s.prevHash = hex.EncodeToString(sum[:])
	}
	return s, nil
}

// Append encrypts and writes a new chained entry to the log.
func (s *Store) Append(level, event, source string, data interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.seq++
	e := Entry{
		Seq:       s.seq,
		Timestamp: time.Now().UTC(),
		Level:     level,
		Event:     event,
		Source:    source,
		PrevHash:  s.prevHash,
	}
	if data != nil {
		b, err := json.Marshal(data)
		if err != nil {
			return err
		}
		e.Data = json.RawMessage(b)
	}

	plain, err := json.Marshal(e)
	if err != nil {
		return err
	}
	sealed, err := encrypt.Seal(plain, s.key)
	if err != nil {
		return err
	}

	// Wire format: [uint32 big-endian length][sealed bytes]
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(sealed)))
	if _, err := s.f.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := s.f.Write(sealed); err != nil {
		return err
	}

	// Advance chain hash.
	sum := sha256.Sum256(plain)
	s.prevHash = hex.EncodeToString(sum[:])

	// Re-anchor. Written after the record is on disk, so a crash between the two
	// leaves a head that is behind the log ("stale"), never one that claims
	// records the log does not contain. Stale is recoverable and honest;
	// over-claiming would look exactly like truncation.
	if s.signer != nil {
		if err := writeHead(s.dir, s.seq, s.prevHash, s.prevHead, s.signer); err != nil {
			return fmt.Errorf("record written but anchor failed to update: %w", err)
		}
		ph, err := hashHeadFile(s.dir)
		if err != nil {
			return err
		}
		s.prevHead = ph
	}
	return nil
}

// Snapshot flushes and returns the raw encrypted log bytes (for backup/broadcast).
func (s *Store) Snapshot() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.f.Sync()
	return os.ReadFile(s.path)
}

// Close flushes and closes the log.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.f.Sync()
	return s.f.Close()
}

// Path returns the log file path.
func (s *Store) Path() string { return s.path }

// ChainResult reports the outcome of a hash-chain integrity check.
type ChainResult struct {
	Entries int    `json:"entries"`  // number of records read before any break
	OK      bool   `json:"ok"`       // true if the whole chain verified
	BreakAt int    `json:"break_at"` // 1-based record index of the first break (0 if none)
	Seq     uint64 `json:"seq"`      // seq of the record at the break (0 if none)
	Reason  string `json:"reason"`   // human-readable cause of the break
	TipHash string `json:"tip_hash"` // SHA-256 of the last verified record's plaintext
}

// VerifyChain walks dir/witness.log record by record and checks tamper-evidence:
//   - every record decrypts under key (else: ciphertext altered or truncated),
//   - seq numbers are strictly 1,2,3,… (else: a record was inserted or removed),
//   - each record's prev_hash equals SHA-256 of the previous record's plaintext
//     (else: a record's contents were altered or a record was dropped).
//
// It reports the FIRST break found. A clean chain returns OK=true.
//
// Two things the chain alone cannot catch, both by construction:
//   - A key holder who rewrites the ENTIRE log. Signed export bundles cover that.
//   - TRUNCATION. Dropping the last N records leaves a shorter chain that still
//     verifies perfectly, because nothing inside the log records how long it is
//     meant to be. Use VerifyHead for that — see head.go.
func VerifyChain(dir string, key []byte) (ChainResult, error) {
	path := filepath.Join(dir, logFilename)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ChainResult{OK: true}, nil // empty log is trivially intact
		}
		return ChainResult{}, err
	}
	defer f.Close()

	var (
		count    int
		prevHash string
		wantSeq  uint64 = 1
	)
	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(f, lenBuf[:]); err != nil {
			break // clean EOF
		}
		length := binary.BigEndian.Uint32(lenBuf[:])
		if length == 0 || length > 64<<20 {
			return ChainResult{Entries: count, BreakAt: count + 1, Reason: "invalid record frame length"}, nil
		}
		sealed := make([]byte, length)
		if _, err := io.ReadFull(f, sealed); err != nil {
			return ChainResult{Entries: count, BreakAt: count + 1, Reason: "truncated record (incomplete ciphertext)"}, nil
		}
		plain, err := encrypt.Open(sealed, key)
		if err != nil {
			return ChainResult{Entries: count, BreakAt: count + 1, Reason: "record failed to decrypt (ciphertext altered or wrong key)"}, nil
		}
		var e Entry
		if err := json.Unmarshal(plain, &e); err != nil {
			return ChainResult{Entries: count, BreakAt: count + 1, Reason: "record is not valid JSON after decryption"}, nil
		}
		if e.Seq != wantSeq {
			return ChainResult{Entries: count, BreakAt: count + 1, Seq: e.Seq,
				Reason: fmt.Sprintf("sequence break: expected seq %d, got %d (record inserted or removed)", wantSeq, e.Seq)}, nil
		}
		if e.PrevHash != prevHash {
			return ChainResult{Entries: count, BreakAt: count + 1, Seq: e.Seq,
				Reason: "prev_hash mismatch (a prior record was altered or dropped)"}, nil
		}
		// Advance chain over the canonical plaintext of THIS record.
		canon, err := json.Marshal(e)
		if err != nil {
			return ChainResult{}, err
		}
		sum := sha256.Sum256(canon)
		prevHash = hex.EncodeToString(sum[:])
		wantSeq++
		count++
	}
	return ChainResult{Entries: count, OK: true, TipHash: prevHash}, nil
}

// ReadAll decrypts and returns all entries from dir/witness.log.
func ReadAll(dir string, key []byte) ([]Entry, error) {
	path := filepath.Join(dir, logFilename)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var entries []Entry
	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(f, lenBuf[:]); err != nil {
			break // EOF or incomplete record
		}
		length := binary.BigEndian.Uint32(lenBuf[:])
		if length == 0 || length > 64<<20 { // sanity: max 64 MiB per record
			break
		}
		sealed := make([]byte, length)
		if _, err := io.ReadFull(f, sealed); err != nil {
			break
		}
		plain, err := encrypt.Open(sealed, key)
		if err != nil {
			continue // skip corrupted record
		}
		var e Entry
		if err := json.Unmarshal(plain, &e); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	return entries, nil
}
