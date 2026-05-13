// Package store implements the primary encrypted, append-only, hash-chained witness log.
package store

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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
	key      []byte
	seq      uint64
	prevHash string
	f        *os.File
}

// Open opens or creates the log at dir/witness.log.
// If existing entries are present it resumes the chain from the last entry.
func Open(dir string, key []byte) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, logFilename)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	s := &Store{path: path, key: key, f: f}

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
