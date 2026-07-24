// Package tokens manages per-role API tokens for the SLATE dashboard.
// Tokens are stored in ~/.slate/tokens.json — one entry per token, each
// bound to a role. The server reads this file at startup and re-reads it
// on every request, so tokens can be added or revoked without restart.
package tokens

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/bigblue-r4/slate/internal/roles"
)

// Entry is one token record.
type Entry struct {
	Token   string `json:"token"`
	Role    string `json:"role"`
	Name    string `json:"name"`            // human-readable — appears in audit logs as the actor
	Badge   string `json:"badge,omitempty"` // officer badge/ID number — renders identity as a person, not hex
	AddedAt string `json:"added_at"`        // YYYY-MM-DD
}

// Store is a simple append-only token registry backed by a JSON file.
type Store struct {
	mu      sync.RWMutex
	path    string
	entries []Entry
}

// Open reads or creates the token store at path.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	return s, s.load()
}

// Lookup returns the entry for the given token value (constant-time scan is
// fine — token lists for a department node are tiny).
func (s *Store) Lookup(token string) (Entry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		if e.Token == token {
			return e, true
		}
	}
	return Entry{}, false
}

// Add generates a new random token bound to role/name (and optional badge),
// saves it, and returns the token string. The caller must print it; it cannot
// be recovered later.
func (s *Store) Add(role, name, badge string) (string, error) {
	if !roles.Valid(role) {
		return "", fmt.Errorf("unknown role %q — valid roles: chief, evidence_clerk, tech_admin, officer, auditor", role)
	}
	if name == "" {
		return "", fmt.Errorf("name is required")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, Entry{
		Token:   token,
		Role:    role,
		Name:    name,
		Badge:   badge,
		AddedAt: time.Now().UTC().Format("2006-01-02"),
	})
	return token, s.save()
}

// Revoke removes the token with the given value. Returns an error if not found.
func (s *Store) Revoke(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var kept []Entry
	found := false
	for _, e := range s.entries {
		if e.Token == token {
			found = true
			continue
		}
		kept = append(kept, e)
	}
	if !found {
		return fmt.Errorf("token not found")
	}
	s.entries = kept
	return s.save()
}

// List returns a copy of all entries (tokens are included — mask them before
// displaying to unprivileged users).
func (s *Store) List() []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Entry, len(s.entries))
	copy(out, s.entries)
	return out
}

// Len returns the number of registered tokens.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// Reload re-reads the file from disk (useful if edited manually while the
// server is running, but the server currently re-reads on each request so
// this is only needed for one-shot CLI uses).
func (s *Store) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var ts struct {
		Tokens []Entry `json:"tokens"`
	}
	if err := json.Unmarshal(data, &ts); err != nil {
		return err
	}
	s.entries = ts.Tokens
	return nil
}

// save must be called while the write lock is held.
func (s *Store) save() error {
	ts := struct {
		Tokens []Entry `json:"tokens"`
	}{Tokens: s.entries}
	data, err := json.MarshalIndent(ts, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0600)
}
