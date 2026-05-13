// Package soul loads and verifies the Witness agent identity file (soul.toml).
//
// The soul file is immutable identity. It is loaded before anything else at
// witness init time. If the file's hash does not match soul_hash, the agent
// halts before creating a genesis or touching any log.
//
// The soul file is NEVER fetched from a network and NEVER overwritten by
// the installer. It is placed by human hand and locked on first init.
package soul

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

const DefaultSoulPath = "~/.slate/soul.toml"

// Soul is the parsed identity file.
type Soul struct {
	Identity   Identity   `toml:"identity"`
	PrimeLaw   PrimeLaw   `toml:"prime_law"`
	Boundaries Boundaries `toml:"boundaries"`
	Logging    Logging    `toml:"logging"`
	Escalation Escalation `toml:"escalation"`
	Integrity  Integrity  `toml:"integrity"`
	Forge      Forge      `toml:"forge"`
}

type Identity struct {
	AgentName     string `toml:"agent_name"`
	AgentVersion  string `toml:"agent_version"`
	Organization  string `toml:"organization"`
	ProductFamily string `toml:"product_family"`
	Role          string `toml:"role"`
	InstanceID    string `toml:"instance_id"`
	SoulLocked    bool   `toml:"soul_locked"`
}

type PrimeLaw struct {
	Text                string `toml:"text"`
	OverridePermitted   bool   `toml:"override_permitted"`
	EscalateOnViolation bool   `toml:"escalate_on_violation"`
}

type Boundaries struct {
	Permitted  map[string]bool `toml:"permitted"`
	Prohibited map[string]bool `toml:"prohibited"`
}

type Logging struct {
	Mode          string `toml:"mode"`
	LogDir        string `toml:"log_dir"`
	LogFormat     string `toml:"log_format"`
	HashAlgorithm string `toml:"hash_algorithm"`
	TamperEvident bool   `toml:"tamper_evident"`
}

type Escalation struct {
	Thresholds  EscalationThresholds `toml:"thresholds"`
	TickSources map[string]int       `toml:"tick_sources"`
	Actions     EscalationActions    `toml:"actions"`
}

type EscalationThresholds struct {
	WarnAt     int `toml:"warn_at"`
	EscalateAt int `toml:"escalate_at"`
	HaltAt     int `toml:"halt_at"`
}

type EscalationActions struct {
	OnWarn     string `toml:"on_warn"`
	OnEscalate string `toml:"on_escalate"`
	OnHalt     string `toml:"on_halt"`
}

type Integrity struct {
	SoulHash        string `toml:"soul_hash"`
	VerifyOnLoad    bool   `toml:"verify_on_load"`
	HaltOnMismatch  bool   `toml:"halt_on_mismatch"`
	MismatchMessage string `toml:"mismatch_message"`
}

type Forge struct {
	ForgedBy    string `toml:"forged_by"`
	ForgeMethod string `toml:"forge_method"`
	ForgeDate   string `toml:"forge_date"`
	ForgedFrom  string `toml:"forged_from"`
	Notes       string `toml:"notes"`
}

// Load reads and verifies the soul file at path.
// If verify_on_load is true and the hash doesn't match, returns an error
// and the caller must halt — do not proceed.
func Load(path string) (*Soul, error) {
	path = expandHome(path)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("soul file not found at %s — run installer first", path)
		}
		return nil, fmt.Errorf("read soul file: %w", err)
	}

	var s Soul
	if _, err := toml.Decode(string(data), &s); err != nil {
		return nil, fmt.Errorf("parse soul file: %w", err)
	}

	if s.Integrity.VerifyOnLoad {
		if err := verify(data, s.Integrity.SoulHash); err != nil {
			msg := s.Integrity.MismatchMessage
			if msg == "" {
				msg = "Soul file integrity check failed. Agent will not run."
			}
			return nil, errors.New(msg)
		}
	}

	return &s, nil
}

// Path returns the expanded default soul file path.
func Path() string {
	return expandHome(DefaultSoulPath)
}

// Exists reports whether a soul file is present.
func Exists() bool {
	_, err := os.Stat(expandHome(DefaultSoulPath))
	return err == nil
}

// InstallDefault copies the default soul file from src to the witness config dir.
// Called by `witness init` when no soul file is present.
// Never overwrites an existing soul file.
func InstallDefault(src string) error {
	dst := expandHome(DefaultSoulPath)
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("soul file already exists at %s — will not overwrite", dst)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read default soul: %w", err)
	}
	return os.WriteFile(dst, data, 0400) // read-only; soul is immutable
}

// Hash returns the SHA-256 hash of the soul file at path (for checksums).
func Hash(path string) (string, error) {
	data, err := os.ReadFile(expandHome(path))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// verify checks the soul file's integrity hash.
// It blanks the soul_hash field before hashing so the stored value is stable —
// otherwise the hash would change every time soul_hash is written.
func verify(data []byte, expected string) error {
	if expected == "" {
		// Not yet stamped — allow on first init.
		return nil
	}
	sum := sha256.Sum256(zeroSoulHash(data))
	actual := hex.EncodeToString(sum[:])
	if actual != expected {
		return fmt.Errorf("soul hash mismatch: expected %s got %s", expected, actual)
	}
	return nil
}

// zeroSoulHash returns a copy of the raw TOML bytes with the soul_hash value
// replaced by an empty string, so the file can be hashed without a circular
// dependency on the field that stores the hash.
func zeroSoulHash(data []byte) []byte {
	lines := bytes.SplitAfter(data, []byte("\n"))
	for i, line := range lines {
		if !bytes.HasPrefix(bytes.TrimSpace(line), []byte("soul_hash")) {
			continue
		}
		first := bytes.IndexByte(line, '"')
		if first < 0 {
			continue
		}
		second := bytes.IndexByte(line[first+1:], '"')
		if second < 0 {
			continue
		}
		second += first + 1
		cleared := make([]byte, 0, len(line))
		cleared = append(cleared, line[:first+1]...)  // up to and including opening "
		cleared = append(cleared, '"')                // immediate closing "
		cleared = append(cleared, line[second+1:]...) // rest of line (comment etc.)
		lines[i] = cleared
	}
	return bytes.Join(lines, nil)
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, path[2:])
	}
	return path
}
