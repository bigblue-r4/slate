// Package machid provides a stable, unique machine identifier.
package machid

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"strings"
)

// Get returns a stable unique identifier for this machine.
// Priority: /etc/machine-id (Linux) → IOPlatformUUID (macOS) → hostname hash.
func Get() string {
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		if id := strings.TrimSpace(string(data)); id != "" {
			return id
		}
	}
	if out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "IOPlatformUUID") {
				parts := strings.Split(line, "\"")
				if len(parts) >= 4 {
					return parts[3]
				}
			}
		}
	}
	hostname, _ := os.Hostname()
	sum := sha256.Sum256([]byte("witness-fallback:" + hostname))
	return hex.EncodeToString(sum[:])
}
