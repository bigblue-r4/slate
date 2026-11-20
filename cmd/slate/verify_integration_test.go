package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/bigblue-r4/slate/internal/store"
)

// The child executes the real CLI path, including os.Exit and JSON envelopes.
func TestVerifyCommandHelper(t *testing.T) {
	if os.Getenv("SLATE_VERIFY_TEST_HELPER") != "1" {
		return
	}
	os.Args = []string{"slate", "verify"}
	if os.Getenv("SLATE_VERIFY_JSON") == "1" {
		os.Args = append(os.Args, "--json")
	}
	runVerify()
	os.Exit(0)
}

func TestVerifyExitStatusAndJSONAgree(t *testing.T) {
	for _, name := range []string{"valid", "missing", "malformed", "bad-signature", "stale", "tip-mismatch", "truncated", "broken-chain", "unreadable-head"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := saveConfig(dir, Config{NodeID: "synthetic-node"}); err != nil {
				t.Fatal(err)
			}
			primary := filepath.Join(dir, "primary")
			_, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			log, err := store.OpenSigned(primary, mustDeriveKey(), priv)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 3; i++ {
				if err := log.Append("INFO", "test", "fixture", map[string]int{"index": i}); err != nil {
					t.Fatal(err)
				}
			}
			if err := log.Close(); err != nil {
				t.Fatal(err)
			}
			head, err := store.ReadHead(primary)
			if err != nil {
				t.Fatal(err)
			}
			headPath := store.HeadPath(primary)
			saveHead := func() {
				t.Helper()
				b, e := json.Marshal(head)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(headPath, b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			switch name {
			case "missing":
				if err := os.Remove(headPath); err != nil {
					t.Fatal(err)
				}
			case "malformed":
				if err := os.WriteFile(headPath, []byte("{invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			case "bad-signature":
				head.Signature = "00"
				saveHead()
			case "stale":
				head.Seq--
				if err := head.Sign(priv); err != nil {
					t.Fatal(err)
				}
				saveHead()
			case "tip-mismatch":
				head.TipHash = "00"
				if err := head.Sign(priv); err != nil {
					t.Fatal(err)
				}
				saveHead()
			case "truncated", "broken-chain":
				path := filepath.Join(primary, "witness.log")
				data, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				if name == "truncated" {
					data = data[:4+int(binary.BigEndian.Uint32(data[:4]))]
				} else {
					data[len(data)-1] ^= 1
				}
				if e = os.WriteFile(path, data, 0600); e != nil {
					t.Fatal(e)
				}
			case "unreadable-head":
				if err := os.Remove(headPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(headPath, 0700); err != nil {
					t.Fatal(err)
				}
			}
			valid := name == "valid" || name == "missing"
			for _, machine := range []bool{false, true} {
				cmd := exec.Command(os.Args[0], "-test.run=^TestVerifyCommandHelper$")
				cmd.Env = []string{"SLATE_VERIFY_TEST_HELPER=1", "SLATE_DIR=" + dir, "HOME=" + dir, "PATH=/usr/bin:/bin"}
				if machine {
					cmd.Env = append(cmd.Env, "SLATE_VERIFY_JSON=1")
				}
				output, err := cmd.CombinedOutput()
				code := 0
				if err != nil {
					if e, ok := err.(*exec.ExitError); ok {
						code = e.ExitCode()
					} else {
						t.Fatal(err)
					}
				}
				expected := 0
				if !valid {
					expected = 1
				}
				if code != expected {
					t.Fatalf("json=%t exit=%d want=%d: %s", machine, code, expected, output)
				}
				if machine {
					var response struct {
						OK   bool `json:"ok"`
						Data struct {
							Head struct {
								Present bool `json:"present"`
							} `json:"head"`
						} `json:"data"`
					}
					if err := json.Unmarshal(output, &response); err != nil {
						t.Fatalf("invalid JSON: %s: %v", output, err)
					}
					if response.OK != valid {
						t.Fatalf("envelope ok=%t want=%t: %s", response.OK, valid, output)
					}
					if name == "malformed" && !response.Data.Head.Present {
						t.Fatal("malformed existing anchor reported as missing")
					}
				}
			}
		})
	}
}
