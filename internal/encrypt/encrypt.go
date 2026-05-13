// Package encrypt provides AES-256-GCM encryption with machine-bound key derivation.
package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	keyLen    = 32 // AES-256
	infoLabel = "witness-aes256-gcm-v1"
	kdfSalt   = "w1tn3ss-kdf-s4lt-2026"
)

// DeriveKey derives a 256-bit AES key from the machine ID using HKDF-SHA256.
// The key is stable across invocations for the same machine.
func DeriveKey(machineID string) ([]byte, error) {
	r := hkdf.New(sha256.New, []byte(machineID), []byte(kdfSalt), []byte(infoLabel))
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// Seal encrypts plaintext using AES-256-GCM.
// Output format: nonce || ciphertext+tag (nonce is random, prepended).
func Seal(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Open decrypts AES-256-GCM ciphertext (nonce || ciphertext+tag).
func Open(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
}
