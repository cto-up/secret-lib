package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// KeyStore holds versioned encryption keys. The current key version is used
// for new encryptions; older versions are retained for decryption during
// key rotation.
type KeyStore struct {
	keys           map[int][]byte // version → 32-byte AES-256 key
	currentVersion int
}

// NewKeyStore creates a KeyStore from a map of version → base64-encoded
// 32-byte keys. The currentVersion is used for all new encryptions.
func NewKeyStore(keys map[int]string, currentVersion int) (*KeyStore, error) {
	if len(keys) == 0 {
		return nil, errors.New("crypto: at least one encryption key is required")
	}
	if _, ok := keys[currentVersion]; !ok {
		return nil, fmt.Errorf("crypto: current version %d not found in keys", currentVersion)
	}

	decoded := make(map[int][]byte, len(keys))
	for v, b64 := range keys {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("crypto: key version %d: invalid base64: %w", v, err)
		}
		if len(raw) != 32 {
			return nil, fmt.Errorf("crypto: key version %d: expected 32 bytes, got %d", v, len(raw))
		}
		decoded[v] = raw
	}

	return &KeyStore{keys: decoded, currentVersion: currentVersion}, nil
}

// CurrentVersion returns the key version used for new encryptions.
func (ks *KeyStore) CurrentVersion() int {
	return ks.currentVersion
}

// Encrypt encrypts plaintext using AES-256-GCM with the current key version.
// Returns base64-encoded ciphertext (nonce prepended to ciphertext).
func (ks *KeyStore) Encrypt(plaintext []byte) (string, error) {
	key := ks.keys[ks.currentVersion]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("crypto: new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("crypto: new GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("crypto: generate nonce: %w", err)
	}

	// nonce is prepended to ciphertext so we can extract it on decrypt
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt decrypts base64-encoded ciphertext using the key at the given version.
// The nonce is expected to be prepended to the ciphertext.
func (ks *KeyStore) Decrypt(ciphertext string, keyVersion int) ([]byte, error) {
	key, ok := ks.keys[keyVersion]
	if !ok {
		return nil, fmt.Errorf("crypto: key version %d not found", keyVersion)
	}

	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("crypto: invalid base64 ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return nil, errors.New("crypto: ciphertext too short")
	}

	nonce, ct := raw[:nonceSize], raw[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt failed (tampered or wrong key): %w", err)
	}

	return plaintext, nil
}
