package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func genTestKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	k1 := genTestKey(t)
	ks, err := NewKeyStore(map[int]string{1: k1}, 1)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := "sk_live_super_secret_stripe_key"
	ct, err := ks.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}

	// Ciphertext must differ from plaintext
	if ct == plaintext {
		t.Fatal("ciphertext equals plaintext — encryption did not happen")
	}

	got, err := ks.Decrypt(ct, 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != plaintext {
		t.Errorf("got %q, want %q", got, plaintext)
	}
}

func TestEncryptProducesUniqueCiphertexts(t *testing.T) {
	ks, err := NewKeyStore(map[int]string{1: genTestKey(t)}, 1)
	if err != nil {
		t.Fatal(err)
	}

	ct1, _ := ks.Encrypt([]byte("same"))
	ct2, _ := ks.Encrypt([]byte("same"))
	if ct1 == ct2 {
		t.Error("two encryptions of same plaintext produced identical ciphertext (nonce reuse)")
	}
}

func TestDecryptWrongKeyVersionFails(t *testing.T) {
	ks, err := NewKeyStore(map[int]string{
		1: genTestKey(t),
		2: genTestKey(t),
	}, 2)
	if err != nil {
		t.Fatal(err)
	}

	ct, _ := ks.Encrypt([]byte("secret"))

	// Decrypt with wrong key version should fail
	_, err = ks.Decrypt(ct, 1)
	if err == nil {
		t.Error("expected error decrypting with wrong key version")
	}
}

func TestDecryptTamperedCiphertextFails(t *testing.T) {
	ks, err := NewKeyStore(map[int]string{1: genTestKey(t)}, 1)
	if err != nil {
		t.Fatal(err)
	}

	ct, _ := ks.Encrypt([]byte("secret"))

	// Tamper with the ciphertext
	raw, _ := base64.StdEncoding.DecodeString(ct)
	raw[len(raw)-1] ^= 0xFF
	tampered := base64.StdEncoding.EncodeToString(raw)

	_, err = ks.Decrypt(tampered, 1)
	if err == nil {
		t.Error("expected error decrypting tampered ciphertext")
	}
}

func TestKeyRotation(t *testing.T) {
	k1 := genTestKey(t)
	k2 := genTestKey(t)

	// Start with key version 1
	ks1, _ := NewKeyStore(map[int]string{1: k1}, 1)
	ct, _ := ks1.Encrypt([]byte("old-secret"))

	// Rotate to key version 2, but keep key 1 for decryption
	ks2, _ := NewKeyStore(map[int]string{1: k1, 2: k2}, 2)

	// Can still decrypt old ciphertext with key version 1
	got, err := ks2.Decrypt(ct, 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old-secret" {
		t.Errorf("got %q", got)
	}

	// New encryptions use key version 2
	if ks2.CurrentVersion() != 2 {
		t.Errorf("current version: got %d, want 2", ks2.CurrentVersion())
	}
}

func TestNewKeyStoreValidation(t *testing.T) {
	t.Run("empty keys rejected", func(t *testing.T) {
		_, err := NewKeyStore(map[int]string{}, 1)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("missing current version rejected", func(t *testing.T) {
		_, err := NewKeyStore(map[int]string{1: genTestKey(t)}, 2)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("wrong key length rejected", func(t *testing.T) {
		short := base64.StdEncoding.EncodeToString([]byte("too-short"))
		_, err := NewKeyStore(map[int]string{1: short}, 1)
		if err == nil {
			t.Error("expected error for short key")
		}
	})

	t.Run("invalid base64 rejected", func(t *testing.T) {
		_, err := NewKeyStore(map[int]string{1: "not-valid-base64!!!"}, 1)
		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})
}
