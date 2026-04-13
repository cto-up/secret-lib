package service

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/cto-up/secret-lib/pkg/crypto"
	"github.com/jackc/pgx/v5/pgtype"
)

func genTestKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func TestBuildCreateParams(t *testing.T) {
	ks, err := crypto.NewKeyStore(map[int]string{1: genTestKey(t)}, 1)
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{keyStore: ks}

	t.Run("encrypts value and sets key version", func(t *testing.T) {
		p, err := svc.buildCreateParams(Secret{
			Name:          "my-api-key",
			Value:         "sk_live_secret123",
			ConnectorType: "stripe",
			Description:   "Production Stripe key",
			TenantID:      "tenant1",
			CreatedBy:     "user1",
		})
		if err != nil {
			t.Fatal(err)
		}

		if p.Name != "my-api-key" {
			t.Errorf("Name: got %s", p.Name)
		}
		// EncryptedValue must not be the plaintext
		if p.EncryptedValue == "sk_live_secret123" {
			t.Error("EncryptedValue is still plaintext — encryption did not happen")
		}
		if p.EncryptedValue == "" {
			t.Error("EncryptedValue is empty")
		}
		if p.KeyVersion != 1 {
			t.Errorf("KeyVersion: got %d, want 1", p.KeyVersion)
		}
		if p.ConnectorType != "stripe" {
			t.Errorf("ConnectorType: got %s", p.ConnectorType)
		}
		if !p.Description.Valid || p.Description.String != "Production Stripe key" {
			t.Errorf("Description: got %+v", p.Description)
		}
		if !p.TenantID.Valid || p.TenantID.String != "tenant1" {
			t.Errorf("TenantID: got %+v", p.TenantID)
		}
		if !p.CreatedBy.Valid || p.CreatedBy.String != "user1" {
			t.Errorf("CreatedBy: got %+v", p.CreatedBy)
		}

		// Verify we can decrypt the value back
		plaintext, err := ks.Decrypt(p.EncryptedValue, int(p.KeyVersion))
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if string(plaintext) != "sk_live_secret123" {
			t.Errorf("decrypted value: got %q, want sk_live_secret123", plaintext)
		}
	})

	t.Run("empty value rejected", func(t *testing.T) {
		_, err := svc.buildCreateParams(Secret{
			Name:          "key",
			Value:         "",
			ConnectorType: "smtp",
		})
		if err == nil {
			t.Error("expected error for empty value")
		}
	})

	t.Run("optional fields not set when empty", func(t *testing.T) {
		p, err := svc.buildCreateParams(Secret{
			Name:          "key",
			Value:         "secret",
			ConnectorType: "smtp",
		})
		if err != nil {
			t.Fatal(err)
		}
		if p.Description != (pgtype.Text{}) {
			t.Errorf("Description should be zero value, got %+v", p.Description)
		}
		if p.TenantID != (pgtype.Text{}) {
			t.Errorf("TenantID should be zero value, got %+v", p.TenantID)
		}
		if p.CreatedBy != (pgtype.Text{}) {
			t.Errorf("CreatedBy should be zero value, got %+v", p.CreatedBy)
		}
	})
}

func TestNewServicePanicsWithoutKeyStore(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic when keyStore is nil")
		}
	}()
	NewService(nil, nil)
}
