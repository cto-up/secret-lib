package service

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/cto-up/secret-lib/pkg/crypto"
	"github.com/cto-up/secret-lib/pkg/db"
	"github.com/cto-up/secret-lib/pkg/db/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// DefaultGeneratedSecretBytes is the default randomness for GenerateSecret.
// 32 bytes (→ 64 hex chars) is comfortably above the 256-bit threshold for
// HMAC-SHA256 keys and gives plenty of margin for future schemes.
const DefaultGeneratedSecretBytes = 32

// MaxGeneratedSecretBytes is the cap accepted by GenerateSecret. Beyond this
// the secret is almost certainly being used as a payload, not a key.
const MaxGeneratedSecretBytes = 128

// MinGeneratedSecretBytes is the floor. 16 bytes is the smallest size where
// brute-force is computationally infeasible for current/near-future attackers.
const MinGeneratedSecretBytes = 16

// Secret is the caller-facing type for storing a connector secret.
// Callers pass the plaintext Value — the service encrypts it internally.
type Secret struct {
	// Name is a human-readable identifier for this secret, unique per tenant.
	Name string

	// Value is the plaintext secret. The service encrypts it using AES-256-GCM
	// before persisting. Never logged or returned via the admin API.
	Value string

	// ConnectorType identifies the connector this secret belongs to,
	// e.g. "smtp", "slack", "stripe", "aws".
	ConnectorType string

	// Description is an optional human-readable note about the secret.
	Description string

	// TenantID scopes the secret to a tenant (optional).
	TenantID string

	// CreatedBy is the user ID that created this secret (optional).
	CreatedBy string
}

// Service provides secure secret storage with AES-256-GCM encryption at rest.
// The encryption key is managed via crypto.KeyStore — callers pass plaintext,
// and the service handles all cryptographic operations.
type Service struct {
	store    *db.Store
	keyStore *crypto.KeyStore
}

// NewService creates a Service. The KeyStore must contain at least the current
// encryption key version. Panics if keyStore is nil — failing open is not acceptable
// for a secret management service.
func NewService(store *db.Store, keyStore *crypto.KeyStore) *Service {
	if keyStore == nil {
		panic("secret.NewService: keyStore must not be nil")
	}
	return &Service{store: store, keyStore: keyStore}
}

// StoreSecret encrypts the plaintext value and persists it.
func (s *Service) StoreSecret(ctx context.Context, sec Secret) error {
	_, err := s.CreateSecret(ctx, sec)
	return err
}

// CreateSecret encrypts + persists a new secret and returns the
// stored row so HTTP handlers can build a response DTO without
// re-querying. Keeps the encrypt-then-insert dance inside this
// package (the store API takes pre-encrypted bytes; the handler
// must not touch plaintext beyond passing it here).
func (s *Service) CreateSecret(ctx context.Context, sec Secret) (repository.SecrSecret, error) {
	params, err := s.buildCreateParams(sec)
	if err != nil {
		return repository.SecrSecret{}, err
	}
	row, err := s.store.CreateSecret(ctx, params)
	if err != nil {
		return repository.SecrSecret{}, fmt.Errorf("secret.CreateSecret: %w", err)
	}
	return row, nil
}

// GenerateSecret mints a strong random value (hex-encoded) and stores it as
// a new Secret, returning both the persisted row and the plaintext so the
// caller can show it to the user exactly once.
//
// Use this when the caller has no pre-existing value (HMAC keys, internal
// signing keys). The plaintext is never logged and never recoverable after
// this call — the database only sees the encrypted form.
//
// lengthBytes is clamped to [MinGeneratedSecretBytes, MaxGeneratedSecretBytes].
// 0 means "use DefaultGeneratedSecretBytes."
func (s *Service) GenerateSecret(ctx context.Context, sec Secret, lengthBytes int) (repository.SecrSecret, string, error) {
	if lengthBytes == 0 {
		lengthBytes = DefaultGeneratedSecretBytes
	}
	if lengthBytes < MinGeneratedSecretBytes {
		lengthBytes = MinGeneratedSecretBytes
	}
	if lengthBytes > MaxGeneratedSecretBytes {
		lengthBytes = MaxGeneratedSecretBytes
	}

	buf := make([]byte, lengthBytes)
	if _, err := cryptorand.Read(buf); err != nil {
		return repository.SecrSecret{}, "", fmt.Errorf("secret.GenerateSecret: rand: %w", err)
	}
	plaintext := hex.EncodeToString(buf)

	sec.Value = plaintext
	row, err := s.CreateSecret(ctx, sec)
	if err != nil {
		return repository.SecrSecret{}, "", err
	}
	return row, plaintext, nil
}

// StoreSecretTx encrypts the plaintext value and persists it inside an existing pgx.Tx.
func (s *Service) StoreSecretTx(ctx context.Context, tx pgx.Tx, sec Secret) error {
	params, err := s.buildCreateParams(sec)
	if err != nil {
		return err
	}
	qtx := s.store.Queries.WithTx(tx)
	_, err = qtx.CreateSecret(ctx, params)
	if err != nil {
		return fmt.Errorf("secret.StoreSecretTx: %w", err)
	}
	return nil
}

// GetDecryptedValue retrieves a secret by ID and decrypts its value.
// This is the only way to obtain the plaintext — the admin API never exposes it.
func (s *Service) GetDecryptedValue(ctx context.Context, id uuid.UUID) (string, error) {
	row, err := s.store.GetSecretByID(ctx, id)
	if err != nil {
		return "", fmt.Errorf("secret.GetDecryptedValue: %w", err)
	}
	plaintext, err := s.keyStore.Decrypt(row.EncryptedValue, int(row.KeyVersion))
	if err != nil {
		return "", fmt.Errorf("secret.GetDecryptedValue: decrypt: %w", err)
	}
	return string(plaintext), nil
}

// GetDecryptedValueByName retrieves an active secret by name and tenant, and decrypts it.
// Connectors should use this to look up their secrets at runtime.
func (s *Service) GetDecryptedValueByName(ctx context.Context, name, tenantID string) (string, error) {
	row, err := s.store.GetSecretByName(ctx, repository.GetSecretByNameParams{
		Name:     name,
		TenantID: pgtype.Text{String: tenantID, Valid: tenantID != ""},
	})
	if err != nil {
		return "", fmt.Errorf("secret.GetDecryptedValueByName: %w", err)
	}
	plaintext, err := s.keyStore.Decrypt(row.EncryptedValue, int(row.KeyVersion))
	if err != nil {
		return "", fmt.Errorf("secret.GetDecryptedValueByName: decrypt: %w", err)
	}
	return string(plaintext), nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func (s *Service) buildCreateParams(sec Secret) (repository.CreateSecretParams, error) {
	if sec.Value == "" {
		return repository.CreateSecretParams{}, fmt.Errorf("secret: value must not be empty")
	}

	ciphertext, err := s.keyStore.Encrypt([]byte(sec.Value))
	if err != nil {
		return repository.CreateSecretParams{}, fmt.Errorf("secret: encrypt: %w", err)
	}

	return repository.CreateSecretParams{
		Name:           sec.Name,
		EncryptedValue: ciphertext,
		KeyVersion:     int32(s.keyStore.CurrentVersion()),
		ConnectorType:  sec.ConnectorType,
		Description:    pgtype.Text{String: sec.Description, Valid: sec.Description != ""},
		TenantID:       pgtype.Text{String: sec.TenantID, Valid: sec.TenantID != ""},
		CreatedBy:      pgtype.Text{String: sec.CreatedBy, Valid: sec.CreatedBy != ""},
	}, nil
}
