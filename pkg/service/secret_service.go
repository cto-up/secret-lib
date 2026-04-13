package service

import (
	"context"
	"fmt"

	"github.com/cto-up/secret-lib/pkg/crypto"
	"github.com/cto-up/secret-lib/pkg/db"
	"github.com/cto-up/secret-lib/pkg/db/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

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
	params, err := s.buildCreateParams(sec)
	if err != nil {
		return err
	}
	_, err = s.store.CreateSecret(ctx, params)
	if err != nil {
		return fmt.Errorf("secret.StoreSecret: %w", err)
	}
	return nil
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
