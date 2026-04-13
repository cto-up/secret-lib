package api

import (
	"testing"
	"time"

	api "github.com/cto-up/secret-lib/api/openapi"
	"github.com/cto-up/secret-lib/pkg/db/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestMapToDTO(t *testing.T) {
	id := uuid.New()
	now := time.Now().Truncate(time.Second)

	t.Run("minimal row maps correctly", func(t *testing.T) {
		row := repository.SecrSecret{
			ID:            id,
			Name:          "my-api-key",
			ConnectorType: "stripe",
			Status:        "active",
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		dto := mapToDTO(row)

		if dto.Id != id {
			t.Errorf("Id: got %v, want %v", dto.Id, id)
		}
		if dto.Name != "my-api-key" {
			t.Errorf("Name: got %s", dto.Name)
		}
		if dto.ConnectorType != "stripe" {
			t.Errorf("ConnectorType: got %s", dto.ConnectorType)
		}
		if dto.Status != api.Active {
			t.Errorf("Status: got %s, want active", dto.Status)
		}
		if dto.Description != nil {
			t.Errorf("Description should be nil, got %v", dto.Description)
		}
		if dto.TenantId != nil {
			t.Errorf("TenantId should be nil, got %v", dto.TenantId)
		}
		if dto.CreatedBy != nil {
			t.Errorf("CreatedBy should be nil, got %v", dto.CreatedBy)
		}
	})

	t.Run("optional fields populated when valid", func(t *testing.T) {
		row := repository.SecrSecret{
			ID:            id,
			Name:          "smtp-password",
			ConnectorType: "smtp",
			Status:        "revoked",
			CreatedAt:     now,
			UpdatedAt:     now,
			Description:   pgtype.Text{String: "SMTP relay password", Valid: true},
			TenantID:      pgtype.Text{String: "tenant1", Valid: true},
			CreatedBy:     pgtype.Text{String: "user1", Valid: true},
		}
		dto := mapToDTO(row)

		if dto.Description == nil || *dto.Description != "SMTP relay password" {
			t.Errorf("Description: got %v, want SMTP relay password", dto.Description)
		}
		if dto.TenantId == nil || *dto.TenantId != "tenant1" {
			t.Errorf("TenantId: got %v, want tenant1", dto.TenantId)
		}
		if dto.CreatedBy == nil || *dto.CreatedBy != "user1" {
			t.Errorf("CreatedBy: got %v, want user1", dto.CreatedBy)
		}
		if dto.Status != api.Revoked {
			t.Errorf("Status: got %s, want revoked", dto.Status)
		}
	})
}
