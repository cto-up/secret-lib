package api

import (
	"errors"
	"net/http"

	"ctoup.com/coreapp/api/helpers"
	"ctoup.com/coreapp/pkg/shared/auth"
	api "github.com/cto-up/secret-lib/api/openapi"
	"github.com/cto-up/secret-lib/pkg/db"
	"github.com/cto-up/secret-lib/pkg/db/repository"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/oapi-codegen/runtime/types"
)

type SecretHandler struct {
	store *db.Store
}

func NewSecretHandler(store *db.Store) *SecretHandler {
	return &SecretHandler{store: store}
}

func RegisterHandler(store *db.Store, options api.GinServerOptions, router *gin.Engine) {
	h := NewSecretHandler(store)
	api.RegisterHandlersWithOptions(router, h, options)
}

// ListSecrets implements api.ServerInterface.
// SUPER_ADMIN sees all tenants; ADMIN sees only their own.
func (h *SecretHandler) ListSecrets(c *gin.Context, params api.ListSecretsParams) {

	tenantID, _ := c.Get(auth.AUTH_TENANT_ID_KEY)
	tid := tenantID.(string)

	tenantFilter := pgtype.Text{}
	if auth.IsSuperAdmin(c) {
		if params.TenantId != nil && *params.TenantId != "" {
			tenantFilter = pgtype.Text{String: *params.TenantId, Valid: true}
		}
	} else {
		tenantFilter = pgtype.Text{String: tid, Valid: true}
	}

	statusFilter := pgtype.Text{}
	if params.Status != nil {
		statusFilter = pgtype.Text{String: string(*params.Status), Valid: true}
	}

	connectorTypeFilter := pgtype.Text{}
	if params.ConnectorType != nil && *params.ConnectorType != "" {
		connectorTypeFilter = pgtype.Text{String: *params.ConnectorType, Valid: true}
	}

	page := 1
	if params.Page != nil && *params.Page > 0 {
		page = *params.Page
	}
	pageSize := 50
	if params.PageSize != nil && *params.PageSize > 0 {
		pageSize = *params.PageSize
	}
	offset := (page - 1) * pageSize

	rows, err := h.store.ListSecrets(c, repository.ListSecretsParams{
		TenantID:      tenantFilter,
		Status:        statusFilter,
		ConnectorType: connectorTypeFilter,
		Limit:         int32(pageSize),
		Offset:        int32(offset),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, helpers.ErrorResponse(err))
		return
	}

	result := make([]api.Secret, len(rows))
	for i, row := range rows {
		result[i] = mapToDTO(row)
	}
	c.JSON(http.StatusOK, result)
}

// RevokeSecret implements api.ServerInterface.
func (h *SecretHandler) RevokeSecret(c *gin.Context, id types.UUID) {
	row, err := h.store.RevokeSecret(c, id)
	if err != nil {
		if errors.Is(err, noRows) {
			c.JSON(http.StatusNotFound, helpers.ErrorResponse(err))
			return
		}
		c.JSON(http.StatusInternalServerError, helpers.ErrorResponse(err))
		return
	}

	c.JSON(http.StatusOK, mapToDTO(row))
}

// DeleteSecret implements api.ServerInterface.
func (h *SecretHandler) DeleteSecret(c *gin.Context, id types.UUID) {

	if err := h.store.DeleteSecret(c, id); err != nil {
		c.JSON(http.StatusInternalServerError, helpers.ErrorResponse(err))
		return
	}
	c.Status(http.StatusNoContent)
}

// ── helpers ───────────────────────────────────────────────────────────────────

var noRows = errors.New("no rows in result set")

func mapToDTO(row repository.SecrSecret) api.Secret {
	dto := api.Secret{
		Id:            row.ID,
		Name:          row.Name,
		ConnectorType: row.ConnectorType,
		Status:        api.SecretStatus(row.Status),
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
	}
	if row.Description.Valid {
		dto.Description = &row.Description.String
	}
	if row.TenantID.Valid {
		dto.TenantId = &row.TenantID.String
	}
	if row.CreatedBy.Valid {
		dto.CreatedBy = &row.CreatedBy.String
	}
	return dto
}
