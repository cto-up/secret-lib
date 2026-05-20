package api

import (
	"errors"
	"net/http"
	"strings"

	"ctoup.com/coreapp/api/helpers"
	"ctoup.com/coreapp/pkg/shared/auth"
	api "github.com/cto-up/secret-lib/api/openapi"
	"github.com/cto-up/secret-lib/pkg/db"
	"github.com/cto-up/secret-lib/pkg/db/repository"
	"github.com/cto-up/secret-lib/pkg/service"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/oapi-codegen/runtime/types"
)

type SecretHandler struct {
	store   *db.Store
	service *service.Service // optional; required only for createSecret
}

func NewSecretHandler(store *db.Store, svc *service.Service) *SecretHandler {
	return &SecretHandler{store: store, service: svc}
}

// RegisterHandler wires the secret admin endpoints under
// /admin-api/v1/secret/secrets. `svc` is optional: when nil, the
// read-only endpoints (list/delete/revoke) still work but CreateSecret
// returns 503 with a clear "secret service not configured" message.
// That matches the key-store-absent mode the rest of the stack
// tolerates for local-dev / tests.
func RegisterHandler(store *db.Store, svc *service.Service, options api.GinServerOptions, router *gin.Engine) {
	h := NewSecretHandler(store, svc)
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

// CreateSecret implements api.ServerInterface.
// ADMIN / CUSTOMER_ADMIN / SUPER_ADMIN can create — gate is the
// union because auth.IsAdmin only matches the literal ADMIN role
// and we'd lock out SUPER_ADMIN otherwise. Tenant is taken from
// the caller's context; cross-tenant creation is not supported
// via this endpoint by design.
func (h *SecretHandler) CreateSecret(c *gin.Context) {
	if !auth.IsAdmin(c) && !auth.IsSuperAdmin(c) && !auth.IsCustomerAdmin(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin privileges required"})
		return
	}
	if h.service == nil {
		c.JSON(http.StatusServiceUnavailable,
			gin.H{"error": "secret service not configured (set SECRET_ENCRYPTION_KEY)"})
		return
	}

	var req api.CreateSecretRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, helpers.ErrorResponse(err))
		return
	}
	if req.Name == "" || req.Value == "" || req.ConnectorType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name, value and connector_type are required"})
		return
	}

	tenantID := c.GetString(auth.AUTH_TENANT_ID_KEY)
	userID := c.GetString(auth.AUTH_USER_ID)

	desc := ""
	if req.Description != nil {
		desc = *req.Description
	}

	row, err := h.service.CreateSecret(c, service.Secret{
		Name:          req.Name,
		Value:         req.Value,
		ConnectorType: req.ConnectorType,
		Description:   desc,
		TenantID:      tenantID,
		CreatedBy:     userID,
	})
	if err != nil {
		// A unique-index violation on (tenant_id, name) where
		// status='active' means the name is already in use. We
		// surface 409 so the UI can suggest a different name.
		if isUniqueViolation(err) {
			c.JSON(http.StatusConflict, gin.H{"error": "a secret with this name already exists for the tenant"})
			return
		}
		c.JSON(http.StatusInternalServerError, helpers.ErrorResponse(err))
		return
	}
	c.JSON(http.StatusCreated, mapToDTO(row))
}

// GenerateSecret implements api.ServerInterface.
// Mints a new secret with a server-side random value. The plaintext is
// returned in the response exactly once and never recoverable afterwards.
// Same auth gate as CreateSecret — admins only.
func (h *SecretHandler) GenerateSecret(c *gin.Context) {
	if !auth.IsAdmin(c) && !auth.IsSuperAdmin(c) && !auth.IsCustomerAdmin(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin privileges required"})
		return
	}
	if h.service == nil {
		c.JSON(http.StatusServiceUnavailable,
			gin.H{"error": "secret service not configured (set SECRET_ENCRYPTION_KEY)"})
		return
	}

	var req api.GenerateSecretRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, helpers.ErrorResponse(err))
		return
	}
	if req.Name == "" || req.ConnectorType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name and connector_type are required"})
		return
	}

	tenantID := c.GetString(auth.AUTH_TENANT_ID_KEY)
	userID := c.GetString(auth.AUTH_USER_ID)

	desc := ""
	if req.Description != nil {
		desc = *req.Description
	}
	lengthBytes := 0
	if req.LengthBytes != nil {
		lengthBytes = *req.LengthBytes
	}

	row, plaintext, err := h.service.GenerateSecret(c, service.Secret{
		Name:          req.Name,
		ConnectorType: req.ConnectorType,
		Description:   desc,
		TenantID:      tenantID,
		CreatedBy:     userID,
	}, lengthBytes)
	if err != nil {
		if isUniqueViolation(err) {
			c.JSON(http.StatusConflict, gin.H{"error": "a secret with this name already exists for the tenant"})
			return
		}
		c.JSON(http.StatusInternalServerError, helpers.ErrorResponse(err))
		return
	}
	secret := mapToDTO(row)
	c.JSON(http.StatusCreated, api.GeneratedSecret{
		Secret: secret,
		Value:  plaintext,
	})
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

// isUniqueViolation checks for the Postgres unique_violation
// SQLSTATE (23505). We avoid a hard dependency on pgx by doing a
// substring match — cheap, robust to driver wrapping.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "23505") ||
		strings.Contains(msg, "duplicate key") ||
		strings.Contains(msg, "already exists")
}

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
