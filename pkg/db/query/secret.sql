-- name: CreateSecret :one
INSERT INTO secr_secrets (
    name,
    encrypted_value,
    key_version,
    connector_type,
    description,
    tenant_id,
    created_by
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
)
RETURNING *;

-- name: ListSecrets :many
SELECT * FROM secr_secrets
WHERE (sqlc.narg('tenant_id')::text IS NULL OR tenant_id = sqlc.narg('tenant_id'))
  AND (sqlc.narg('status')::text   IS NULL OR status     = sqlc.narg('status'))
  AND (sqlc.narg('connector_type')::text IS NULL OR connector_type = sqlc.narg('connector_type'))
ORDER BY created_at DESC
LIMIT  sqlc.arg('limit')::int
OFFSET sqlc.arg('offset')::int;

-- name: CountSecrets :one
SELECT COUNT(*) FROM secr_secrets
WHERE (sqlc.narg('tenant_id')::text IS NULL OR tenant_id = sqlc.narg('tenant_id'))
  AND (sqlc.narg('status')::text   IS NULL OR status     = sqlc.narg('status'))
  AND (sqlc.narg('connector_type')::text IS NULL OR connector_type = sqlc.narg('connector_type'));

-- name: GetSecretByID :one
SELECT * FROM secr_secrets WHERE id = $1;

-- name: GetSecretByName :one
SELECT * FROM secr_secrets
WHERE name = $1
  AND (sqlc.narg('tenant_id')::text IS NULL OR tenant_id = sqlc.narg('tenant_id'))
  AND status = 'active';

-- name: UpdateSecret :one
UPDATE secr_secrets
SET name            = $2,
    encrypted_value = $3,
    key_version     = $4,
    connector_type  = $5,
    description     = $6,
    updated_at      = NOW()
WHERE id = $1
RETURNING *;

-- name: RevokeSecret :one
UPDATE secr_secrets
SET status     = 'revoked',
    updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: DeleteSecret :exec
DELETE FROM secr_secrets WHERE id = $1;
