-- +goose Up
-- Platform-scoped secrets (tenant_id IS NULL) were not deduplicated: Postgres
-- treats NULLs as distinct in a unique index, so N active rows named e.g.
-- 'llm.openai.api_key' with tenant_id IS NULL could coexist and GetSecretByName
-- would pick between them arbitrarily. NULLS NOT DISTINCT (PG15+) makes the
-- platform scope single-valued, exactly like every tenant scope already is.
--
-- This CREATE fails if duplicate active platform rows already exist. That is
-- deliberate: revoke all but the intended row and re-run, rather than let the
-- database keep two live values for one credential.
DROP INDEX IF EXISTS idx_secr_secrets_tenant_name;

CREATE UNIQUE INDEX idx_secr_secrets_tenant_name
    ON secr_secrets (tenant_id, name) NULLS NOT DISTINCT
    WHERE status = 'active';

-- +goose Down
DROP INDEX IF EXISTS idx_secr_secrets_tenant_name;

CREATE UNIQUE INDEX idx_secr_secrets_tenant_name
    ON secr_secrets (tenant_id, name)
    WHERE status = 'active';
