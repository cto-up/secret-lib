-- +goose Up
CREATE TABLE secr_secrets (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name            varchar(128) NOT NULL,
    encrypted_value text         NOT NULL,
    key_version     int          NOT NULL DEFAULT 1,
    connector_type  varchar(128) NOT NULL,
    description     text,
    status          varchar(32)  NOT NULL DEFAULT 'active',
    tenant_id       varchar(64),
    created_by      varchar(128),
    created_at      timestamptz  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      timestamptz  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON COLUMN secr_secrets.status IS 'active | revoked';
COMMENT ON COLUMN secr_secrets.encrypted_value IS 'AES-256-GCM ciphertext (base64). Nonce prepended. Never store plaintext.';
COMMENT ON COLUMN secr_secrets.key_version IS 'Encryption key version used — enables key rotation without re-encrypting all rows';

CREATE UNIQUE INDEX idx_secr_secrets_tenant_name
    ON secr_secrets (tenant_id, name)
    WHERE status = 'active';

CREATE INDEX idx_secr_secrets_connector_type
    ON secr_secrets (connector_type);

CREATE INDEX idx_secr_secrets_tenant_id
    ON secr_secrets (tenant_id);

CREATE TRIGGER update_secr_secrets_modtime
    BEFORE UPDATE ON secr_secrets
    FOR EACH ROW EXECUTE FUNCTION update_modified_column();

-- +goose Down
DROP TRIGGER IF EXISTS update_secr_secrets_modtime ON secr_secrets;
DROP INDEX IF EXISTS idx_secr_secrets_connector_type;
DROP INDEX IF EXISTS idx_secr_secrets_tenant_id;
DROP INDEX IF EXISTS idx_secr_secrets_tenant_name;
DROP TABLE IF EXISTS secr_secrets;
