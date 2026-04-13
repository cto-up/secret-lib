# secret-lib

A Go library for **secure secret management** for connectors. Store, retrieve, revoke, and delete secrets with **AES-256-GCM encryption at rest**, key rotation support, and multi-tenant isolation.

## Overview

```
Your service                      secret-lib                        Connector
──────────────                    ──────────                        ─────────
BEGIN tx
  write business data   ──────►  ENCRYPT value (AES-256-GCM)
                                 INSERT secret row (ciphertext)
COMMIT tx                         ↓
                                  connector calls GetDecryptedValueByName()
                                  DECRYPT value ──────────────────► external API
                                  on compromise → revoke secret
```

Key properties:

- **AES-256-GCM encryption at rest** — plaintext never touches the database; the library encrypts/decrypts internally
- **Key rotation** — `key_version` column allows rolling to a new key without re-encrypting all rows
- **Authenticated encryption** — GCM provides both confidentiality and integrity (tampered ciphertext is rejected)
- **API never exposes values** — admin endpoints omit `encrypted_value`; only `GetDecryptedValue()` returns plaintext
- **Transactional safety** — `StoreSecretTx()` lets you store inside an existing `pgx.Tx`
- **Multi-tenant** — all rows are scoped by `tenant_id`
- **Unique per tenant** — secret names are unique within a tenant (for active secrets)

## Prerequisites

| Tool              | Version | Install                                                                      |
| ----------------- | ------- | ---------------------------------------------------------------------------- |
| Go                | 1.25+   | https://go.dev/dl                                                            |
| PostgreSQL        | 14+     | `docker compose` target below                                                |
| sqlc              | latest  | `go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest`                        |
| oapi-codegen      | latest  | `go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest` |
| openapi-generator | latest  | `npm install -g @openapitools/openapi-generator-cli`                         |

## Quickstart

```bash
# 1. Copy and edit environment config
cp .env.example .env   # edit DATABASE_URL, DATABASE_USERNAME, DATABASE_PASSWORD

# 2. Generate a 32-byte encryption key (base64-encoded)
openssl rand -base64 32
# Add to .env: SECRET_ENCRYPTION_KEY=<output>

# 3. Start local PostgreSQL
make postgresup

# 4. Run migrations (via your migration runner — see pkg/db/migration/)

# 5. Build
make build
```

## Using the Library

### Initialize the service with encryption

```go
import (
    "github.com/cto-up/secret-lib/pkg/crypto"
    "github.com/cto-up/secret-lib/pkg/db"
    "github.com/cto-up/secret-lib/pkg/service"
)

// Load the encryption key from environment (never hardcode)
keyStore, err := crypto.NewKeyStore(map[int]string{
    1: os.Getenv("SECRET_ENCRYPTION_KEY"),
}, 1)
if err != nil {
    log.Fatal(err)
}

store := db.NewStore(pool)
svc   := service.NewService(store, keyStore)
```

### Store a secret (without transaction)

Callers pass the **plaintext** value — the service encrypts it internally using AES-256-GCM.

```go
err := svc.StoreSecret(ctx, service.Secret{
    Name:          "stripe-api-key",
    Value:         "sk_live_abc123",   // plaintext — encrypted by the service
    ConnectorType: "stripe",
    Description:   "Production Stripe API key",
    TenantID:      tenantID,
    CreatedBy:     userID,
})
```

### Store a secret (inside a transaction)

```go
tx, err := pool.Begin(ctx)
if err != nil {
    return err
}
defer tx.Rollback(ctx)

_, err = tx.Exec(ctx, "INSERT INTO connectors ...", ...)
if err != nil {
    return err
}

err = svc.StoreSecretTx(ctx, tx, service.Secret{
    Name:          "smtp-password",
    Value:         "my-smtp-pass",
    ConnectorType: "smtp",
    TenantID:      tenantID,
    CreatedBy:     userID,
})
if err != nil {
    return err
}

return tx.Commit(ctx)
```

### Retrieve a decrypted secret (for connectors)

```go
// By name (recommended for connectors)
value, err := svc.GetDecryptedValueByName(ctx, "stripe-api-key", tenantID)

// By ID
value, err := svc.GetDecryptedValue(ctx, secretID)
```

### Key rotation

To rotate keys, add the new key and update the current version. Old secrets remain decryptable.

```go
keyStore, _ := crypto.NewKeyStore(map[int]string{
    1: os.Getenv("SECRET_ENCRYPTION_KEY_V1"),  // old key — kept for decryption
    2: os.Getenv("SECRET_ENCRYPTION_KEY_V2"),  // new key — used for new encryptions
}, 2)
```

### Register the admin API

```go
import (
    secretapi "github.com/cto-up/secret-lib/pkg/api"
    api       "github.com/cto-up/secret-lib/api/openapi"
)

secretapi.RegisterHandler(store, api.GinServerOptions{}, router)
```

This mounts the following routes under `/admin-api/v1/secret`:

| Method   | Path                   | Role                | Description                                |
| -------- | ---------------------- | ------------------- | ------------------------------------------ |
| `GET`    | `/secrets`             | ADMIN / SUPER_ADMIN | List secrets with filtering and pagination |
| `POST`   | `/secrets/{id}/revoke` | ADMIN / SUPER_ADMIN | Revoke a secret                            |
| `DELETE` | `/secrets/{id}`        | ADMIN / SUPER_ADMIN | Hard-delete a secret                       |

SUPER_ADMIN can query across all tenants. ADMIN is automatically scoped to their own `tenant_id`.

**The admin API intentionally omits `encrypted_value` from all responses.** Secret values are only accessible programmatically via `GetDecryptedValue()` / `GetDecryptedValueByName()`.

### Query parameters for `GET /secrets`

| Param            | Type   | Description                     |
| ---------------- | ------ | ------------------------------- |
| `status`         | string | Filter by `active`, `revoked`   |
| `connector_type` | string | Filter by connector type        |
| `tenant_id`      | string | SUPER_ADMIN only                |
| `page`           | int    | Page number (default `1`)       |
| `page_size`      | int    | Results per page (default `50`) |

## Secret lifecycle

```
active ──► revoked   (compromised or rotated)
       ──► deleted   (hard-delete via API)
```

Connectors should look up secrets by name using `GetDecryptedValueByName()`. Only active secrets are returned.

## Security architecture

| Layer | Control |
|---|---|
| **Encryption** | AES-256-GCM (authenticated encryption) — unique random nonce per secret |
| **Key management** | Versioned keys via `crypto.KeyStore`; `key_version` column per row enables rotation |
| **At-rest protection** | Database stores only base64-encoded ciphertext with prepended nonce |
| **Integrity** | GCM authentication tag detects tampering — corrupted ciphertext is rejected |
| **API surface** | Admin API never returns `encrypted_value`; only service methods return plaintext |
| **Empty value guard** | Service rejects empty plaintext — prevents storing placeholder secrets |
| **Fail-closed** | `NewService` panics if no KeyStore — the service cannot start without encryption |
| **Multi-tenant isolation** | Unique index on `(tenant_id, name)` for active secrets |

## Development

### Make targets

| Target                                    | Description                                      |
| ----------------------------------------- | ------------------------------------------------ |
| `make build`                              | Compile all packages                             |
| `make postgresup`                         | Start local PostgreSQL via Docker Compose        |
| `make postgresdown`                       | Stop local PostgreSQL                            |
| `make sqlc`                               | Regenerate `pkg/db/repository/` from SQL queries |
| `make openapi`                            | Regenerate Go server stubs and TypeScript client |
| `make update-core-backend VERSION=v0.x.x` | Bump `ctoup.com/coreapp` dependency              |
| `make release VERSION=v0.x.x NOTES="..."` | Create a GitHub release                          |

### Code generation

All generated files are committed. Regenerate after changing source definitions:

```
pkg/db/query/secret.sql              ──► make sqlc     ──► pkg/db/repository/*.go
pkg/api/openapi/secret-api.yaml      ──► make openapi  ──► api/openapi/secret-service.go
pkg/api/openapi/secret-schema.yaml                     ──► api/openapi/secret-schema.go
                                                       ──► ../secret-fe-lib/ (TypeScript)
```

### Project layout

```
secret-lib/
├── api/openapi/           # Generated Go server stubs (oapi-codegen output)
├── pkg/
│   ├── crypto/            # AES-256-GCM encryption + versioned key store
│   ├── service/           # StoreSecret() / GetDecryptedValue() — public API
│   ├── api/               # Gin handler — admin REST endpoints
│   │   └── openapi/       # OpenAPI source specs + code-gen configs
│   └── db/
│       ├── store.go       # Store struct + ExecTx helper
│       ├── migration/     # Embedded SQL migrations
│       ├── query/         # sqlc query definitions
│       └── repository/    # Generated DB access code (sqlc output)
├── Makefile
└── go.mod
```

### Database schema

Single table `secr_secrets` with indexes optimised for lookups:

- `(tenant_id, name)` — partial unique index on active secrets
- `connector_type` — filtered listings
- `tenant_id` — tenant-scoped admin queries

See `pkg/db/migration/20260413000000_secret.sql` for the full DDL.

## Configuration

Copy `.env.example` to `.env`. Required variables:

```ini
DATABASE_URL              = 127.0.0.1:5432/mydb?sslmode=disable
DATABASE_USERNAME         = myuser
DATABASE_PASSWORD         = mypassword
SECRET_ENCRYPTION_KEY     = <base64-encoded 32-byte key>
```

Generate a key: `openssl rand -base64 32`

## Releasing

```bash
make release VERSION=v0.2.0 NOTES="Add revoke endpoint"
```

This creates a GitHub release via `gh`. The module is consumed via Go module proxy, so tag format must be `vMAJOR.MINOR.PATCH`.
