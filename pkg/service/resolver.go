package service

import "context"

// Resolver is the narrow read-only contract consumers depend on when
// they only need to look up a decrypted secret by name. Prefer this
// over *Service in consumer signatures — it keeps the API surface
// minimal (no write/admin methods exposed), makes tests trivial to
// stub, and lets callers layer behavior (tenant→platform fallback,
// caching, audit) by composing a wrapper that still satisfies Resolver.
//
// The concrete *Service satisfies this interface, so any caller that
// already holds a *Service can pass it directly where a Resolver is
// expected.
type Resolver interface {
	GetDecryptedValueByName(ctx context.Context, name, tenantID string) (string, error)
}
