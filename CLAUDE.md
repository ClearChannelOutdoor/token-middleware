# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test ./... -v

# Run a single test
go test ./... -run TestV4Local_ValidToken

# Build
go build ./...

# Tidy dependencies
go mod tidy
```

## Architecture

This is a single-package Go library (`package middleware`) that provides Gin middleware for PASETO bearer token validation. There are only two source files and one test file.

### Key design: `ctx.Error()` + `ctx.Abort()`, not `ctx.AbortWithStatus()`

The middleware registers errors via `ctx.Error(err)` and stops the chain with `ctx.Abort()`, but **never sets an HTTP status code**. Callers are responsible for wiring an error-reporter middleware that reads `ctx.Errors` and writes the response. See `readme.md` for the canonical example. This matters when writing tests — a rejected request still produces a 200 from `httptest` unless the test router includes an error handler.

### Token version dispatch

Two PASETO libraries are in use:
- `oldTimey` (`github.com/o1egl/paseto`) — handles v1 and v2 tokens
- `pasetov4` (`aidanwoods.dev/go-paseto`) — handles v4 tokens

The `parse()` method checks `strings.HasPrefix(token, "v4.local.")` to dispatch. Everything else — key storage, gin context keys, expiry validation — is shared between versions.

### Symmetric key

The same `symmetricKey []byte` (must be 32 bytes) is used for both v2.local and v4.local decryption. Keys are passed to `NewTokenHandler` as `[]byte` or `string`; ed25519 public keys map to v2 public, RSA public keys map to v1 public.

### Gin context keys set by the middleware

| Key   | Type                  | Contents                        |
|-------|-----------------------|---------------------------------|
| `jwt` | `paseto.JSONToken`    | Decrypted token claims          |
| `pst` | `string`              | Raw PASETO token string         |
| `jti` | `string`              | JWT ID from the token           |

### Token accepted from

1. `Authorization: Bearer <token>` header
2. `?bearer_token=<token>` query parameter
